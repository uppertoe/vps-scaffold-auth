// Package passkey verifies WebAuthn passkey registrations and sign-ins for the
// one shape this gateway accepts: a discoverable ES256 (P-256) credential held
// by the device's own passkey provider (a phone's, or a computer's Touch ID or
// Windows Hello), with user verification, and no attestation. Nothing else is
// supported, on purpose.
//
// A general WebAuthn library (go-webauthn) was tried and set aside: it links
// attestation formats, TPM and certificate-chain parsing, JWT and a metadata
// service client, ten modules and about 65,000 lines, none of which is used
// when attestation is "none". The one part of a ceremony that needs a real
// parser, the CBOR of the credential's COSE key, is read with
// fxamacker/cbor, a fuzzed and widely used CBOR library with no dependency
// beyond a float16 package. The rest is fixed-layout bytes and a little JSON,
// small enough to read in one sitting:
//
//   - clientDataJSON: the ceremony type, the challenge this server issued, and
//     the exact origin of the sign-in host.
//   - authenticatorData: the hash of the relying-party ID (the sign-in host),
//     the user-present and user-verified flags, and the signature counter.
//   - at registration, the COSE key in authenticatorData (decoded with
//     fxamacker/cbor) must be an ES256 key on P-256 in CTAP2's canonical
//     encoding, and the same key the browser reports (SubjectPublicKeyInfo,
//     from getPublicKey()), which is the form stored.
//   - at sign-in, an ECDSA signature (Go's crypto/ecdsa) over
//     authenticatorData followed by the SHA-256 of clientDataJSON.
//
// The tests hold the verifier to its recorded behaviour: a corpus of
// real-shaped and mutated ceremonies with their verdicts
// (testdata/corpus.json), fuzz targets for every field a browser posts, and
// a passkey stored in the gateway's format as fixed bytes.
//
// Registration carries no attestation, so nothing at registration is signed:
// the flags (user verified, backed up), the provider ID and the key are what
// the posting browser says they are. A script holding a software key can
// therefore register one. That is the normal choice for consumer passkeys,
// and it means registration is only as strong as the session that asks for
// it: the server decides who may add a passkey (see the server package). At
// sign-in the flags are signed by the registered key, so they are as
// trustworthy as that key.
package passkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// AlgES256 is the COSE algorithm identifier for ECDSA with P-256 and SHA-256,
// the only algorithm accepted. Apple and Google passkeys both use it.
const AlgES256 = -7

// Authenticator-data flag bits (WebAuthn §6.1).
const (
	flagUP = 1 << 0 // user present
	flagUV = 1 << 2 // user verified (face, fingerprint or PIN)
	flagBE = 1 << 3 // backup eligible (a synced passkey)
	flagBS = 1 << 4 // backed up
	flagAT = 1 << 6 // attested credential data included
	flagED = 1 << 7 // extension data included
)

// maxCredentialID is WebAuthn's limit on a credential ID's length.
const maxCredentialID = 1023

// Errors. They are deliberately coarse: the caller shows one message for any
// failure and records which check failed in the audit log.
var (
	ErrClientData  = errors.New("passkey: client data does not match this sign-in")
	ErrAuthData    = errors.New("passkey: authenticator data does not match this sign-in")
	ErrNotVerified = errors.New("passkey: the authenticator did not verify the person")
	ErrKey         = errors.New("passkey: unsupported or mismatched public key")
	ErrSignature   = errors.New("passkey: signature does not verify")
	ErrCounter     = errors.New("passkey: signature counter went backwards")
)

// RelyingParty is the sign-in host as WebAuthn sees it. ID is the host name
// alone (auth.example.org): passkeys are bound to that host, not to the whole
// domain, so no other application on the domain can ask the browser to use
// them. Origin is the exact scheme://host[:port] the pages are served from.
type RelyingParty struct {
	ID     string
	Origin string
}

// Registration is what the browser returns from navigator.credentials.create,
// decoded from the posted form.
type Registration struct {
	CredentialID      []byte // rawId
	ClientDataJSON    []byte
	AuthenticatorData []byte // response.getAuthenticatorData()
	PublicKey         []byte // response.getPublicKey(): SubjectPublicKeyInfo DER
	PublicKeyAlg      int    // response.getPublicKeyAlgorithm()
	// Attachment and Transports are what the browser reports about where the
	// passkey was made: credential.authenticatorAttachment ("platform" or
	// "cross-platform") and response.getTransports() ("internal", "hybrid",
	// "usb" and so on). Nothing signs them, so they describe the choice the
	// person's own browser made; they steer an honest mistake, such as saving
	// to a phone over Bluetooth, and are no defence against a hostile script.
	Attachment string
	Transports []string
}

// HeldByThisDevice reports whether the browser says the passkey is held by
// the device the ceremony ran on: a platform authenticator, reached through
// the "internal" transport. A passkey made on a phone over Bluetooth or a QR
// code reports "cross-platform" and "hybrid", and a security key reports
// "cross-platform" and "usb", "nfc" or "ble"; neither is held by this device.
// A browser that reports no transports is not taken at its word.
func (r Registration) HeldByThisDevice() bool {
	if r.Attachment != "" && r.Attachment != "platform" {
		return false
	}
	for _, t := range r.Transports {
		if t == "internal" {
			return true
		}
	}
	return false
}

// Credential is a verified registration, ready to store.
type Credential struct {
	ID        []byte
	PublicKey []byte // SubjectPublicKeyInfo DER, P-256
	SignCount uint32
	AAGUID    [16]byte // the passkey provider's identifier; zero when withheld
	Synced    bool     // backup eligible: the passkey lives in a synced provider
}

// Assertion is what the browser returns from navigator.credentials.get.
type Assertion struct {
	CredentialID      []byte
	ClientDataJSON    []byte
	AuthenticatorData []byte
	Signature         []byte // ASN.1 DER ECDSA signature
	UserHandle        []byte
}

// VerifyRegistration checks a new credential against the challenge this server
// issued for it.
func (rp RelyingParty) VerifyRegistration(reg Registration, challenge []byte) (Credential, error) {
	if err := rp.checkClientData(reg.ClientDataJSON, "webauthn.create", challenge); err != nil {
		return Credential{}, err
	}
	ad, err := rp.parseAuthData(reg.AuthenticatorData)
	if err != nil {
		return Credential{}, err
	}
	if ad.flags&flagAT == 0 {
		return Credential{}, ErrAuthData
	}
	rest := ad.rest
	if len(rest) < 18 {
		return Credential{}, ErrAuthData
	}
	var aaguid [16]byte
	copy(aaguid[:], rest[:16])
	idLen := int(binary.BigEndian.Uint16(rest[16:18]))
	rest = rest[18:]
	if idLen == 0 || idLen > maxCredentialID || len(rest) < idLen {
		return Credential{}, ErrAuthData
	}
	credID, coseKey := rest[:idLen], rest[idLen:]
	if !bytes.Equal(credID, reg.CredentialID) {
		return Credential{}, ErrAuthData
	}
	if reg.PublicKeyAlg != AlgES256 {
		return Credential{}, ErrKey
	}
	pub, err := parseP256(reg.PublicKey)
	if err != nil {
		return Credential{}, err
	}
	// The key must be the canonical encoding of the reported key. Anything
	// after it is allowed only when the extensions flag says so.
	after, err := matchCOSEKey(coseKey, pub)
	if err != nil || (ad.flags&flagED == 0 && len(after) != 0) {
		return Credential{}, ErrKey
	}
	return Credential{
		ID:        append([]byte(nil), credID...),
		PublicKey: append([]byte(nil), reg.PublicKey...),
		SignCount: ad.signCount,
		AAGUID:    aaguid,
		Synced:    ad.flags&flagBE != 0,
	}, nil
}

// VerifyAssertion checks a sign-in against the challenge this server issued
// and the stored public key, and returns the authenticator's new signature
// counter. storedCount is the counter saved at the last use. Synced passkeys
// always report zero; a counter that is non-zero and has not increased means
// the key may have been copied, and is refused.
func (rp RelyingParty) VerifyAssertion(a Assertion, challenge, publicKey []byte, storedCount uint32) (uint32, error) {
	if err := rp.checkClientData(a.ClientDataJSON, "webauthn.get", challenge); err != nil {
		return 0, err
	}
	ad, err := rp.parseAuthData(a.AuthenticatorData)
	if err != nil {
		return 0, err
	}
	pub, err := parseP256(publicKey)
	if err != nil {
		return 0, err
	}
	cdHash := sha256.Sum256(a.ClientDataJSON)
	signed := make([]byte, 0, len(a.AuthenticatorData)+len(cdHash))
	signed = append(signed, a.AuthenticatorData...)
	signed = append(signed, cdHash[:]...)
	digest := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(pub, digest[:], a.Signature) {
		return 0, ErrSignature
	}
	if (ad.signCount != 0 || storedCount != 0) && ad.signCount <= storedCount {
		return 0, ErrCounter
	}
	return ad.signCount, nil
}

// clientData is the part of clientDataJSON this package reads. topOrigin is
// present only when the ceremony ran in a cross-origin iframe, which the
// sign-in pages forbid (frame-ancestors 'none'); its presence is refused.
type clientData struct {
	Type        string
	Challenge   string
	Origin      string
	CrossOrigin bool
	TopOrigin   *string
}

// checkClientData reads clientDataJSON as the browser writes it. Go's
// encoding/json matches member names without regard to case, so each member
// is read by its exact name from a map, and a member whose name differs from
// one of these only in case ("tYpe") is refused. The challenge must be the
// exact unpadded base64url of the one issued.
func (rp RelyingParty) checkClientData(raw []byte, typ string, challenge []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return ErrClientData
	}
	var cd clientData
	fields := map[string]any{
		"type": &cd.Type, "challenge": &cd.Challenge, "origin": &cd.Origin,
		"crossOrigin": &cd.CrossOrigin, "topOrigin": &cd.TopOrigin,
	}
	for got := range m {
		for name := range fields {
			if got != name && strings.EqualFold(got, name) {
				return ErrClientData
			}
		}
	}
	for name, v := range fields {
		if r, ok := m[name]; ok && json.Unmarshal(r, v) != nil {
			return ErrClientData
		}
	}
	if cd.Type != typ || cd.Origin != rp.Origin || cd.CrossOrigin || cd.TopOrigin != nil {
		return ErrClientData
	}
	want := base64.RawURLEncoding.EncodeToString(challenge)
	if len(challenge) == 0 || subtle.ConstantTimeCompare([]byte(cd.Challenge), []byte(want)) != 1 {
		return ErrClientData
	}
	return nil
}

type authData struct {
	flags     byte
	signCount uint32
	rest      []byte // attested credential data and extensions, when present
}

// parseAuthData reads the fixed 37-byte head of authenticatorData and checks
// the relying-party hash and the presence and verification flags, which every
// ceremony here requires.
func (rp RelyingParty) parseAuthData(b []byte) (authData, error) {
	if len(b) < 37 {
		return authData{}, ErrAuthData
	}
	want := sha256.Sum256([]byte(rp.ID))
	if subtle.ConstantTimeCompare(b[:32], want[:]) != 1 {
		return authData{}, ErrAuthData
	}
	flags := b[32]
	if flags&flagUP == 0 || flags&flagUV == 0 {
		return authData{}, ErrNotVerified
	}
	return authData{flags: flags, signCount: binary.BigEndian.Uint32(b[33:37]), rest: b[37:]}, nil
}

func parseP256(spki []byte) (*ecdsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, ErrKey
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, ErrKey
	}
	return pub, nil
}

// coseEC2 is a COSE_Key for an elliptic-curve key (RFC 9053), with the
// labels as CBOR integers.
type coseEC2 struct {
	Kty int64  `cbor:"1,keyasint"`
	Alg int64  `cbor:"3,keyasint"`
	Crv int64  `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

// The COSE values of the one key accepted: EC2, ES256, P-256.
const (
	coseKtyEC2  = 2
	coseCrvP256 = 1
)

// coseDecode reads a COSE key strictly: no duplicate or unknown labels, no
// indefinite lengths and no tags. coseEncode writes the canonical CBOR that
// CTAP2 requires.
var (
	coseDecode = mustDecMode(cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		MaxNestedLevels:   4,
		MaxMapPairs:       16,
	})
	coseEncode = mustEncMode(cbor.CTAP2EncOptions())
)

// matchCOSEKey decodes the COSE key at the start of b (fxamacker/cbor), and
// returns what follows it. The key must be an ES256 key on P-256, written in
// CTAP2's canonical encoding, as Apple's and Google's passkeys write it, and
// must be pub: the key the browser reports as SubjectPublicKeyInfo. That
// binds the reported key to the key the authenticator wrote. With
// attestation "none" nothing signs either, so this is a consistency check on
// the person's own browser, not proof of which device holds the key.
func matchCOSEKey(b []byte, pub *ecdsa.PublicKey) (rest []byte, err error) {
	var k coseEC2
	rest, err = coseDecode.UnmarshalFirst(b, &k)
	if err != nil {
		return nil, ErrKey
	}
	if k.Kty != coseKtyEC2 || k.Alg != AlgES256 || k.Crv != coseCrvP256 {
		return nil, ErrKey
	}
	canonical, err := coseEncode.Marshal(k)
	if err != nil || !bytes.Equal(canonical, b[:len(b)-len(rest)]) {
		return nil, ErrKey
	}
	ecdh, err := pub.ECDH()
	if err != nil {
		return nil, ErrKey
	}
	raw := ecdh.Bytes() // 0x04 || x || y
	if len(raw) != 65 || !bytes.Equal(k.X, raw[1:33]) || !bytes.Equal(k.Y, raw[33:65]) {
		return nil, ErrKey
	}
	return rest, nil
}

func mustDecMode(o cbor.DecOptions) cbor.DecMode {
	m, err := o.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}

func mustEncMode(o cbor.EncOptions) cbor.EncMode {
	m, err := o.EncMode()
	if err != nil {
		panic(err)
	}
	return m
}

// AAGUIDString formats a provider identifier the usual way.
func AAGUIDString(a [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", a[0:4], a[4:6], a[6:8], a[8:10], a[10:16])
}
