// Package passkey verifies WebAuthn passkey registrations and sign-ins for the
// one shape this gateway accepts: a discoverable ES256 (P-256) credential held
// by the device's own passkey provider (a phone's, or a computer's Touch ID or
// Windows Hello), with user verification, and no attestation. Nothing else is
// supported, on purpose.
//
// The parsing and the cryptographic checks are go-webauthn's
// (github.com/go-webauthn/webauthn/protocol), a maintained library with its
// own fuzzing and conformance tests. This package holds only the policy, and
// calls the library for each part of a ceremony:
//
//   - clientDataJSON (protocol.CollectedClientData): the ceremony type, the
//     challenge this server issued, and the origin of the sign-in host. On top
//     of the library's checks, the origin must be the configured one exactly,
//     and no cross-origin ceremony or topOrigin is accepted.
//   - authenticatorData (protocol.AuthenticatorData): the hash of the
//     relying-party ID (the sign-in host), the user-present and user-verified
//     flags, the signature counter, and at registration the credential ID and
//     its COSE key.
//   - at registration, the COSE key (webauthncose) must be an ES256 key on
//     P-256 and the same key the browser reports (SubjectPublicKeyInfo, from
//     getPublicKey()), which is the form stored.
//   - at sign-in, the stored key is read as a COSE EC2 key and the library
//     verifies its ECDSA signature over authenticatorData followed by the
//     SHA-256 of clientDataJSON.
//
// The library's attestation formats, metadata service and high-level
// webauthn.WebAuthn flow are not used: attestation is "none", and the server
// keeps its own challenges, cookies and stored credential format.
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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// AlgES256 is the COSE algorithm identifier for ECDSA with P-256 and SHA-256,
// the only algorithm accepted. Apple and Google passkeys both use it.
const AlgES256 = -7

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
	if err := rp.checkClientData(reg.ClientDataJSON, protocol.CreateCeremony, challenge); err != nil {
		return Credential{}, err
	}
	ad, err := rp.checkAuthData(reg.AuthenticatorData)
	if err != nil {
		return Credential{}, err
	}
	att := ad.AttData
	if !ad.Flags.HasAttestedCredentialData() || len(att.CredentialID) == 0 || !bytes.Equal(att.CredentialID, reg.CredentialID) {
		return Credential{}, ErrAuthData
	}
	if reg.PublicKeyAlg != AlgES256 {
		return Credential{}, ErrKey
	}
	pub, err := parseP256(reg.PublicKey)
	if err != nil {
		return Credential{}, err
	}
	// The key the authenticator wrote must be an ES256 key on P-256, and the
	// same key the browser reports. With attestation "none" nothing signs
	// either, so this is a consistency check on the person's own browser, not
	// proof of which device holds the key.
	parsed, err := webauthncose.ParsePublicKey(att.CredentialPublicKey)
	if err != nil {
		return Credential{}, ErrKey
	}
	cose, ok := parsed.(webauthncose.EC2PublicKeyData)
	if !ok || !isES256(cose) {
		return Credential{}, ErrKey
	}
	want, err := coseKey(pub)
	if err != nil || !bytes.Equal(cose.XCoord, want.XCoord) || !bytes.Equal(cose.YCoord, want.YCoord) {
		return Credential{}, ErrKey
	}
	var aaguid [16]byte
	copy(aaguid[:], att.AAGUID)
	return Credential{
		ID:        bytes.Clone(att.CredentialID),
		PublicKey: bytes.Clone(reg.PublicKey),
		SignCount: ad.Counter,
		AAGUID:    aaguid,
		Synced:    ad.Flags.HasBackupEligible(),
	}, nil
}

// VerifyAssertion checks a sign-in against the challenge this server issued
// and the stored public key, and returns the authenticator's new signature
// counter. storedCount is the counter saved at the last use. Synced passkeys
// always report zero; a counter that is non-zero and has not increased means
// the key may have been copied, and is refused.
func (rp RelyingParty) VerifyAssertion(a Assertion, challenge, publicKey []byte, storedCount uint32) (uint32, error) {
	if err := rp.checkClientData(a.ClientDataJSON, protocol.AssertCeremony, challenge); err != nil {
		return 0, err
	}
	ad, err := rp.checkAuthData(a.AuthenticatorData)
	if err != nil {
		return 0, err
	}
	pub, err := parseP256(publicKey)
	if err != nil {
		return 0, err
	}
	cdHash := sha256.Sum256(a.ClientDataJSON)
	signed := append(bytes.Clone(a.AuthenticatorData), cdHash[:]...)
	key, err := coseKey(pub)
	if err != nil {
		return 0, err
	}
	if ok, err := webauthncose.VerifySignature(key, signed, a.Signature); !ok || err != nil {
		return 0, ErrSignature
	}
	if (ad.Counter != 0 || storedCount != 0) && ad.Counter <= storedCount {
		return 0, ErrCounter
	}
	return ad.Counter, nil
}

// checkClientData parses clientDataJSON and has the library check its type,
// challenge and origin. Two checks of this package's own sit on top: the
// origin must be the configured one exactly, as the browser serialises it,
// not merely an equivalent spelling; and a topOrigin of any value is refused,
// because it is present only when the ceremony ran in a cross-origin iframe,
// which the sign-in pages forbid (frame-ancestors 'none').
func (rp RelyingParty) checkClientData(raw []byte, ceremony protocol.CeremonyType, challenge []byte) error {
	var cd protocol.CollectedClientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return ErrClientData
	}
	var top struct {
		TopOrigin *string `json:"topOrigin"`
	}
	if err := json.Unmarshal(raw, &top); err != nil || top.TopOrigin != nil {
		return ErrClientData
	}
	if len(challenge) == 0 || cd.Origin != rp.Origin {
		return ErrClientData
	}
	if err := cd.Verify(base64.RawURLEncoding.EncodeToString(challenge), ceremony,
		[]string{rp.Origin}, nil, nil, protocol.TopOriginExplicitVerificationMode, false); err != nil {
		return ErrClientData
	}
	return nil
}

// checkAuthData parses authenticatorData and has the library check the
// relying-party hash and the presence and verification flags, which every
// ceremony here requires.
func (rp RelyingParty) checkAuthData(raw []byte) (protocol.AuthenticatorData, error) {
	var ad protocol.AuthenticatorData
	if err := ad.Unmarshal(raw); err != nil {
		return ad, ErrAuthData
	}
	rpHash := sha256.Sum256([]byte(rp.ID))
	if err := ad.Verify(rpHash[:], nil, true, true); err != nil {
		// The library reports every failure alike. The audit log tells a
		// missing face, fingerprint or PIN check apart from the wrong host.
		if bytes.Equal(ad.RPIDHash, rpHash[:]) {
			return ad, ErrNotVerified
		}
		return ad, ErrAuthData
	}
	return ad, nil
}

// parseP256 reads a stored or browser-reported SubjectPublicKeyInfo, which
// must hold a P-256 key.
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

// coseKey is the ES256 COSE key for pub, the form the library verifies with.
// Stored passkeys keep the SubjectPublicKeyInfo they were registered with, so
// every passkey added before the library was adopted still signs in.
func coseKey(pub *ecdsa.PublicKey) (webauthncose.EC2PublicKeyData, error) {
	ecdh, err := pub.ECDH()
	if err != nil {
		return webauthncose.EC2PublicKeyData{}, ErrKey
	}
	raw := ecdh.Bytes() // 0x04 || x || y
	if len(raw) != 65 {
		return webauthncose.EC2PublicKeyData{}, ErrKey
	}
	return webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: raw[1:33],
		YCoord: raw[33:65],
	}, nil
}

func isES256(k webauthncose.EC2PublicKeyData) bool {
	return k.KeyType == int64(webauthncose.EllipticKey) &&
		k.Algorithm == int64(webauthncose.AlgES256) &&
		k.Curve == int64(webauthncose.P256)
}

// AAGUIDString formats a provider identifier the usual way.
func AAGUIDString(a [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", a[0:4], a[4:6], a[6:8], a[8:10], a[10:16])
}
