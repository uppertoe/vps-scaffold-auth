package passkey

// The hand-written verifier this package used before go-webauthn, kept only
// for the differential test in differential_test.go. It is deleted in the
// next commit.

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
)

const (
	flagUP = 1 << 0
	flagUV = 1 << 2
	flagBE = 1 << 3
	flagAT = 1 << 6
	flagED = 1 << 7
)

const maxCredentialID = 1023

func (rp RelyingParty) legacyVerifyRegistration(reg Registration, challenge []byte) (Credential, error) {
	if err := rp.legacyCheckClientData(reg.ClientDataJSON, "webauthn.create", challenge); err != nil {
		return Credential{}, err
	}
	ad, err := rp.legacyParseAuthData(reg.AuthenticatorData)
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
	pub, err := legacyParseP256(reg.PublicKey)
	if err != nil {
		return Credential{}, err
	}
	want, err := legacyCOSEP256(pub)
	if err != nil {
		return Credential{}, err
	}
	// The key must be exactly the canonical encoding of the reported key.
	// Anything after it is allowed only when the extensions flag says so.
	if !bytes.HasPrefix(coseKey, want) || (ad.flags&flagED == 0 && len(coseKey) != len(want)) {
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
func (rp RelyingParty) legacyVerifyAssertion(a Assertion, challenge, publicKey []byte, storedCount uint32) (uint32, error) {
	if err := rp.legacyCheckClientData(a.ClientDataJSON, "webauthn.get", challenge); err != nil {
		return 0, err
	}
	ad, err := rp.legacyParseAuthData(a.AuthenticatorData)
	if err != nil {
		return 0, err
	}
	pub, err := legacyParseP256(publicKey)
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

// legacyClientData is the part of clientDataJSON this package reads. topOrigin is
// present only when the ceremony ran in a cross-origin iframe, which the
// sign-in pages forbid (frame-ancestors 'none'); its presence is refused.
type legacyClientData struct {
	Type        string  `json:"type"`
	Challenge   string  `json:"challenge"`
	Origin      string  `json:"origin"`
	CrossOrigin bool    `json:"crossOrigin"`
	TopOrigin   *string `json:"topOrigin"`
}

func (rp RelyingParty) legacyCheckClientData(raw []byte, typ string, challenge []byte) error {
	var cd legacyClientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return ErrClientData
	}
	if cd.Type != typ || cd.Origin != rp.Origin || cd.CrossOrigin || cd.TopOrigin != nil {
		return ErrClientData
	}
	got, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil || len(challenge) == 0 || subtle.ConstantTimeCompare(got, challenge) != 1 {
		return ErrClientData
	}
	return nil
}

type legacyAuthData struct {
	flags     byte
	signCount uint32
	rest      []byte // attested credential data and extensions, when present
}

// legacyParseAuthData reads the fixed 37-byte head of authenticatorData and checks
// the relying-party hash and the presence and verification flags, which every
// ceremony here requires.
func (rp RelyingParty) legacyParseAuthData(b []byte) (legacyAuthData, error) {
	if len(b) < 37 {
		return legacyAuthData{}, ErrAuthData
	}
	want := sha256.Sum256([]byte(rp.ID))
	if subtle.ConstantTimeCompare(b[:32], want[:]) != 1 {
		return legacyAuthData{}, ErrAuthData
	}
	flags := b[32]
	if flags&flagUP == 0 || flags&flagUV == 0 {
		return legacyAuthData{}, ErrNotVerified
	}
	return legacyAuthData{flags: flags, signCount: binary.BigEndian.Uint32(b[33:37]), rest: b[37:]}, nil
}

func legacyParseP256(spki []byte) (*ecdsa.PublicKey, error) {
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

// legacyCOSEP256 is the COSE_Key an authenticator writes for the ES256 key pub, in
// the canonical CBOR that CTAP2 requires and Apple's and Google's passkeys
// emit: a five-entry map of kty 2 (EC2), alg -7 (ES256), crv 1 (P-256), and
// the 32-byte x and y coordinates, in that order. Rather than carry a general
// CBOR decoder, registration requires the authenticator data to hold exactly
// these 77 bytes, which binds the browser-reported SubjectPublicKeyInfo to the
// key the authenticator wrote. With attestation "none" nothing signs either,
// so this is a consistency check on the person's own browser, not proof of
// which device holds the key.
func legacyCOSEP256(pub *ecdsa.PublicKey) ([]byte, error) {
	ecdh, err := pub.ECDH()
	if err != nil {
		return nil, ErrKey
	}
	raw := ecdh.Bytes() // 0x04 || x || y
	if len(raw) != 65 {
		return nil, ErrKey
	}
	out := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
	out = append(out, raw[1:33]...)
	out = append(out, 0x22, 0x58, 0x20)
	return append(out, raw[33:65]...), nil
}

