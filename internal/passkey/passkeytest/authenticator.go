// Package passkeytest is a software passkey authenticator for tests. It
// produces exactly what a phone's passkey provider returns to the browser, so
// the gateway's verifier and handlers can be exercised end to end without a
// browser. It is never linked into the gateway binary.
package passkeytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"

	"github.com/uppertoe/vps-scaffold-auth/internal/passkey"
)

// Authenticator holds one passkey.
type Authenticator struct {
	Key        *ecdsa.PrivateKey
	ID         []byte
	UserHandle []byte
	AAGUID     [16]byte
	Counter    uint32 // 0 models a synced passkey; set non-zero to model a counting one
	Flags      byte   // authenticator-data flags; New sets UP|UV|BE|BS
	// Attachment and Transports are what the browser reports at registration.
	// New models a phone's own provider ("platform"; "internal" and "hybrid");
	// set them to model a passkey saved to a phone over Bluetooth or a QR code
	// ("cross-platform"; "hybrid").
	Attachment string
	Transports []string
}

// WindowsHello is the identifier (AAGUID) Windows Hello reports.
var WindowsHello = [16]byte{0x08, 0x98, 0x70, 0x58, 0xca, 0xdc, 0x4b, 0x81, 0xb6, 0xe1, 0x30, 0xde, 0x50, 0xdc, 0xbe, 0x96}

// New makes an authenticator with a fresh P-256 key and credential ID.
func New() *Authenticator {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	id := make([]byte, 16)
	rand.Read(id)
	return &Authenticator{Key: k, ID: id, Flags: 0x01 | 0x04 | 0x08 | 0x10, Attachment: "platform", Transports: []string{"internal", "hybrid"}}
}

// NewComputer makes an authenticator that models a computer's own one, as
// Windows Hello reports itself: held by the computer ("platform";
// "internal"), not synced, and counting its signatures.
func NewComputer() *Authenticator {
	a := New()
	a.Flags = 0x01 | 0x04
	a.Transports = []string{"internal"}
	a.AAGUID = WindowsHello
	a.Counter = 1
	return a
}

// ClientData builds clientDataJSON for a ceremony.
func ClientData(typ string, challenge []byte, origin string) []byte {
	b, _ := json.Marshal(map[string]any{
		"type":        typ,
		"challenge":   base64.RawURLEncoding.EncodeToString(challenge),
		"origin":      origin,
		"crossOrigin": false,
	})
	return b
}

func (a *Authenticator) head(rpID string, flags byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append([]byte(nil), h[:]...)
	out = append(out, flags)
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], a.Counter)
	return append(out, c[:]...)
}

// COSEKey is the authenticator's public key as a CBOR COSE_Key map.
func (a *Authenticator) COSEKey() []byte {
	x := a.Key.PublicKey.X.FillBytes(make([]byte, 32))
	y := a.Key.PublicKey.Y.FillBytes(make([]byte, 32))
	out := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
	out = append(out, x...)
	out = append(out, 0x22, 0x58, 0x20)
	return append(out, y...)
}

// SPKI is the public key as the browser's getPublicKey() reports it.
func (a *Authenticator) SPKI() []byte {
	b, err := x509.MarshalPKIXPublicKey(&a.Key.PublicKey)
	if err != nil {
		panic(err)
	}
	return b
}

// Register answers navigator.credentials.create for rpID and origin.
func (a *Authenticator) Register(rpID, origin string, challenge, userHandle []byte) passkey.Registration {
	a.UserHandle = userHandle
	ad := a.head(rpID, a.Flags|0x40)
	ad = append(ad, a.AAGUID[:]...)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(a.ID)))
	ad = append(ad, l[:]...)
	ad = append(ad, a.ID...)
	ad = append(ad, a.COSEKey()...)
	return passkey.Registration{
		CredentialID:      a.ID,
		ClientDataJSON:    ClientData("webauthn.create", challenge, origin),
		AuthenticatorData: ad,
		PublicKey:         a.SPKI(),
		PublicKeyAlg:      passkey.AlgES256,
		Attachment:        a.Attachment,
		Transports:        append([]string(nil), a.Transports...),
	}
}

// SignIn answers navigator.credentials.get for rpID and origin. A counting
// authenticator advances its counter first, as a real one does.
func (a *Authenticator) SignIn(rpID, origin string, challenge []byte) passkey.Assertion {
	if a.Counter != 0 {
		a.Counter++
	}
	return a.SignWith(a.head(rpID, a.Flags), ClientData("webauthn.get", challenge, origin))
}

// SignWith signs arbitrary authenticator data and client data, for tests that
// tamper with either.
func (a *Authenticator) SignWith(authData, clientData []byte) passkey.Assertion {
	h := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte(nil), authData...), h[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.Key, digest[:])
	if err != nil {
		panic(err)
	}
	return passkey.Assertion{
		CredentialID:      a.ID,
		ClientDataJSON:    clientData,
		AuthenticatorData: authData,
		Signature:         sig,
		UserHandle:        a.UserHandle,
	}
}

// Head exposes the authenticator-data head (rpID hash, flags, counter) for
// tests that build their own.
func (a *Authenticator) Head(rpID string, flags byte) []byte { return a.head(rpID, flags) }
