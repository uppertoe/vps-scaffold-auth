package passkeytest

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
)

// A passkey as the gateway has stored it since passkeys were added: the
// credential ID and user handle as raw bytes, and the public key as the
// SubjectPublicKeyInfo DER the browser's getPublicKey() reported. These bytes
// are fixed, so a test that signs in with them proves that a passkey stored
// in this format still works after any change to the verifier.
const (
	StoredSPKIHex         = "3059301306072a8648ce3d020106082a8648ce3d030107034200044c5bffd64d691a1f10aa0a44715f0d2dcb4100c660a4df138298127a165d86f86acb58a16b2f49a92ada8744caba01c1d9705e015e09f310beac74abffa45c70"
	StoredCredentialIDHex = "4c67aa38eedf45ae585690104b804fe8"
	StoredUserHandleHex   = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
	// The private key, which in life never leaves the phone.
	storedKeyHex = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104201b29e43f5955b03ba56985cb5e9c1b10055d629c4987785bd23e9b7783f9d107a144034200044c5bffd64d691a1f10aa0a44715f0d2dcb4100c660a4df138298127a165d86f86acb58a16b2f49a92ada8744caba01c1d9705e015e09f310beac74abffa45c70"
)

// Unhex decodes one of the constants above.
func Unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Stored is the authenticator that holds the stored passkey: a synced phone
// passkey, whose counter is always zero.
func Stored() *Authenticator {
	k, err := x509.ParsePKCS8PrivateKey(Unhex(storedKeyHex))
	if err != nil {
		panic(err)
	}
	a := New()
	a.Key = k.(*ecdsa.PrivateKey)
	a.ID = Unhex(StoredCredentialIDHex)
	a.UserHandle = Unhex(StoredUserHandleHex)
	return a
}
