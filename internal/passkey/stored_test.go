package passkey_test

import (
	"bytes"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/passkey/passkeytest"
)

// A sign-in recorded byte for byte against a passkey stored in the format
// the gateway has always used (SubjectPublicKeyInfo DER), with the challenge
// it answered. It must verify under any implementation of the verifier.
var recorded = struct{ challenge, authData, clientData, signature string }{
	challenge:  "d5e271d4c38cc80a21d51c867ed20fa3ac19e71974753927d422cfd3d21cea0c",
	authData:   "da9b7f21ad437f56753ea9b809bfb5fcb130da8ac3b7246081ced12b92650d7f1d00000000",
	clientData: `{"type":"webauthn.get","challenge":"1eJx1MOMyAoh1RyGftIPo6wZ5xl0dTkn1CLP09Ic6gw","origin":"https://auth.example.org","crossOrigin":false}`,
	signature:  "3046022100fc64ee5aef3330a7b42a50beb511d57200c3b4953a05a3bbca77230fba954bc40221009bebbe6a1901d4da8f031a8cc42238cad6e118cc93d7501271fa8f90541260db",
}

func TestStoredPasskeySignsIn(t *testing.T) {
	stored := passkeytest.Unhex(passkeytest.StoredSPKIHex)
	a := passkeytest.Stored()
	if !bytes.Equal(a.SPKI(), stored) {
		t.Fatal("the fixture's key is not the stored key")
	}
	// The recorded sign-in.
	as := a.SignWith(passkeytest.Unhex(recorded.authData), []byte(recorded.clientData))
	as.Signature = passkeytest.Unhex(recorded.signature)
	if n, err := rp.VerifyAssertion(as, passkeytest.Unhex(recorded.challenge), stored, 0); err != nil || n != 0 {
		t.Fatalf("recorded sign-in with a stored passkey: count %d, err %v", n, err)
	}
	// A fresh sign-in with the same stored key.
	ch := challenge()
	if _, err := rp.VerifyAssertion(a.SignIn(rp.ID, rp.Origin, ch), ch, stored, 0); err != nil {
		t.Fatalf("fresh sign-in with a stored passkey: %v", err)
	}
}
