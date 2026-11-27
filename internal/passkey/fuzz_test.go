package passkey_test

// Fuzz targets for every way into the verifier. Each holds one field
// arbitrary and the rest genuine, so the fuzzer explores that field's parser
// past the checks before it, and each states what an accepted input must
// satisfy, beyond not panicking. The seeds are the differential corpus.
//
// The verifier takes no attestation object: the registration form posts
// getAuthenticatorData() and getPublicKey(), so the credential's COSE key is
// fuzzed inside authenticator data (FuzzRegistrationCOSEKey).
//
//	go test ./internal/passkey -run '^$' -fuzz FuzzSignInClientData -fuzztime 60s

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/passkey"
	"github.com/uppertoe/vps-scaffold-auth/internal/passkey/passkeytest"
)

var fuzzChallenge = []byte("0123456789abcdef0123456789abcdef")

func seeds(f *testing.F, add func(c corpusCase)) {
	b, err := os.ReadFile(corpusFile)
	if err != nil {
		f.Fatal(err)
	}
	var cases []corpusCase
	if err := json.Unmarshal(b, &cases); err != nil {
		f.Fatal(err)
	}
	for _, c := range cases {
		add(c)
	}
}

// clientDataAcceptable is what any accepted clientDataJSON must say.
func clientDataAcceptable(raw []byte, typ string, ch []byte) bool {
	var cd map[string]any
	if json.Unmarshal(raw, &cd) != nil {
		return false
	}
	got, _ := cd["challenge"].(string)
	top, _ := cd["topOrigin"]
	return cd["type"] == typ && cd["origin"] == rp.Origin && got == base64.RawURLEncoding.EncodeToString(ch) &&
		(cd["crossOrigin"] == nil || cd["crossOrigin"] == false) && top == nil
}

// authDataAcceptable is what any accepted authenticator data must say.
func authDataAcceptable(ad []byte) bool {
	h := sha256.Sum256([]byte(rp.ID))
	return len(ad) >= 37 && bytes.Equal(ad[:32], h[:]) && ad[32]&0x05 == 0x05
}

// Client data signed by the registered key: accepted only when it names this
// ceremony, challenge and origin.
func FuzzSignInClientData(f *testing.F) {
	a := passkeytest.New()
	f.Add(passkeytest.ClientData("webauthn.get", fuzzChallenge, rp.Origin))
	seeds(f, func(c corpusCase) { f.Add(c.ClientDataJSON) })
	key := a.SPKI()
	head := a.Head(rp.ID, 0x05)
	f.Fuzz(func(t *testing.T, cd []byte) {
		if _, err := rp.VerifyAssertion(a.SignWith(head, cd), fuzzChallenge, key, 0); err == nil && !clientDataAcceptable(cd, "webauthn.get", fuzzChallenge) {
			t.Fatalf("accepted client data %q", cd)
		}
	})
}

// Authenticator data signed by the registered key: accepted only for this
// host, with the person present and verified, and a counter that advances.
func FuzzSignInAuthData(f *testing.F) {
	a := passkeytest.New()
	f.Add(a.Head(rp.ID, 0x05), uint32(0))
	seeds(f, func(c corpusCase) { f.Add(c.AuthenticatorData, c.StoredCount) })
	key := a.SPKI()
	cd := passkeytest.ClientData("webauthn.get", fuzzChallenge, rp.Origin)
	f.Fuzz(func(t *testing.T, ad []byte, stored uint32) {
		n, err := rp.VerifyAssertion(a.SignWith(ad, cd), fuzzChallenge, key, stored)
		if err != nil {
			return
		}
		if !authDataAcceptable(ad) {
			t.Fatalf("accepted authenticator data %x", ad)
		}
		if got := binary.BigEndian.Uint32(ad[33:37]); got != n || (n|stored != 0 && n <= stored) {
			t.Fatalf("counter %d returned as %d against stored %d", got, n, stored)
		}
	})
}

// A signature over genuine data: accepted only when it verifies.
func FuzzSignInSignature(f *testing.F) {
	a := passkeytest.New()
	good := a.SignIn(rp.ID, rp.Origin, fuzzChallenge)
	f.Add(good.Signature)
	seeds(f, func(c corpusCase) { f.Add(c.Signature) })
	key := a.SPKI()
	cdHash := sha256.Sum256(good.ClientDataJSON)
	digest := sha256.Sum256(append(append([]byte(nil), good.AuthenticatorData...), cdHash[:]...))
	f.Fuzz(func(t *testing.T, sig []byte) {
		as := good
		as.Signature = sig
		if _, err := rp.VerifyAssertion(as, fuzzChallenge, key, 0); err == nil && !ecdsa.VerifyASN1(&a.Key.PublicKey, digest[:], sig) {
			t.Fatalf("accepted signature %x", sig)
		}
	})
}

// A stored key that is not the one that signed is never accepted.
func FuzzSignInStoredKey(f *testing.F) {
	a := passkeytest.New()
	good := a.SignIn(rp.ID, rp.Origin, fuzzChallenge)
	f.Add(a.SPKI())
	f.Add(passkeytest.New().SPKI())
	seeds(f, func(c corpusCase) { f.Add(c.StoredKey); f.Add(c.PublicKey) })
	f.Fuzz(func(t *testing.T, key []byte) {
		if _, err := rp.VerifyAssertion(good, fuzzChallenge, key, 0); err == nil && !bytes.Equal(key, a.SPKI()) {
			// Another encoding of the same key would be harmless; anything
			// else is a forgery.
			if !sameKey(key, a) {
				t.Fatalf("accepted a sign-in against stored key %x", key)
			}
		}
	})
}

// The credential's COSE key inside otherwise genuine registration data:
// accepted only when it is exactly the canonical ES256 key the browser
// reports, followed by nothing unless the extensions flag is set.
func FuzzRegistrationCOSEKey(f *testing.F) {
	a := passkeytest.New()
	f.Add(a.COSEKey(), false)
	f.Add(append(a.COSEKey(), 0xa0), true)
	seeds(f, func(c corpusCase) {
		if c.Kind == "register" && len(c.AuthenticatorData) > 55 {
			f.Add(c.AuthenticatorData[55:], false)
		}
	})
	f.Fuzz(func(t *testing.T, cose []byte, ext bool) {
		reg := a.Register(rp.ID, rp.Origin, fuzzChallenge, []byte("h"))
		ad := reg.AuthenticatorData[: 55+len(a.ID) : 55+len(a.ID)]
		if ext {
			ad[32] |= 0x80
		}
		reg.AuthenticatorData = append(ad, cose...)
		cred, err := rp.VerifyRegistration(reg, fuzzChallenge)
		if err != nil {
			return
		}
		want := a.COSEKey()
		if !bytes.HasPrefix(cose, want) || (!ext && len(cose) != len(want)) || !bytes.Equal(cred.PublicKey, a.SPKI()) {
			t.Fatalf("accepted COSE key %x (extensions %v)", cose, ext)
		}
	})
}

// Every field of a registration arbitrary: never a panic, and an accepted one
// always names this ceremony and host, and returns what the browser posted.
func FuzzRegistration(f *testing.F) {
	f.Add([]byte("id"), []byte("{}"), make([]byte, 37), []byte{0x30}, -7)
	seeds(f, func(c corpusCase) {
		if c.Kind == "register" {
			f.Add(c.CredentialID, c.ClientDataJSON, c.AuthenticatorData, c.PublicKey, c.PublicKeyAlg)
		}
	})
	f.Fuzz(func(t *testing.T, id, cd, ad, spki []byte, alg int) {
		cred, err := rp.VerifyRegistration(passkey.Registration{CredentialID: id, ClientDataJSON: cd, AuthenticatorData: ad, PublicKey: spki, PublicKeyAlg: alg}, fuzzChallenge)
		if err != nil {
			return
		}
		if !clientDataAcceptable(cd, "webauthn.create", fuzzChallenge) || !authDataAcceptable(ad) || ad[32]&0x40 == 0 ||
			alg != passkey.AlgES256 || !bytes.Equal(cred.ID, id) || !bytes.Equal(cred.PublicKey, spki) || !coseMatchesSPKI(ad, spki) {
			t.Fatalf("accepted registration id %x cd %q ad %x key %x alg %d", id, cd, ad, spki, alg)
		}
	})
}

// coseMatchesSPKI reports whether the COSE key in registration data ad is
// exactly the canonical ES256 encoding of the P-256 key in spki, followed by
// nothing unless the extensions flag is set. It is written independently of
// the verifier, from the CTAP2 layout.
func coseMatchesSPKI(ad, spki []byte) bool {
	if len(ad) < 55 {
		return false
	}
	idLen := int(binary.BigEndian.Uint16(ad[53:55]))
	if len(ad) < 55+idLen {
		return false
	}
	cose := ad[55+idLen:]
	k, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return false
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return false
	}
	e, err := pub.ECDH()
	if err != nil {
		return false
	}
	raw := e.Bytes()
	want := append([]byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}, raw[1:33]...)
	want = append(append(want, 0x22, 0x58, 0x20), raw[33:65]...)
	return bytes.HasPrefix(cose, want) && (ad[32]&0x80 != 0 || len(cose) == len(want))
}

func sameKey(spki []byte, a *passkeytest.Authenticator) bool {
	reg := a.Register(rp.ID, rp.Origin, fuzzChallenge, nil)
	reg.PublicKey = spki
	_, err := rp.VerifyRegistration(reg, fuzzChallenge)
	return err == nil
}
