package passkey_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/passkey"
	"github.com/uppertoe/vps-scaffold-auth/internal/passkey/passkeytest"
)

var rp = passkey.RelyingParty{ID: "auth.example.org", Origin: "https://auth.example.org"}

func challenge() []byte {
	c := make([]byte, 32)
	rand.Read(c)
	return c
}

func registered(t *testing.T) (*passkeytest.Authenticator, passkey.Credential) {
	t.Helper()
	a := passkeytest.New()
	ch := challenge()
	cred, err := rp.VerifyRegistration(a.Register(rp.ID, rp.Origin, ch, []byte("handle")), ch)
	if err != nil {
		t.Fatalf("registration refused: %v", err)
	}
	return a, cred
}

func TestRegisterThenSignIn(t *testing.T) {
	a, cred := registered(t)
	if !cred.Synced {
		t.Error("a backup-eligible passkey should be marked synced")
	}
	ch := challenge()
	n, err := rp.VerifyAssertion(a.SignIn(rp.ID, rp.Origin, ch), ch, cred.PublicKey, cred.SignCount)
	if err != nil || n != 0 {
		t.Fatalf("sign-in: count %d, err %v", n, err)
	}
	// A synced passkey reports zero every time, which is not a regression.
	ch = challenge()
	if _, err := rp.VerifyAssertion(a.SignIn(rp.ID, rp.Origin, ch), ch, cred.PublicKey, 0); err != nil {
		t.Fatalf("second sign-in with a zero counter: %v", err)
	}
}

// Every registration check, each broken on its own.
func TestRegistrationRefusals(t *testing.T) {
	other := passkeytest.New()
	for name, tc := range map[string]struct {
		mut  func(r *passkey.Registration, ch []byte)
		want error
	}{
		"origin of a sibling app": {func(r *passkey.Registration, ch []byte) {
			r.ClientDataJSON = passkeytest.ClientData("webauthn.create", ch, "https://app.example.org")
		}, passkey.ErrClientData},
		"a sign-in, not a registration": {func(r *passkey.Registration, ch []byte) {
			r.ClientDataJSON = passkeytest.ClientData("webauthn.get", ch, rp.Origin)
		}, passkey.ErrClientData},
		"another challenge": {func(r *passkey.Registration, ch []byte) {
			r.ClientDataJSON = passkeytest.ClientData("webauthn.create", challenge(), rp.Origin)
		}, passkey.ErrClientData},
		"cross-origin iframe": {func(r *passkey.Registration, ch []byte) {
			r.ClientDataJSON = withField(r.ClientDataJSON, "crossOrigin", true)
		}, passkey.ErrClientData},
		"top origin present": {func(r *passkey.Registration, ch []byte) {
			r.ClientDataJSON = withField(r.ClientDataJSON, "topOrigin", "https://evil.example")
		}, passkey.ErrClientData},
		"key for the whole domain": {func(r *passkey.Registration, ch []byte) {
			a := passkeytest.New()
			*r = a.Register("example.org", rp.Origin, ch, nil)
		}, passkey.ErrAuthData},
		"no user verification": {func(r *passkey.Registration, ch []byte) {
			a := passkeytest.New()
			a.Flags = 0x01
			*r = a.Register(rp.ID, rp.Origin, ch, nil)
		}, passkey.ErrNotVerified},
		"no user presence": {func(r *passkey.Registration, ch []byte) {
			a := passkeytest.New()
			a.Flags = 0x04
			*r = a.Register(rp.ID, rp.Origin, ch, nil)
		}, passkey.ErrNotVerified},
		"browser reports a different key": {func(r *passkey.Registration, ch []byte) {
			r.PublicKey = other.SPKI()
		}, passkey.ErrKey},
		"RS256 or anything but ES256": {func(r *passkey.Registration, ch []byte) {
			r.PublicKeyAlg = -257
		}, passkey.ErrKey},
		"P-384 key": {func(r *passkey.Registration, ch []byte) {
			k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			r.PublicKey, _ = x509.MarshalPKIXPublicKey(&k.PublicKey)
		}, passkey.ErrKey},
		"credential ID differs from authenticator data": {func(r *passkey.Registration, ch []byte) {
			r.CredentialID = []byte("someone else's id")
		}, passkey.ErrAuthData},
		"truncated authenticator data": {func(r *passkey.Registration, ch []byte) {
			r.AuthenticatorData = r.AuthenticatorData[:40]
		}, passkey.ErrAuthData},
		"no attested credential data": {func(r *passkey.Registration, ch []byte) {
			r.AuthenticatorData = r.AuthenticatorData[:37]
		}, passkey.ErrAuthData},
		"browser's key appended after the authenticator's": {func(r *passkey.Registration, ch []byte) {
			r.AuthenticatorData = append(r.AuthenticatorData, other.COSEKey()...)
			r.PublicKey = other.SPKI()
		}, passkey.ErrKey},
		"trailing bytes without the extensions flag": {func(r *passkey.Registration, ch []byte) {
			r.AuthenticatorData = append(r.AuthenticatorData, 0x00)
		}, passkey.ErrKey},
	} {
		t.Run(name, func(t *testing.T) {
			ch := challenge()
			reg := passkeytest.New().Register(rp.ID, rp.Origin, ch, nil)
			tc.mut(&reg, ch)
			if _, err := rp.VerifyRegistration(reg, ch); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// Every sign-in check, each broken on its own.
func TestSignInRefusals(t *testing.T) {
	a, cred := registered(t)
	for name, tc := range map[string]struct {
		make func(ch []byte) passkey.Assertion
		key  []byte
		want error
	}{
		"origin of a sibling app": {func(ch []byte) passkey.Assertion {
			return a.SignIn(rp.ID, "https://app.example.org", ch)
		}, nil, passkey.ErrClientData},
		"a registration, not a sign-in": {func(ch []byte) passkey.Assertion {
			return a.SignWith(a.Head(rp.ID, 0x05), passkeytest.ClientData("webauthn.create", ch, rp.Origin))
		}, nil, passkey.ErrClientData},
		"replayed from an earlier challenge": {func(ch []byte) passkey.Assertion {
			return a.SignIn(rp.ID, rp.Origin, challenge())
		}, nil, passkey.ErrClientData},
		"relying party is the whole domain": {func(ch []byte) passkey.Assertion {
			return a.SignIn("example.org", rp.Origin, ch)
		}, nil, passkey.ErrAuthData},
		"no user verification": {func(ch []byte) passkey.Assertion {
			return a.SignWith(a.Head(rp.ID, 0x01), passkeytest.ClientData("webauthn.get", ch, rp.Origin))
		}, nil, passkey.ErrNotVerified},
		"signed by another key": {func(ch []byte) passkey.Assertion {
			return passkeytest.New().SignIn(rp.ID, rp.Origin, ch)
		}, nil, passkey.ErrSignature},
		"authenticator data altered after signing": {func(ch []byte) passkey.Assertion {
			as := a.SignIn(rp.ID, rp.Origin, ch)
			as.AuthenticatorData[36] ^= 1
			return as
		}, nil, passkey.ErrSignature},
		"client data altered after signing": {func(ch []byte) passkey.Assertion {
			as := a.SignWith(a.Head(rp.ID, 0x05), passkeytest.ClientData("webauthn.get", ch, rp.Origin))
			as.ClientDataJSON = withField(as.ClientDataJSON, "extra", "x")
			return as
		}, nil, passkey.ErrSignature},
		"stored key is not P-256": {func(ch []byte) passkey.Assertion {
			return a.SignIn(rp.ID, rp.Origin, ch)
		}, []byte("not a key"), passkey.ErrKey},
	} {
		t.Run(name, func(t *testing.T) {
			ch := challenge()
			key := cred.PublicKey
			if tc.key != nil {
				key = tc.key
			}
			if _, err := rp.VerifyAssertion(tc.make(ch), ch, key, 0); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// A counting authenticator must move forward; a copy replaying an old counter
// is refused.
func TestCounterMustAdvance(t *testing.T) {
	a := passkeytest.New()
	a.Counter = 5
	ch := challenge()
	cred, err := rp.VerifyRegistration(a.Register(rp.ID, rp.Origin, ch, nil), ch)
	if err != nil {
		t.Fatal(err)
	}
	ch = challenge()
	n, err := rp.VerifyAssertion(a.SignIn(rp.ID, rp.Origin, ch), ch, cred.PublicKey, cred.SignCount)
	if err != nil || n != 6 {
		t.Fatalf("count %d, err %v", n, err)
	}
	a.Counter = 5 // the copy, one step behind
	ch = challenge()
	if _, err := rp.VerifyAssertion(a.SignIn(rp.ID, rp.Origin, ch), ch, cred.PublicKey, n); !errors.Is(err, passkey.ErrCounter) {
		t.Fatalf("got %v, want ErrCounter", err)
	}
}

func withField(raw []byte, k string, v any) []byte {
	m := map[string]any{}
	json.Unmarshal(raw, &m)
	m[k] = v
	b, _ := json.Marshal(m)
	return b
}

// FuzzVerifyNeverAcceptsWithoutTheKey: arbitrary bytes in every field never
// verify against a key that did not sign them, and never panic.
func FuzzVerifyNeverAcceptsWithoutTheKey(f *testing.F) {
	a := passkeytest.New()
	ch := []byte("0123456789abcdef0123456789abcdef")
	good := a.SignIn(rp.ID, rp.Origin, ch)
	f.Add(good.ClientDataJSON, good.AuthenticatorData, good.Signature)
	f.Add([]byte("{}"), make([]byte, 37), []byte{0x30, 0x00})
	other := passkeytest.New().SPKI()
	f.Fuzz(func(t *testing.T, cd, ad, sig []byte) {
		as := passkey.Assertion{ClientDataJSON: cd, AuthenticatorData: ad, Signature: sig}
		if _, err := rp.VerifyAssertion(as, ch, other, 0); err == nil {
			t.Fatalf("accepted a signature from a key that never signed")
		}
		rp.VerifyRegistration(passkey.Registration{CredentialID: sig, ClientDataJSON: cd, AuthenticatorData: ad, PublicKey: sig, PublicKeyAlg: -7}, ch)
	})
}
