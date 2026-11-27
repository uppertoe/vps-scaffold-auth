package passkey_test

// The differential corpus: real-shaped registrations and sign-ins, made with
// passkeytest and then mutated by hand, each with the verdict the verifier
// gave when the corpus was recorded. Any change to the verifier, such as
// moving its parsing to a library, must give the same verdict on every case.
//
// The corpus is fixed bytes (ECDSA signatures are randomised, so it cannot be
// regenerated to the same bytes). To record it afresh, which should be rare
// and deliberate:
//
//	go test ./internal/passkey -run TestCorpus -update-corpus

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/passkey"
	"github.com/uppertoe/vps-scaffold-auth/internal/passkey/passkeytest"
)

var updateCorpus = flag.Bool("update-corpus", false, "record testdata/corpus.json afresh")

const corpusFile = "testdata/corpus.json"

type corpusCase struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"` // "register" or "sign-in"
	Challenge []byte `json:"challenge"`

	CredentialID      []byte `json:"credentialId,omitempty"`
	ClientDataJSON    []byte `json:"clientDataJSON"`
	AuthenticatorData []byte `json:"authenticatorData"`
	PublicKey         []byte `json:"publicKey,omitempty"` // registration: as the browser reports it
	PublicKeyAlg      int    `json:"publicKeyAlg,omitempty"`

	Signature   []byte `json:"signature,omitempty"`
	StoredKey   []byte `json:"storedKey,omitempty"` // sign-in: as stored at registration
	StoredCount uint32 `json:"storedCount,omitempty"`

	// The verdict: "ok" or the error's name. On "ok", what was returned.
	Want   string `json:"want"`
	Count  uint32 `json:"count,omitempty"`
	Synced bool   `json:"synced,omitempty"`
	AAGUID string `json:"aaguid,omitempty"`
}

func verdict(err error) string {
	for name, e := range map[string]error{
		"ErrClientData": passkey.ErrClientData, "ErrAuthData": passkey.ErrAuthData,
		"ErrNotVerified": passkey.ErrNotVerified, "ErrKey": passkey.ErrKey,
		"ErrSignature": passkey.ErrSignature, "ErrCounter": passkey.ErrCounter,
	} {
		if errors.Is(err, e) {
			return name
		}
	}
	if err != nil {
		return "other: " + err.Error()
	}
	return "ok"
}

// run gives the verifier's verdict on c, filling in what it returned.
func (c corpusCase) run() corpusCase {
	switch c.Kind {
	case "register":
		cred, err := rp.VerifyRegistration(passkey.Registration{
			CredentialID: c.CredentialID, ClientDataJSON: c.ClientDataJSON,
			AuthenticatorData: c.AuthenticatorData, PublicKey: c.PublicKey, PublicKeyAlg: c.PublicKeyAlg,
		}, c.Challenge)
		c.Want, c.Count, c.Synced, c.AAGUID = verdict(err), 0, false, ""
		if err == nil {
			c.Count, c.Synced, c.AAGUID = cred.SignCount, cred.Synced, passkey.AAGUIDString(cred.AAGUID)
		}
	case "sign-in":
		n, err := rp.VerifyAssertion(passkey.Assertion{
			ClientDataJSON: c.ClientDataJSON, AuthenticatorData: c.AuthenticatorData, Signature: c.Signature,
		}, c.Challenge, c.StoredKey, c.StoredCount)
		c.Want, c.Count = verdict(err), n
	}
	return c
}

func TestCorpus(t *testing.T) {
	if *updateCorpus {
		cases := buildCorpus()
		for i := range cases {
			cases[i] = cases[i].run()
		}
		b, err := json.MarshalIndent(cases, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(corpusFile, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("recorded %d cases", len(cases))
	}
	b, err := os.ReadFile(corpusFile)
	if err != nil {
		t.Fatal(err)
	}
	var cases []corpusCase
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 50 {
		t.Fatalf("corpus holds only %d cases", len(cases))
	}
	seen := map[string]bool{}
	for _, want := range cases {
		if seen[want.Name] {
			t.Fatalf("case %q appears twice", want.Name)
		}
		seen[want.Name] = true
		got := want.run()
		if got.Want != want.Want || got.Count != want.Count || got.Synced != want.Synced || got.AAGUID != want.AAGUID {
			t.Errorf("%s (%s): got %s count %d synced %v aaguid %q; recorded %s count %d synced %v aaguid %q",
				want.Name, want.Kind, got.Want, got.Count, got.Synced, got.AAGUID, want.Want, want.Count, want.Synced, want.AAGUID)
		}
	}
}

// buildCorpus makes the cases. It runs only when the corpus is recorded.
func buildCorpus() []corpusCase {
	var out []corpusCase
	ch := challenge()
	reg := func(name string, a *passkeytest.Authenticator, mut func(r *passkey.Registration)) {
		r := a.Register(rp.ID, rp.Origin, ch, []byte("handle"))
		if mut != nil {
			mut(&r)
		}
		out = append(out, corpusCase{Name: name, Kind: "register", Challenge: ch, CredentialID: r.CredentialID,
			ClientDataJSON: r.ClientDataJSON, AuthenticatorData: r.AuthenticatorData, PublicKey: r.PublicKey, PublicKeyAlg: r.PublicKeyAlg})
	}
	// withCOSE rebuilds a's registration with cose in place of its key.
	withCOSE := func(a *passkeytest.Authenticator, cose []byte) func(r *passkey.Registration) {
		return func(r *passkey.Registration) {
			r.AuthenticatorData = append(r.AuthenticatorData[:len(r.AuthenticatorData)-77:len(r.AuthenticatorData)-77], cose...)
		}
	}
	cdWith := func(typ string, edit func(m map[string]any)) []byte {
		m := map[string]any{}
		json.Unmarshal(passkeytest.ClientData(typ, ch, rp.Origin), &m)
		edit(m)
		b, _ := json.Marshal(m)
		return b
	}
	rawCD := func(s string) []byte { return []byte(strings.ReplaceAll(s, "CH", enc(ch))) }

	phone, computer, other := passkeytest.New(), passkeytest.NewComputer(), passkeytest.New()

	// Registrations that are accepted.
	reg("register: phone (synced)", phone, nil)
	reg("register: computer (Windows Hello, counting)", computer, nil)
	unsynced := passkeytest.New()
	unsynced.Flags = 0x01 | 0x04
	reg("register: not backup eligible", unsynced, nil)
	reg("register: Chrome's extra client-data member", passkeytest.New(), func(r *passkey.Registration) {
		r.ClientDataJSON = cdWith("webauthn.create", func(m map[string]any) {
			m["other_keys_can_be_added_here"] = "do not compare clientDataJSON against a template. See https://goo.gl/yabPex"
		})
	})
	reg("register: client data with escaped slashes", passkeytest.New(), func(r *passkey.Registration) {
		r.ClientDataJSON = rawCD(`{"type":"webauthn.create","challenge":"CH","origin":"https:\/\/auth.example.org","crossOrigin":false}`)
	})
	reg("register: client data without crossOrigin", passkeytest.New(), func(r *passkey.Registration) {
		r.ClientDataJSON = rawCD(`{"type":"webauthn.create","challenge":"CH","origin":"https://auth.example.org"}`)
	})
	ext := passkeytest.New()
	ext.Flags |= 0x80
	reg("register: credProtect extension after the key", ext, func(r *passkey.Registration) {
		r.AuthenticatorData = append(r.AuthenticatorData, append([]byte{0xa1, 0x6b}, append([]byte("credProtect"), 0x02)...)...)
	})

	// Registrations that are refused.
	reg("register: origin of a sibling app", passkeytest.New(), func(r *passkey.Registration) {
		r.ClientDataJSON = passkeytest.ClientData("webauthn.create", ch, "https://app.example.org")
	})
	reg("register: origin with a trailing slash", passkeytest.New(), func(r *passkey.Registration) {
		r.ClientDataJSON = passkeytest.ClientData("webauthn.create", ch, rp.Origin+"/")
	})
	reg("register: origin with the default port", passkeytest.New(), func(r *passkey.Registration) {
		r.ClientDataJSON = passkeytest.ClientData("webauthn.create", ch, rp.Origin+":443")
	})
	reg("register: origin in capitals", passkeytest.New(), func(r *passkey.Registration) {
		r.ClientDataJSON = passkeytest.ClientData("webauthn.create", ch, strings.ToUpper(rp.Origin))
	})
	reg("register: http origin", passkeytest.New(), func(r *passkey.Registration) {
		r.ClientDataJSON = passkeytest.ClientData("webauthn.create", ch, "http://auth.example.org")
	})
	reg("register: a sign-in's client data", passkeytest.New(), func(r *passkey.Registration) {
		r.ClientDataJSON = passkeytest.ClientData("webauthn.get", ch, rp.Origin)
	})
	reg("register: another challenge", passkeytest.New(), func(r *passkey.Registration) {
		r.ClientDataJSON = passkeytest.ClientData("webauthn.create", challenge(), rp.Origin)
	})
	reg("register: padded challenge", passkeytest.New(), func(r *passkey.Registration) {
		r.ClientDataJSON = rawCD(`{"type":"webauthn.create","challenge":"CH=","origin":"https://auth.example.org"}`)
	})
	reg("register: cross-origin iframe", passkeytest.New(), func(r *passkey.Registration) {
		r.ClientDataJSON = cdWith("webauthn.create", func(m map[string]any) { m["crossOrigin"] = true })
	})
	reg("register: top origin present", passkeytest.New(), func(r *passkey.Registration) {
		r.ClientDataJSON = cdWith("webauthn.create", func(m map[string]any) { m["topOrigin"] = "https://evil.example" })
	})
	reg("register: empty top origin", passkeytest.New(), func(r *passkey.Registration) {
		r.ClientDataJSON = cdWith("webauthn.create", func(m map[string]any) { m["topOrigin"] = "" })
	})
	reg("register: member names in other cases", passkeytest.New(), func(r *passkey.Registration) {
		r.ClientDataJSON = rawCD(`{"tYpe":"webauthn.create","ChAllenge":"CH","ORIGIN":"https://auth.example.org"}`)
	})
	reg("register: type given in two cases", passkeytest.New(), func(r *passkey.Registration) {
		r.ClientDataJSON = rawCD(`{"type":"webauthn.create","challenge":"CH","origin":"https://auth.example.org","TYPE":"webauthn.get"}`)
	})
	reg("register: challenge with a line break", passkeytest.New(), func(r *passkey.Registration) {
		c := enc(ch)
		r.ClientDataJSON = []byte(`{"type":"webauthn.create","challenge":"` + c[:10] + `\n` + c[10:] + `","origin":"https://auth.example.org"}`)
	})
	reg("register: topOrigin as null", passkeytest.New(), func(r *passkey.Registration) {
		r.ClientDataJSON = rawCD(`{"type":"webauthn.create","challenge":"CH","origin":"https://auth.example.org","topOrigin":null}`)
	})
	reg("register: crossOrigin as null", passkeytest.New(), func(r *passkey.Registration) {
		r.ClientDataJSON = rawCD(`{"type":"webauthn.create","challenge":"CH","origin":"https://auth.example.org","crossOrigin":null}`)
	})
	reg("register: crossOrigin as a string", passkeytest.New(), func(r *passkey.Registration) {
		r.ClientDataJSON = rawCD(`{"type":"webauthn.create","challenge":"CH","origin":"https://auth.example.org","crossOrigin":"false"}`)
	})
	reg("register: client data is not JSON", passkeytest.New(), func(r *passkey.Registration) {
		r.ClientDataJSON = []byte("type=webauthn.create")
	})
	reg("register: key for the whole domain", passkeytest.New(), func(r *passkey.Registration) {
		*r = passkeytest.New().Register("example.org", rp.Origin, ch, nil)
	})
	noUV := passkeytest.New()
	noUV.Flags = 0x01
	reg("register: no user verification", noUV, nil)
	noUP := passkeytest.New()
	noUP.Flags = 0x04
	reg("register: no user presence", noUP, nil)
	reg("register: browser reports a different key", passkeytest.New(), func(r *passkey.Registration) { r.PublicKey = other.SPKI() })
	reg("register: RS256", passkeytest.New(), func(r *passkey.Registration) { r.PublicKeyAlg = -257 })
	reg("register: EdDSA", passkeytest.New(), func(r *passkey.Registration) { r.PublicKeyAlg = -8 })
	reg("register: browser reports a P-384 key", passkeytest.New(), func(r *passkey.Registration) {
		k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		r.PublicKey, _ = x509.MarshalPKIXPublicKey(&k.PublicKey)
	})
	reg("register: public key is not SPKI", passkeytest.New(), func(r *passkey.Registration) { r.PublicKey = []byte("not a key") })
	reg("register: credential ID differs", passkeytest.New(), func(r *passkey.Registration) { r.CredentialID = []byte("someone else's id") })
	reg("register: truncated authenticator data", passkeytest.New(), func(r *passkey.Registration) { r.AuthenticatorData = r.AuthenticatorData[:40] })
	reg("register: authenticator data shorter than its head", passkeytest.New(), func(r *passkey.Registration) { r.AuthenticatorData = r.AuthenticatorData[:36] })
	reg("register: attested-data flag but no attested data", passkeytest.New(), func(r *passkey.Registration) { r.AuthenticatorData = r.AuthenticatorData[:37] })
	reg("register: attested data without its flag", passkeytest.New(), func(r *passkey.Registration) { r.AuthenticatorData[32] &^= 0x40 })
	reg("register: key cut short", passkeytest.New(), func(r *passkey.Registration) { r.AuthenticatorData = r.AuthenticatorData[:len(r.AuthenticatorData)-1] })
	reg("register: credential ID length overruns", passkeytest.New(), func(r *passkey.Registration) {
		binary.BigEndian.PutUint16(r.AuthenticatorData[53:55], 0xffff)
	})
	reg("register: credential ID of length zero", passkeytest.New(), func(r *passkey.Registration) {
		ad := append([]byte(nil), r.AuthenticatorData[:53]...)
		ad = append(ad, 0, 0)
		r.AuthenticatorData = append(ad, r.AuthenticatorData[55+len(r.CredentialID):]...)
		r.CredentialID = nil
	})
	long := passkeytest.New()
	long.ID = make([]byte, 1024)
	rand.Read(long.ID)
	reg("register: credential ID longer than WebAuthn allows", long, nil)
	reg("register: another key appended after the authenticator's", passkeytest.New(), func(r *passkey.Registration) {
		r.AuthenticatorData = append(r.AuthenticatorData, other.COSEKey()...)
		r.PublicKey = other.SPKI()
	})
	reg("register: trailing byte without the extensions flag", passkeytest.New(), func(r *passkey.Registration) {
		r.AuthenticatorData = append(r.AuthenticatorData, 0x00)
	})

	// COSE keys that are not the canonical ES256 encoding of the reported key.
	cose := func(name string, edit func(k []byte) []byte) {
		a := passkeytest.New()
		reg("register: COSE "+name, a, withCOSE(a, edit(a.COSEKey())))
	}
	cose("kty in a long integer form", func(k []byte) []byte { return append([]byte{0xa5, 0x01, 0x18, 0x02}, k[3:]...) })
	cose("entries reordered", func(k []byte) []byte {
		return append([]byte{0xa5, 0x03, 0x26, 0x01, 0x02}, k[5:]...)
	})
	cose("with a sixth entry", func(k []byte) []byte { return append(append([]byte{0xa6}, k[1:]...), 0x04, 0x01) })
	cose("alg EdDSA", func(k []byte) []byte { k[4] = 0x27; return k })
	cose("alg RS256 in the key", func(k []byte) []byte {
		return append([]byte{0xa5, 0x01, 0x02, 0x03, 0x39, 0x01, 0x00}, k[5:]...)
	})
	cose("curve P-384", func(k []byte) []byte { k[7] = 0x02; return k })
	cose("kty OKP", func(k []byte) []byte { k[2] = 0x01; return k })
	cose("y of the other parity", func(k []byte) []byte {
		y := new(big.Int).SetBytes(k[45:77])
		p := elliptic.P256().Params().P
		copy(k[45:77], new(big.Int).Sub(p, y).FillBytes(make([]byte, 32)))
		return k
	})
	cose("x one byte short", func(k []byte) []byte {
		out := append([]byte(nil), k[:9]...)
		out = append(out, 0x1f)
		out = append(out, k[11:42]...)
		return append(out, k[42:]...)
	})
	cose("as an indefinite-length map", func(k []byte) []byte { return append(append([]byte{0xbf}, k[1:]...), 0xff) })
	cose("with kty given twice", func(k []byte) []byte { return append([]byte{0xa6, 0x01, 0x02}, k[1:]...) })
	cose("with x as a tagged byte string", func(k []byte) []byte {
		return append(append(append([]byte(nil), k[:8]...), 0xd8, 0x40), k[8:]...)
	})
	cose("with alg as a float", func(k []byte) []byte {
		return append([]byte{0xa5, 0x01, 0x02, 0x03, 0xf9, 0xc7, 0x00}, k[5:]...)
	})
	cose("with x as a text string", func(k []byte) []byte { k[8] = 0x78; return k })
	cose("not CBOR at all", func(k []byte) []byte {
		return []byte("not cbor, but seventy-seven bytes long, padded out to that length ......")
	})

	// Sign-ins.
	signIn := func(name string, a *passkeytest.Authenticator, stored []byte, storedCount uint32, as passkey.Assertion) {
		out = append(out, corpusCase{Name: name, Kind: "sign-in", Challenge: ch, ClientDataJSON: as.ClientDataJSON,
			AuthenticatorData: as.AuthenticatorData, Signature: as.Signature, StoredKey: stored, StoredCount: storedCount})
	}
	syncedKey := phone.SPKI()
	get := func(edit func(m map[string]any)) []byte { return cdWith("webauthn.get", edit) }
	keep := func(map[string]any) {}

	signIn("sign-in: phone (synced)", phone, syncedKey, 0, phone.SignIn(rp.ID, rp.Origin, ch))
	computer.Counter = 5
	signIn("sign-in: computer, counter advances", computer, computer.SPKI(), 5, computer.SignIn(rp.ID, rp.Origin, ch))
	signIn("sign-in: computer, counter repeated", computer, computer.SPKI(), 6, computer.SignWith(computer.Head(rp.ID, 0x05), get(keep)))
	computer.Counter = 4
	signIn("sign-in: computer, counter behind", computer, computer.SPKI(), 6, computer.SignWith(computer.Head(rp.ID, 0x05), get(keep)))
	signIn("sign-in: counter reset to zero", phone, syncedKey, 3, phone.SignIn(rp.ID, rp.Origin, ch))
	signIn("sign-in: synced flags (BE and BS)", phone, syncedKey, 0, phone.SignWith(phone.Head(rp.ID, 0x1d), get(keep)))
	signIn("sign-in: Chrome's extra client-data member", phone, syncedKey, 0, phone.SignWith(phone.Head(rp.ID, 0x05), get(func(m map[string]any) {
		m["other_keys_can_be_added_here"] = "do not compare clientDataJSON against a template. See https://goo.gl/yabPex"
	})))
	signIn("sign-in: trailing bytes after the head, signed", phone, syncedKey, 0, phone.SignWith(append(phone.Head(rp.ID, 0x05), 0xde, 0xad), get(keep)))
	signIn("sign-in: extensions flag with an extension, signed", phone, syncedKey, 0, phone.SignWith(append(phone.Head(rp.ID, 0x85), 0xa0), get(keep)))
	signIn("sign-in: attested-data flag on a sign-in, signed", phone, syncedKey, 0, phone.SignWith(phone.Head(rp.ID, 0x45), get(keep)))

	signIn("sign-in: origin of a sibling app", phone, syncedKey, 0, phone.SignIn(rp.ID, "https://app.example.org", ch))
	signIn("sign-in: origin with the default port", phone, syncedKey, 0, phone.SignIn(rp.ID, rp.Origin+":443", ch))
	signIn("sign-in: a registration's client data", phone, syncedKey, 0, phone.SignWith(phone.Head(rp.ID, 0x05), passkeytest.ClientData("webauthn.create", ch, rp.Origin)))
	signIn("sign-in: payment client data", phone, syncedKey, 0, phone.SignWith(phone.Head(rp.ID, 0x05), passkeytest.ClientData("payment.get", ch, rp.Origin)))
	signIn("sign-in: replayed from an earlier challenge", phone, syncedKey, 0, phone.SignIn(rp.ID, rp.Origin, challenge()))
	signIn("sign-in: cross-origin iframe", phone, syncedKey, 0, phone.SignWith(phone.Head(rp.ID, 0x05), get(func(m map[string]any) { m["crossOrigin"] = true })))
	signIn("sign-in: top origin present", phone, syncedKey, 0, phone.SignWith(phone.Head(rp.ID, 0x05), get(func(m map[string]any) {
		m["crossOrigin"] = true
		m["topOrigin"] = rp.Origin
	})))
	signIn("sign-in: empty top origin", phone, syncedKey, 0, phone.SignWith(phone.Head(rp.ID, 0x05), get(func(m map[string]any) { m["topOrigin"] = "" })))
	signIn("sign-in: relying party is the whole domain", phone, syncedKey, 0, phone.SignIn("example.org", rp.Origin, ch))
	signIn("sign-in: no user verification", phone, syncedKey, 0, phone.SignWith(phone.Head(rp.ID, 0x01), get(keep)))
	signIn("sign-in: verified but not present", phone, syncedKey, 0, phone.SignWith(phone.Head(rp.ID, 0x04), get(keep)))
	signIn("sign-in: authenticator data shorter than its head", phone, syncedKey, 0, phone.SignWith(phone.Head(rp.ID, 0x05)[:36], get(keep)))
	signIn("sign-in: signed by another key", other, syncedKey, 0, other.SignIn(rp.ID, rp.Origin, ch))
	altered := phone.SignIn(rp.ID, rp.Origin, ch)
	altered.AuthenticatorData[36] ^= 1
	signIn("sign-in: authenticator data altered after signing", phone, syncedKey, 0, altered)
	cdAltered := phone.SignWith(phone.Head(rp.ID, 0x05), get(keep))
	cdAltered.ClientDataJSON = get(func(m map[string]any) { m["extra"] = "x" })
	signIn("sign-in: client data altered after signing", phone, syncedKey, 0, cdAltered)
	signIn("sign-in: stored key is not a key", phone, []byte("not a key"), 0, phone.SignIn(rp.ID, rp.Origin, ch))
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384SPKI, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	signIn("sign-in: stored key is P-384", phone, p384SPKI, 0, phone.SignIn(rp.ID, rp.Origin, ch))

	// Signatures in other encodings.
	sig := func(name string, edit func(r, s *big.Int) []byte) {
		as := phone.SignIn(rp.ID, rp.Origin, ch)
		r, s := splitSig(as.Signature)
		as.Signature = edit(r, s)
		signIn("sign-in: signature "+name, phone, syncedKey, 0, as)
	}
	n := elliptic.P256().Params().N
	sig("with high S", func(r, s *big.Int) []byte { return derSig(r.Bytes(), new(big.Int).Sub(n, s).Bytes()) })
	sig("with a needless leading zero", func(r, s *big.Int) []byte { return derSig(append([]byte{0, 0}, r.Bytes()...), s.Bytes()) })
	sig("with a trailing byte", func(r, s *big.Int) []byte { return append(derSig(r.Bytes(), s.Bytes()), 0) })
	sig("as raw r and s", func(r, s *big.Int) []byte {
		return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	})
	sig("with r zero", func(r, s *big.Int) []byte { return derSig([]byte{0}, s.Bytes()) })
	sig("empty", func(r, s *big.Int) []byte { return nil })
	sig("with r and s swapped", func(r, s *big.Int) []byte { return derSig(s.Bytes(), r.Bytes()) })

	// A sign-in signed over the wrong hash construction.
	wrong := phone.SignIn(rp.ID, rp.Origin, ch)
	h := sha256.Sum256(append(append([]byte(nil), wrong.AuthenticatorData...), wrong.ClientDataJSON...))
	wrong.Signature, _ = ecdsa.SignASN1(rand.Reader, phone.Key, h[:])
	signIn("sign-in: signed over the raw client data", phone, syncedKey, 0, wrong)
	return out
}

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func splitSig(der []byte) (*big.Int, *big.Int) {
	var v struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &v); err != nil {
		panic(err)
	}
	return v.R, v.S
}

// derSig writes an ECDSA signature with the integers' bytes as given, so a
// test can make one that is not minimally encoded.
func derSig(r, s []byte) []byte {
	integer := func(v []byte) []byte {
		if len(v) == 0 || v[0]&0x80 != 0 {
			v = append([]byte{0}, v...)
		}
		return append([]byte{0x02, byte(len(v))}, v...)
	}
	body := append(integer(r), integer(s)...)
	return append([]byte{0x30, byte(len(body))}, body...)
}
