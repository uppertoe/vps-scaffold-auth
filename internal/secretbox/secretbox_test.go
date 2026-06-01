package secretbox

import (
	"strings"
	"testing"
)

func newTestBox(t *testing.T) *Box {
	t.Helper()
	b, err := NewFromConfig([]byte("this-is-a-test-session-secret-32b!!"), nil)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	return b
}

func TestSealOpenRoundTrip(t *testing.T) {
	b := newTestBox(t)
	for _, pt := range []string{"", "hello", "JBSWY3DPEHPK3PXP", strings.Repeat("x", 1000)} {
		sealed, err := b.Seal(pt)
		if err != nil {
			t.Fatalf("Seal(%q): %v", pt, err)
		}
		if !strings.HasPrefix(sealed, version) {
			t.Errorf("sealed value missing version prefix: %q", sealed)
		}
		got, err := b.Open(sealed)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if got != pt {
			t.Errorf("round-trip mismatch: got %q want %q", got, pt)
		}
	}
}

func TestSealDistinctNonces(t *testing.T) {
	b := newTestBox(t)
	a, _ := b.Seal("same")
	c, _ := b.Seal("same")
	if a == c {
		t.Error("two Seals of the same plaintext produced identical ciphertext (nonce reuse)")
	}
}

func TestOpenTampered(t *testing.T) {
	b := newTestBox(t)
	sealed, _ := b.Seal("secret")
	// Flip a character within the base64 body (just after the "v1:" prefix, in
	// the nonce region). A middle character always changes the decoded bytes —
	// unlike the final character, whose low bits RawURLEncoding ignores.
	body := []byte(sealed)
	i := len(version) + 4
	if body[i] == 'A' {
		body[i] = 'B'
	} else {
		body[i] = 'A'
	}
	if _, err := b.Open(string(body)); err == nil {
		t.Error("Open accepted tampered ciphertext")
	}
}

func TestOpenLegacyPlaintext(t *testing.T) {
	b := newTestBox(t)
	got, err := b.Open("JBSWY3DPEHPK3PXP") // no version prefix
	if err != ErrLegacyPlaintext {
		t.Fatalf("want ErrLegacyPlaintext, got %v", err)
	}
	if got != "JBSWY3DPEHPK3PXP" {
		t.Errorf("legacy passthrough mismatch: %q", got)
	}
}

func TestWrongKeyFails(t *testing.T) {
	b := newTestBox(t)
	sealed, _ := b.Seal("secret")
	other, err := NewFromConfig([]byte("a-completely-different-secret-32by!"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Open(sealed); err == nil {
		t.Error("Open with wrong key succeeded")
	}
}

func TestExplicitKeyRequires32Bytes(t *testing.T) {
	if _, err := NewFromConfig(nil, []byte("too-short")); err == nil {
		t.Error("expected error for short explicit key")
	}
}
