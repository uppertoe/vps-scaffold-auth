package otp

import (
	"strings"
	"testing"
)

func TestGenerateLengthAndDigits(t *testing.T) {
	for _, n := range []int{4, 6, 8} {
		code, err := Generate(n)
		if err != nil {
			t.Fatalf("Generate(%d): %v", n, err)
		}
		if len(code) != n {
			t.Errorf("Generate(%d) length = %d", n, len(code))
		}
		if strings.Trim(code, "0123456789") != "" {
			t.Errorf("Generate(%d) = %q, not all digits", n, code)
		}
	}
}

func TestGenerateRandomish(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		c, err := Generate(6)
		if err != nil {
			t.Fatal(err)
		}
		seen[c] = true
	}
	if len(seen) < 40 {
		t.Errorf("expected mostly unique codes, got %d distinct of 50", len(seen))
	}
}

func TestHashAndEqual(t *testing.T) {
	h1 := Hash("123456")
	h2 := Hash("123456")
	if h1 != h2 {
		t.Error("Hash not deterministic")
	}
	if !Equal(h1, h2) {
		t.Error("Equal returned false for identical hashes")
	}
	if Equal(h1, Hash("654321")) {
		t.Error("Equal returned true for different codes")
	}
	if len(h1) != 64 {
		t.Errorf("Hash length = %d, want 64 hex chars", len(h1))
	}
}

func TestHashKeyed(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	other := []byte("ffffffffffffffffffffffffffffffff")

	h := HashKeyed("123456", key)
	if h != HashKeyed("123456", key) {
		t.Error("HashKeyed not deterministic for the same code+key")
	}
	if h == HashKeyed("654321", key) {
		t.Error("HashKeyed collided for different codes")
	}
	// Different key => different hash: this is what stops offline brute force of
	// the small numeric space from a stolen DB without the key.
	if h == HashKeyed("123456", other) {
		t.Error("HashKeyed produced the same digest under a different key")
	}
	// Must not equal the unkeyed SHA-256 of the same input.
	if h == Hash("123456") {
		t.Error("HashKeyed equals unkeyed Hash; the key had no effect")
	}
	if len(h) != 64 {
		t.Errorf("HashKeyed length = %d, want 64 hex chars", len(h))
	}
}
