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
