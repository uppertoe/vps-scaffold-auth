// Package otp generates and hashes the short numeric one-time codes that are
// emailed to users. Codes are never stored in the clear; only their SHA-256
// hash is persisted, and verification uses a constant-time comparison.
package otp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"math/big"
)

// Generate returns a random numeric code of the given length using a
// cryptographically secure source.
func Generate(length int) (string, error) {
	const digits = "0123456789"
	buf := make([]byte, length)
	max := big.NewInt(int64(len(digits)))
	for i := range buf {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		buf[i] = digits[n.Int64()]
	}
	return string(buf), nil
}

// Hash returns the hex-encoded SHA-256 of a code. This is what gets stored.
func Hash(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// Equal compares two hex hashes in constant time.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
