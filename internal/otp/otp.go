// Package otp generates and hashes the short numeric one-time codes that are
// emailed to users. Codes are never stored in the clear; only their SHA-256
// hash is persisted, and verification uses a constant-time comparison.
package otp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"math/big"
)

// hashKeyedInfo domain-separates the keyed OTP hash from any other use of the
// same secret (e.g. cookie signing).
const hashKeyedInfo = "vps-auth/otp-code/v1"

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

// Hash returns the hex-encoded SHA-256 of a value. Suitable for high-entropy
// inputs (e.g. break-glass tokens) where an offline brute force is infeasible.
func Hash(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// HashKeyed returns a hex-encoded HMAC-SHA256 of a code under key. Use this for
// low-entropy values such as the short numeric login codes: without the key, a
// stolen database cannot brute-force the (e.g. 10^6) preimage space, so a live
// code can't be recovered from the stored hash alone.
func HashKeyed(code string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(hashKeyedInfo))
	mac.Write([]byte(code))
	return hex.EncodeToString(mac.Sum(nil))
}

// Equal compares two hex hashes in constant time.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
