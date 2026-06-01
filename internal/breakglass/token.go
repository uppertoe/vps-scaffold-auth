// Package breakglass implements the supporting machinery for break-the-glass QR
// codes: high-entropy token generation, QR-image rendering, printable PDF cards,
// and asynchronous use-notifications. The persistence and HTTP flow live in the
// store and server packages; this package is pure helpers with no DB access.
package breakglass

import (
	"crypto/rand"
	"encoding/base64"
	"io"
)

// tokenBytes is the entropy of a break-glass token (128 bits). The token is a
// bearer secret printed onto a physical card. 128 bits is unguessable to an
// astronomical margin against the only feasible attack — online, IP-rate-limited
// guessing at /break/ — while keeping the encoded URL short so the QR code stays
// low-density and easy to scan.
const tokenBytes = 16

// GenerateToken returns a new URL-safe, 256-bit random token.
func GenerateToken() (string, error) {
	buf := make([]byte, tokenBytes)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
