// Package secretbox provides authenticated encryption (AES-256-GCM) for the
// small reversible secrets the service must persist: break-glass tokens and
// admin TOTP seeds. Nothing reversible is stored in clear, so a stolen SQLite
// file is inert without the key.
//
// The key is derived from the session secret via an HMAC-SHA256 KDF (so no
// extra configuration is required), or supplied explicitly to decouple at-rest
// encryption from session signing — see NewFromConfig.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// version prefixes every ciphertext so the format can evolve and so legacy
// (unencrypted) values are distinguishable on read.
const version = "v1:"

// kdfInfo domain-separates the derived encryption key from the raw session
// secret used for cookie signing.
const kdfInfo = "vps-auth/data-encryption/v1"

// ErrLegacyPlaintext is returned by Open when the value was not produced by
// Seal (no version prefix). Callers treat it as a stored-in-clear legacy value
// and transparently re-encrypt on next write.
var ErrLegacyPlaintext = errors.New("secretbox: value is legacy plaintext")

var b64 = base64.RawURLEncoding

// Box seals and opens secrets with a fixed 32-byte key.
type Box struct {
	gcm cipher.AEAD
}

// New builds a Box from a 32-byte AES-256 key.
func New(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("secretbox: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{gcm: gcm}, nil
}

// NewFromConfig builds a Box. If explicitKey is non-empty it is used directly
// (must be exactly 32 bytes); otherwise the key is derived from sessionSecret.
// The explicit key lets operators rotate SESSION_SECRET (to invalidate all
// sessions) without making stored secrets undecryptable.
func NewFromConfig(sessionSecret, explicitKey []byte) (*Box, error) {
	if len(explicitKey) > 0 {
		return New(explicitKey)
	}
	return New(DeriveKey(sessionSecret))
}

// DeriveKey derives a 32-byte key from a high-entropy secret via HMAC-SHA256.
func DeriveKey(secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(kdfInfo))
	return mac.Sum(nil) // 32 bytes
}

// Seal encrypts plaintext and returns "v1:" + base64(nonce||ciphertext).
func (b *Box) Seal(plaintext string) (string, error) {
	nonce := make([]byte, b.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := b.gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return version + b64.EncodeToString(sealed), nil
}

// Open reverses Seal. A value without the version prefix yields
// ErrLegacyPlaintext along with the value itself, so callers can use it and
// re-encrypt lazily.
func (b *Box) Open(token string) (string, error) {
	if len(token) < len(version) || token[:len(version)] != version {
		return token, ErrLegacyPlaintext
	}
	raw, err := b64.DecodeString(token[len(version):])
	if err != nil {
		return "", fmt.Errorf("secretbox: malformed ciphertext: %w", err)
	}
	ns := b.gcm.NonceSize()
	if len(raw) < ns {
		return "", errors.New("secretbox: ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	plaintext, err := b.gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("secretbox: decrypt failed: %w", err)
	}
	return string(plaintext), nil
}
