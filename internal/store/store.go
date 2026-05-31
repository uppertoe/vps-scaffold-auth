// Package store persists the only mutable state the service needs: the
// single-use OTP codes (for replay protection) and, optionally, admin TOTP
// secrets. Sessions are stateless signed cookies and never touch the store.
package store

import (
	"context"
	"time"
)

// ConsumeResult is the outcome of attempting to verify an OTP code.
type ConsumeResult int

const (
	// ConsumeOK means the code matched and has been consumed (single-use).
	ConsumeOK ConsumeResult = iota
	// ConsumeNoCode means no outstanding code exists for the email.
	ConsumeNoCode
	// ConsumeExpired means a code existed but has passed its expiry.
	ConsumeExpired
	// ConsumeMismatch means the code did not match (an attempt was counted).
	ConsumeMismatch
	// ConsumeTooManyAttempts means the attempt cap was reached; code invalidated.
	ConsumeTooManyAttempts
)

// Store is the persistence interface. Implementations must be safe for
// concurrent use.
type Store interface {
	// SaveCode stores (replacing any existing code for the email) the hash of a
	// freshly issued OTP code with its expiry, resetting the attempt counter.
	SaveCode(ctx context.Context, email, codeHash string, expiresAt time.Time) error

	// ConsumeCode atomically checks candidateHash against the stored code for
	// email, enforcing expiry and the attempt cap, and consumes the code on a
	// successful match.
	ConsumeCode(ctx context.Context, email, candidateHash string, maxAttempts int, now time.Time) (ConsumeResult, error)

	// GetTOTPSecret returns the stored TOTP secret for an admin email.
	GetTOTPSecret(ctx context.Context, email string) (secret string, ok bool, err error)

	// SetTOTPSecret stores (or replaces) the TOTP secret for an admin email.
	SetTOTPSecret(ctx context.Context, email, secret string) error

	// Close releases underlying resources.
	Close() error
}
