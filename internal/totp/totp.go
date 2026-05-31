// Package totp wraps pquerna/otp to provide optional admin two-factor auth.
// It is only exercised when TOTP_ENABLED=true.
package totp

import (
	"github.com/pquerna/otp/totp"
)

// Enrollment is the result of provisioning a new TOTP secret.
type Enrollment struct {
	Secret string // base32 secret to store
	URL    string // otpauth:// URL for QR codes / authenticator apps
}

// Enroll provisions a new TOTP secret for an account.
func Enroll(issuer, account string) (Enrollment, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
	})
	if err != nil {
		return Enrollment{}, err
	}
	return Enrollment{Secret: key.Secret(), URL: key.URL()}, nil
}

// Validate reports whether code is currently valid for secret.
func Validate(code, secret string) bool {
	return totp.Validate(code, secret)
}
