// Package email sends the OTP code to users through a pluggable backend:
// SMTP (universal), the Resend HTTP API, or a log backend for local/CI use.
package email

import (
	"context"
	"fmt"
	"strings"
)

// Message is a single email to send.
type Message struct {
	To      string
	Subject string
	HTML    string
	Text    string
	// OTPCode and OTPOrigin, both set on a sign-in code email, add the
	// OTP-Token header (draft-goto-otp-token), which names the code and the
	// site it is for so that a mail client can offer to copy or fill it.
	OTPCode   string
	OTPOrigin string
}

// OTPTokenHeader returns the OTP-Token header value for msg, or "" when msg
// carries no code or either value could not sit safely inside the quoted
// strings: the code must be digits and the origin an https origin without
// quotes, backslashes or control characters.
func OTPTokenHeader(msg Message) string {
	if msg.OTPCode == "" || msg.OTPOrigin == "" {
		return ""
	}
	for _, r := range msg.OTPCode {
		if r < '0' || r > '9' {
			return ""
		}
	}
	if !strings.HasPrefix(msg.OTPOrigin, "https://") && !strings.HasPrefix(msg.OTPOrigin, "http://") {
		return ""
	}
	for _, r := range msg.OTPOrigin {
		if r < 0x21 || r > 0x7e || r == '"' || r == '\\' {
			return ""
		}
	}
	return `"` + msg.OTPCode + `"; origin="` + msg.OTPOrigin + `"`
}

// Sender delivers a Message. Implementations should be safe for concurrent use.
type Sender interface {
	Send(ctx context.Context, msg Message) error
}

// Config selects and configures a backend.
type Config struct {
	Backend      string // log | smtp | resend
	From         string
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	ResendAPIKey string
}

// New builds a Sender from cfg.
func New(cfg Config) (Sender, error) {
	switch cfg.Backend {
	case "log":
		return &LogSender{}, nil
	case "smtp":
		return &SMTPSender{
			Host:     cfg.SMTPHost,
			Port:     cfg.SMTPPort,
			Username: cfg.SMTPUsername,
			Password: cfg.SMTPPassword,
			From:     cfg.From,
		}, nil
	case "resend":
		return &ResendSender{APIKey: cfg.ResendAPIKey, From: cfg.From}, nil
	default:
		return nil, fmt.Errorf("email: unknown backend %q", cfg.Backend)
	}
}
