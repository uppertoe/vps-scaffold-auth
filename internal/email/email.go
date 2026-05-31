// Package email sends the OTP code to users through a pluggable backend:
// SMTP (universal), the Resend HTTP API, or a log backend for local/CI use.
package email

import (
	"context"
	"fmt"
)

// Message is a single email to send.
type Message struct {
	To      string
	Subject string
	HTML    string
	Text    string
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
