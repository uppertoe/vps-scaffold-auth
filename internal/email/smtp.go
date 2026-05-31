package email

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"
)

// SMTPSender delivers mail via an SMTP relay. It uses STARTTLS on submission
// ports when the server advertises it (net/smtp's SendMail handles this).
type SMTPSender struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

// Send delivers a single message.
func (s *SMTPSender) Send(ctx context.Context, msg Message) error {
	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)
	var auth smtp.Auth
	if s.Username != "" {
		auth = smtp.PlainAuth("", s.Username, s.Password, s.Host)
	}
	body := buildMIME(s.From, msg)
	if err := smtp.SendMail(addr, auth, extractAddr(s.From), []string{msg.To}, body); err != nil {
		return fmt.Errorf("smtp send: %w", err)
	}
	return nil
}

// buildMIME assembles a minimal multipart/alternative message with text and
// HTML parts.
func buildMIME(from string, msg Message) []byte {
	const boundary = "vps-scaffold-auth-boundary"
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", msg.To)
	fmt.Fprintf(&b, "Subject: %s\r\n", msg.Subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", boundary)

	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
	b.WriteString(msg.Text)
	b.WriteString("\r\n\r\n")

	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.WriteString("Content-Type: text/html; charset=UTF-8\r\n\r\n")
	b.WriteString(msg.HTML)
	b.WriteString("\r\n\r\n")

	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return []byte(b.String())
}

// extractAddr returns the bare address from a "Name <addr>" header value.
func extractAddr(from string) string {
	if i := strings.LastIndex(from, "<"); i >= 0 {
		if j := strings.LastIndex(from, ">"); j > i {
			return from[i+1 : j]
		}
	}
	return strings.TrimSpace(from)
}
