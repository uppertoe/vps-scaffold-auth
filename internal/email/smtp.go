package email

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// smtpDefaultTimeout bounds a send whose context carries no deadline. net/smtp
// has no timeouts of its own, so without this a stalled relay would hold the
// connection, its goroutine and its socket open indefinitely.
const smtpDefaultTimeout = 30 * time.Second

// SMTPSender delivers mail via an SMTP relay. TLS is MANDATORY: port 465 uses
// implicit TLS (SMTPS); every other port requires STARTTLS and the send is
// refused if the server does not advertise it. This closes the STARTTLS-strip
// downgrade where an active MITM removes the capability and net/smtp's
// best-effort SendMail would silently transmit the OTP (a live credential) in
// cleartext.
type SMTPSender struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

// Send delivers a single message over an authenticated, TLS-protected channel.
func (s *SMTPSender) Send(ctx context.Context, msg Message) error {
	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)
	body := buildMIME(s.From, msg)
	tlsCfg := &tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}

	// Every step of the exchange is bounded by the context: the dial honours
	// cancellation, the connection carries an absolute deadline, and a cancel
	// after the dial closes the socket so a blocked read or write returns.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(smtpDefaultTimeout)
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	dialer := &net.Dialer{Timeout: smtpDefaultTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return fmt.Errorf("smtp deadline: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	var client *smtp.Client
	if s.Port == 465 {
		// Implicit TLS: the whole connection is wrapped from the first byte.
		tconn := tls.Client(conn, tlsCfg)
		if err := tconn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return fmt.Errorf("smtp tls dial: %w", err)
		}
		client, err = smtp.NewClient(tconn, s.Host)
	} else {
		client, err = smtp.NewClient(conn, s.Host)
	}
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp dial: %w", err)
	}
	defer client.Close()

	if s.Port != 465 {
		// STARTTLS is required. A server (or a MITM stripping the capability)
		// that does not offer it means we would send in cleartext -- fail closed.
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("smtp: server does not advertise STARTTLS; refusing to send OTP in cleartext")
		}
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}

	if s.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", s.Username, s.Password, s.Host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := client.Mail(extractAddr(s.From)); err != nil {
		return fmt.Errorf("smtp mail: %w", err)
	}
	if err := client.Rcpt(msg.To); err != nil {
		return fmt.Errorf("smtp rcpt: %w", err)
	}
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := wc.Write(body); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp data close: %w", err)
	}
	return client.Quit()
}

// buildMIME assembles a minimal multipart/alternative message with text and
// HTML parts. The boundary is random per message so a body that contains
// attacker-controlled text -- e.g. the scanner User-Agent carried into a
// break-glass notification -- cannot embed a matching delimiter to inject an
// extra MIME part. (Header injection is separately prevented by sanitizeHeader;
// the body parts are written verbatim, so the unguessable boundary is what keeps
// body content from breaking the MIME structure.)
//
// A message with no HTML part (a break-glass notification carries text only)
// is sent as plain text, not as a multipart whose HTML alternative is empty:
// a client that prefers HTML would otherwise show an empty incident notice.
func buildMIME(from string, msg Message) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", sanitizeHeader(from))
	fmt.Fprintf(&b, "To: %s\r\n", sanitizeHeader(msg.To))
	fmt.Fprintf(&b, "Subject: %s\r\n", sanitizeHeader(msg.Subject))
	b.WriteString("MIME-Version: 1.0\r\n")
	if msg.HTML == "" {
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		b.WriteString(msg.Text)
		b.WriteString("\r\n")
		return []byte(b.String())
	}
	boundary := randomBoundary()
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

// sanitizeHeader strips CR and LF so a value carried into an email header
// (e.g. an admin-set break-glass label flowing into the Subject) cannot inject
// additional headers or a body. Newlines are replaced with a single space.
func sanitizeHeader(v string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(v)
}

// randomBoundary returns an unguessable multipart boundary (hex, valid in the
// boundary charset). A random boundary is what makes body injection infeasible:
// an attacker can't embed a delimiter that matches a value they can't predict.
func randomBoundary() string {
	var raw [18]byte
	if _, err := rand.Read(raw[:]); err != nil {
		// crypto/rand failing is catastrophic and effectively never happens; the
		// fixed fallback still blocks header injection (see sanitizeHeader) and
		// only re-exposes the guessable-boundary case.
		return "vps-scaffold-auth-boundary"
	}
	return "vps-auth-" + hex.EncodeToString(raw[:])
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
