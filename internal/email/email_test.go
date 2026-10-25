package email

import (
	"bytes"
	"context"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewBackendSelection(t *testing.T) {
	if s, err := New(Config{Backend: "log"}); err != nil || s == nil {
		t.Errorf("log backend: %v", err)
	} else if _, ok := s.(*LogSender); !ok {
		t.Errorf("log backend wrong type %T", s)
	}

	if s, err := New(Config{Backend: "smtp", SMTPHost: "h", From: "a@b"}); err != nil {
		t.Errorf("smtp backend: %v", err)
	} else if _, ok := s.(*SMTPSender); !ok {
		t.Errorf("smtp backend wrong type %T", s)
	}

	if s, err := New(Config{Backend: "resend", ResendAPIKey: "k", From: "a@b"}); err != nil {
		t.Errorf("resend backend: %v", err)
	} else if _, ok := s.(*ResendSender); !ok {
		t.Errorf("resend backend wrong type %T", s)
	}

	if _, err := New(Config{Backend: "smoke-signal"}); err == nil {
		t.Error("expected error for unknown backend")
	}
}

func TestLogSenderSucceeds(t *testing.T) {
	s := &LogSender{}
	if err := s.Send(context.Background(), Message{To: "a@b", Subject: "s", Text: "code 123456"}); err != nil {
		t.Errorf("LogSender.Send: %v", err)
	}
}

func TestBuildMIMEStripsHeaderInjection(t *testing.T) {
	// A label-derived Subject carrying CRLF must not break out into new headers
	// or a forged body.
	msg := Message{
		To:      "admin@example.com",
		Subject: "Break-glass used: Lab\r\nBcc: attacker@evil.com\r\n\r\nInjected body",
		Text:    "legit body",
	}
	out := string(buildMIME("auth@example.com", msg))
	headers, _, _ := strings.Cut(out, "\r\n\r\n")
	if strings.Contains(headers, "attacker@evil.com") {
		// Acceptable only if it stayed folded inside the Subject line, not as a
		// standalone Bcc header.
		for _, line := range strings.Split(headers, "\r\n") {
			if strings.HasPrefix(strings.ToLower(line), "bcc:") {
				t.Fatalf("injected Bcc header survived: %q", line)
			}
		}
	}
	if strings.Count(out, "\r\nSubject:") != 1 {
		t.Errorf("expected exactly one Subject header, MIME was:\n%s", out)
	}
}

func TestBuildMIMEResistsBoundaryInjection(t *testing.T) {
	// An attacker-controlled body field (e.g. the scanner User-Agent carried into
	// a break-glass notification) embeds what used to be the fixed boundary, to
	// forge an extra MIME part. With a random per-message boundary the embedded
	// delimiter is inert, so the message still parses to exactly two parts.
	inject := "Mozilla\r\n--vps-scaffold-auth-boundary\r\n" +
		"Content-Type: text/html\r\n\r\n<b>phish</b>\r\n--vps-scaffold-auth-boundary--"
	raw := buildMIME("auth@example.com", Message{
		To: "admin@example.com", Subject: "Break-glass used", Text: "ua: " + inject, HTML: "<p>hi</p>",
	})

	if strings.Contains(string(raw), `boundary="vps-scaffold-auth-boundary"`) {
		t.Fatal("message used the old fixed boundary; injection would succeed")
	}

	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse message: %v", err)
	}
	_, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("parse content-type: %v", err)
	}
	mr := multipart.NewReader(m.Body, params["boundary"])
	var bodies []string
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("read part: %v", err)
		}
		body, _ := io.ReadAll(p)
		bodies = append(bodies, string(body))
	}
	// The decisive check: the genuine HTML part must survive intact. With the old
	// fixed boundary the injected "--boundary--" close delimiter makes the parser
	// stop early, so the genuine "<p>hi</p>" part is never reached and the second
	// part is the attacker's forged "<b>phish</b>" instead — same part *count*,
	// which is why counting alone is insufficient. With a random boundary the
	// injected delimiters are inert body text and the real part is preserved.
	var sawGenuineHTML, sawForgedPart bool
	for _, b := range bodies {
		if strings.TrimSpace(b) == "<p>hi</p>" {
			sawGenuineHTML = true
		}
		if strings.TrimSpace(b) == "<b>phish</b>" {
			sawForgedPart = true // the injected content parsed as its own MIME part
		}
	}
	if !sawGenuineHTML {
		t.Fatalf("genuine HTML part did not survive; injection truncated the message. parts=%q", bodies)
	}
	if sawForgedPart {
		t.Fatalf("injected content parsed as a standalone MIME part. parts=%q", bodies)
	}
}

func TestRandomBoundaryIsPerMessage(t *testing.T) {
	a := string(buildMIME("auth@example.com", Message{To: "x@example.com", Subject: "s", Text: "t", HTML: "<p>t</p>"}))
	b := string(buildMIME("auth@example.com", Message{To: "x@example.com", Subject: "s", Text: "t", HTML: "<p>t</p>"}))
	if boundaryOf(a) == "" || boundaryOf(a) == boundaryOf(b) {
		t.Fatalf("boundary should be random per message: %q vs %q", boundaryOf(a), boundaryOf(b))
	}
}

// boundaryOf extracts the multipart boundary from a built message's headers.
func boundaryOf(mimeMsg string) string {
	const marker = `boundary="`
	i := strings.Index(mimeMsg, marker)
	if i < 0 {
		return ""
	}
	rest := mimeMsg[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func TestExtractAddr(t *testing.T) {
	cases := map[string]string{
		"Login <auth@example.com>": "auth@example.com",
		"auth@example.com":         "auth@example.com",
		"  auth@example.com  ":     "auth@example.com",
	}
	for in, want := range cases {
		if got := extractAddr(in); got != want {
			t.Errorf("extractAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

// A relay that accepts the connection and then says nothing must not hold
// Send past its context: the dial, greeting and every later step are bounded.
func TestSMTPSendHonoursContextDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c) // accept and stall: never send the 220 greeting
			mu.Unlock()
		}
	}()
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			c.Close()
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	s := &SMTPSender{Host: host, Port: port, From: "a@b"}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = s.Send(ctx, Message{To: "x@y", Subject: "s", Text: "t"})
	if err == nil {
		t.Fatal("Send returned nil against a stalled relay")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Send took %v, want to return at the context deadline", elapsed)
	}
}

// A text-only message is sent as plain text, so a client that prefers HTML
// does not pick an empty alternative over the incident details.
func TestBuildMIMETextOnlyIsPlainText(t *testing.T) {
	raw := buildMIME("auth@example.com", Message{To: "oncall@example.com", Subject: "Break-glass used", Text: "Location: Lab 1"})
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	ct, _, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
	if err != nil || ct != "text/plain" {
		t.Fatalf("Content-Type = %q (%v), want text/plain", m.Header.Get("Content-Type"), err)
	}
	body, _ := io.ReadAll(m.Body)
	if !strings.Contains(string(body), "Location: Lab 1") {
		t.Fatalf("body lacks the text: %q", body)
	}
}
