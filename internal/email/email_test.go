package email

import (
	"context"
	"strings"
	"testing"
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
