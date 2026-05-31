package email

import (
	"context"
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
