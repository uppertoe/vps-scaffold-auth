package server

import (
	"context"
	"strings"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/email"
)

// A direct visit (no route requirement) hints the configured allow-list and
// derives the email placeholder from it, so the bare login page still tells the
// user which domain to use.
func TestDirectVisitHintsConfiguredDomain(t *testing.T) {
	srv, _ := testServer(t)
	srv.cfg.AllowedDomains = []string{"monashhealth.org"}
	c := newClient(t, srv.Handler())
	body := c.get("/login", nil).Body.String()
	if !strings.Contains(body, "This page is for") || !strings.Contains(body, "monashhealth.org") {
		t.Errorf("direct login page did not hint the configured domain:\n%s", body)
	}
	if !strings.Contains(body, `placeholder="you@monashhealth.org"`) {
		t.Errorf("email placeholder not derived from the configured domain:\n%s", body)
	}
}

// A domain-gated route still wins over the configured-domain fallback: the
// route's domain is what's hinted and drives the placeholder.
func TestRouteDomainWinsOverConfiguredFallback(t *testing.T) {
	srv, _ := testServer(t)
	srv.cfg.AllowedDomains = []string{"example.com"}
	c := newClient(t, srv.Handler())
	body := c.get("/login?rd=&rqd=rch.org.au", nil).Body.String()
	if !strings.Contains(body, `placeholder="you@rch.org.au"`) {
		t.Errorf("placeholder should follow the route requirement, not the allow-list:\n%s", body)
	}
}

// The OTP subject substitutes {brand} (and drops {code} if the template omits
// it), giving a branded subject when a deployment overrides the default.
func TestOTPSubjectBrandedOverride(t *testing.T) {
	srv, _ := testServer(t)
	srv.cfg.OTPEmailSubject = "Login - {brand}"
	srv.cfg.BrandName = "MCH Anaesthesia"
	msg := srv.buildCodeEmail(context.Background(), "user@example.com", "123456")
	if msg.Subject != "Login - MCH Anaesthesia" {
		t.Errorf("subject = %q, want %q", msg.Subject, "Login - MCH Anaesthesia")
	}
}

// The default subject leads with the code (inbox-preview affordance preserved).
func TestOTPSubjectDefaultLeadsWithCode(t *testing.T) {
	srv, _ := testServer(t)
	srv.cfg.OTPEmailSubject = "{code} is your sign-in code"
	msg := srv.buildCodeEmail(context.Background(), "user@example.com", "123456")
	if msg.Subject != "123456 is your sign-in code" {
		t.Errorf("subject = %q, want code-led default", msg.Subject)
	}
}

// An empty/whitespace subject template can never produce a blank Subject header —
// it falls back to the code-led form.
func TestOTPSubjectEmptyFallsBack(t *testing.T) {
	srv, _ := testServer(t)
	srv.cfg.OTPEmailSubject = "   "
	msg := srv.buildCodeEmail(context.Background(), "user@example.com", "123456")
	if msg.Subject != "123456 is your sign-in code" {
		t.Errorf("subject = %q, want code-led fallback", msg.Subject)
	}
}

// The code email's plain text leads with the code, and the message carries
// the code and the sign-in origin for the OTP-Token header.
func TestCodeEmailLeadsWithTheCode(t *testing.T) {
	srv, _ := testServer(t)
	srv.cfg.BrandName = "RCH Anaesthesia"
	msg := srv.buildCodeEmail(context.Background(), "user@example.com", "282397")
	if !strings.HasPrefix(msg.Text, "282397 is your RCH Anaesthesia sign-in code.\n\n") {
		t.Fatalf("text = %q", msg.Text)
	}
	if msg.OTPCode != "282397" || msg.OTPOrigin != "https://auth.example.com" {
		t.Fatalf("OTP fields = %q %q", msg.OTPCode, msg.OTPOrigin)
	}
	if got := email.OTPTokenHeader(msg); got != `"282397"; origin="https://auth.example.com"` {
		t.Fatalf("header = %q", got)
	}
}
