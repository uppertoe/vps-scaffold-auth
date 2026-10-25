package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
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

// The admin door (group-gated) must not presume the configured domain: no hint
// line and a generic placeholder, even though a domain is configured. This is
// the door for people who can't match the domain.
func TestAdminDoorNoDomainPresumption(t *testing.T) {
	srv, _ := testServer(t)
	srv.cfg.AllowedDomains = []string{"monashhealth.org"}
	c := newClient(t, srv.Handler())
	body := c.get("/login?rd=&rqg=admin", nil).Body.String()
	if strings.Contains(body, "This page is for") {
		t.Errorf("admin door presumed a domain hint:\n%s", body)
	}
	if strings.Contains(body, "you@monashhealth.org") {
		t.Errorf("admin door presumed the configured domain in the placeholder:\n%s", body)
	}
	if !strings.Contains(body, `placeholder="you@example.com"`) {
		t.Errorf("admin door should show the generic placeholder:\n%s", body)
	}
}

// /verify on a group-only route carries the group flag into the login URL so the
// login page suppresses the configured-domain fallback (the door is deliberately
// domain-agnostic).
func TestVerifyCarriesGroupOnlyFlag(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv.Handler())
	rec := c.get("/verify", map[string]string{
		"X-Forwarded-Host": "app.example.com",
		"X-Forwarded-Uri":  "/x",
		"X-Auth-Policy":    "groups=admin",
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "rqg=admin") {
		t.Errorf("group-only login redirect missing rqg flag: %q", loc)
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
