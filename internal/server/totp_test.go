package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	pqtotp "github.com/pquerna/otp/totp"

	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/totp"
)

// provisionTOTP stores an encrypted secret for email using the same crypto the
// server uses, and returns the raw secret so the test can generate codes.
func provisionTOTP(t *testing.T, srv *Server, email string) string {
	t.Helper()
	en, err := totp.Enroll("example.com", email)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := srv.secrets.Seal(en.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.store.SetTOTPSecret(context.Background(), email, sealed); err != nil {
		t.Fatal(err)
	}
	return en.Secret
}

// An admin with no provisioned secret must be DENIED at login, not self-enrolled.
// This is the core of the admin-provisioned model: a login (which only proves
// inbox control) must not be able to bootstrap the second factor.
func TestTOTPNoSelfEnrolment(t *testing.T) {
	srv, sender := testServer(t)
	srv.cfg.TOTPEnabled = true
	c := newClient(t, srv.Handler())

	c.postForm("/request", url.Values{"email": {"admin@example.com"}})
	code := sender.code()
	if code == "" {
		t.Fatal("no OTP code captured")
	}
	rec := c.postForm("/verify-code", url.Values{"code": {code}})

	// Denied with a setup-required page, NOT a redirect (login is incomplete).
	if rec.Code != http.StatusForbidden {
		t.Fatalf("/verify-code = %d, want 403 (setup required)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Two-factor setup required") {
		t.Errorf("missing setup-required message; body=%q", rec.Body.String())
	}
	// No session was issued, and no secret was silently created.
	if ck := c.cookies[session.SessionCookie]; ck != nil {
		t.Error("a session cookie was issued without TOTP")
	}
	if _, ok, _ := srv.store.GetTOTPSecret(context.Background(), "admin@example.com"); ok {
		t.Error("a TOTP secret was self-enrolled at login (must be admin-provisioned)")
	}
	if rec := c.get("/verify", nil); rec.Code != http.StatusFound {
		t.Errorf("/verify after failed login = %d, want 302 to login", rec.Code)
	}
}

// With a provisioned secret, an admin is challenged and a valid code logs them in.
func TestTOTPLoginWithProvisionedSecret(t *testing.T) {
	srv, sender := testServer(t)
	srv.cfg.TOTPEnabled = true
	secret := provisionTOTP(t, srv, "admin@example.com")
	c := newClient(t, srv.Handler())

	c.postForm("/request", url.Values{"email": {"admin@example.com"}})
	code := sender.code()
	rec := c.postForm("/verify-code", url.Values{"code": {code}})

	// The email step yields the TOTP challenge, not a session.
	if rec.Code != http.StatusOK {
		t.Fatalf("/verify-code = %d, want 200 (TOTP challenge)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "authenticator") {
		t.Errorf("expected TOTP challenge page; body=%q", rec.Body.String())
	}
	if ck := c.cookies[session.SessionCookie]; ck != nil {
		t.Fatal("session issued before TOTP was satisfied")
	}

	totpCode, err := pqtotp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec = c.postForm("/totp", url.Values{"code": {totpCode}})
	if rec.Code != http.StatusFound {
		t.Fatalf("/totp = %d, want 302 after valid code", rec.Code)
	}

	rec = c.get("/verify", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/verify after TOTP = %d, want 200", rec.Code)
	}
	if g := rec.Header().Get("Remote-Groups"); g != "admin" {
		t.Errorf("groups = %q, want admin", g)
	}
}

// The admin UI provisions, reports status for, and removes admin TOTP secrets.
func TestAdminTOTPProvisioning(t *testing.T) {
	srv, sender := testServer(t) // TOTP disabled, so admin can log in via email only
	ctx := context.Background()
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)

	// Page lists the configured admin as not-yet-enrolled.
	body := c.get("/admin/totp", nil).Body.String()
	if !strings.Contains(body, "admin@example.com") || !strings.Contains(body, "Not set up") {
		t.Fatalf("admin TOTP page missing admin/status; body=%q", body)
	}
	tok := extractCSRF(t, body)

	// Generate: shows the secret once and stores it.
	rec := c.postForm("/admin/totp/generate", url.Values{"csrf": {tok}, "email": {"admin@example.com"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "New secret for") {
		t.Fatalf("generate = %d; body=%q", rec.Code, rec.Body.String())
	}
	if _, ok, _ := srv.store.GetTOTPSecret(ctx, "admin@example.com"); !ok {
		t.Fatal("secret not stored after generate")
	}
	if !strings.Contains(c.get("/admin/totp", nil).Body.String(), "Enrolled") {
		t.Error("status not Enrolled after generate")
	}

	// Remove: deletes the secret.
	tok = extractCSRF(t, c.get("/admin/totp", nil).Body.String())
	rec = c.postForm("/admin/totp/remove", url.Values{"csrf": {tok}, "email": {"admin@example.com"}})
	if rec.Code != http.StatusFound {
		t.Fatalf("remove = %d, want 302", rec.Code)
	}
	if _, ok, _ := srv.store.GetTOTPSecret(ctx, "admin@example.com"); ok {
		t.Error("secret still present after remove")
	}
}

// Generate must refuse an address that is not in the admin list, and must reject
// a request with a missing/invalid CSRF token.
func TestAdminTOTPGenerateGuards(t *testing.T) {
	srv, sender := testServer(t)
	ctx := context.Background()
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	tok := extractCSRF(t, c.get("/admin/totp", nil).Body.String())

	// Non-admin target is rejected.
	rec := c.postForm("/admin/totp/generate", url.Values{"csrf": {tok}, "email": {"stranger@evil.com"}})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("generate for non-admin = %d, want 400", rec.Code)
	}
	if _, ok, _ := srv.store.GetTOTPSecret(ctx, "stranger@evil.com"); ok {
		t.Error("secret created for a non-admin address")
	}

	// Missing CSRF token is rejected.
	rec = c.postForm("/admin/totp/generate", url.Values{"email": {"admin@example.com"}})
	if rec.Code != http.StatusForbidden {
		t.Errorf("generate without CSRF = %d, want 403", rec.Code)
	}
}
