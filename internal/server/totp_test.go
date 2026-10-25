package server

import (
	"context"
	"errors"
	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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

	rec = c.get("/verify", protectedAny())
	if rec.Code != http.StatusOK {
		t.Fatalf("/verify after TOTP = %d, want 200", rec.Code)
	}
	if g := rec.Header().Get("Remote-Groups"); g != "admin" {
		t.Errorf("groups = %q, want admin", g)
	}
}

// A TOTP code stays valid for its whole ~30s step. A second use of the SAME code
// (e.g. replayed by an attacker who sniffed it) must be rejected, even though the
// raw code still validates against the secret. The clock is pinned so both login
// attempts generate the identical code, making the second a genuine replay.
func TestTOTPCodeCannotBeReplayed(t *testing.T) {
	srv, sender := testServer(t)
	srv.cfg.TOTPEnabled = true
	secret := provisionTOTP(t, srv, "admin@example.com")

	totpCode, err := pqtotp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Submit the SAME code through two independent login flows.
	login := func() int {
		// Sends are async (detached goroutine in sendCode): without a reset,
		// sender.code() can return the PREVIOUS login's cached email, whose OTP
		// was overwritten by this login's /request — a stale code that derails
		// the flow before the replay check this test is about.
		sender.reset()
		c := newClient(t, srv.Handler())
		c.postForm("/request", url.Values{"email": {"admin@example.com"}})
		c.postForm("/verify-code", url.Values{"code": {sender.code()}})
		return c.postForm("/totp", url.Values{"code": {totpCode}}).Code
	}

	if got := login(); got != http.StatusFound {
		t.Fatalf("first TOTP use = %d, want 302", got)
	}
	if got := login(); got != http.StatusUnauthorized {
		t.Fatalf("replayed TOTP code = %d, want 401 (rejected)", got)
	}
}

// The TOTP flow has the same dual-carrier redirect scheme as the code flow:
// the challenge form re-carries rd as a hidden field, and a missing/expired
// pending cookie bounces to /login with the posted rd preserved.
func TestTOTPRedirectSurvivesLostPending(t *testing.T) {
	srv, sender := testServer(t)
	srv.cfg.TOTPEnabled = true
	secret := provisionTOTP(t, srv, "admin@example.com")
	c := newClient(t, srv.Handler())

	c.postForm("/request", url.Values{
		"email": {"admin@example.com"},
		"rd":    {"https://app.example.com/secret"},
	})
	rec := c.postForm("/verify-code", url.Values{"code": {sender.code()}})
	if !strings.Contains(rec.Body.String(), `name="rd" value="https://app.example.com/secret"`) {
		t.Errorf("TOTP form missing hidden rd field; body:\n%s", rec.Body.String())
	}

	// Pending cookie gone (expired / other browser context): the bounce must
	// keep the destination.
	delete(c.cookies, session.PendingCookie)
	totpCode, err := pqtotp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec = c.postForm("/totp", url.Values{
		"code": {totpCode},
		"rd":   {"https://app.example.com/secret"},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("/totp without pending = %d, want 302", rec.Code)
	}
	want := "/login?rd=" + url.QueryEscape("https://app.example.com/secret")
	if loc := rec.Header().Get("Location"); loc != want {
		t.Fatalf("lost-pending bounce = %q, want %q (rd dropped)", loc, want)
	}
}

// The TOTP step has the same double-submit hazard as the code step: the first
// /totp consumes the pending state and issues the session, so a re-tap finds no
// pending but a valid session. It must forward to the app, not bounce to /login.
// The TOTP code itself is single-use (replay guard), so the second submit can't
// re-validate — making the session-forward path the only way the re-tap lands
// safely rather than stranding an already-signed-in admin.
func TestTOTPDoubleSubmitForwardsToApp(t *testing.T) {
	srv, sender := testServer(t)
	srv.cfg.TOTPEnabled = true
	secret := provisionTOTP(t, srv, "admin@example.com")
	c := newClient(t, srv.Handler())

	c.postForm("/request", url.Values{
		"email": {"admin@example.com"},
		"rd":    {"https://app.example.com/secret"},
	})
	c.postForm("/verify-code", url.Values{
		"code": {sender.code()},
		"rd":   {"https://app.example.com/secret"},
	})

	totpCode, err := pqtotp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec := c.postForm("/totp", url.Values{
		"code": {totpCode},
		"rd":   {"https://app.example.com/secret"},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("first /totp = %d, want 302", rec.Code)
	}
	if c.cookies[session.SessionCookie] == nil {
		t.Fatal("first /totp issued no session cookie")
	}

	// Re-tap: pending gone, session present. Must land on the app.
	rec = c.postForm("/totp", url.Values{
		"code": {totpCode},
		"rd":   {"https://app.example.com/secret"},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("double-submit /totp = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://app.example.com/secret" {
		t.Fatalf("double-submit redirect = %q, want the app (not a /login bounce)", loc)
	}
}

// Enabling TOTP after an admin already holds a first-factor-only session must
// force that session to re-authenticate through the TOTP step, rather than
// letting a pre-TOTP cookie keep admin access until it expires. Covers both the
// /verify path (downstream group=admin apps) and the auth-host /admin UI.
func TestEnablingTOTPReChallengesExistingAdminSession(t *testing.T) {
	srv, sender := testServer(t) // TOTP disabled: admin logs in with the email code only
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)

	// Baseline: the first-factor-only admin session is honoured while TOTP is off.
	if rec := c.get("/verify", requireGroups("admin")); rec.Code != http.StatusOK {
		t.Fatalf("/verify before enabling TOTP = %d, want 200", rec.Code)
	}
	if rec := c.get("/admin/break", nil); rec.Code != http.StatusOK {
		t.Fatalf("/admin before enabling TOTP = %d, want 200", rec.Code)
	}

	// Operator turns TOTP on. The already-issued cookie carries totp=false.
	srv.cfg.TOTPEnabled = true

	// /verify for an admin-gated app now clears the session and bounces to login.
	if rec := c.get("/verify", requireGroups("admin")); rec.Code != http.StatusFound {
		t.Fatalf("/verify after enabling TOTP = %d, want 302 (re-challenge)", rec.Code)
	}
	// The auth-host admin UI likewise refuses the stale first-factor session.
	rec := c.get("/admin/break", nil)
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/login") {
		t.Fatalf("/admin after enabling TOTP = %d loc=%q, want 302 to /login",
			rec.Code, rec.Header().Get("Location"))
	}

	// Re-authenticating with the second factor restores admin access. Drop the
	// first login's captured message first, so code() waits for this login's
	// mail rather than reusing the earlier (already consumed) code.
	secret := provisionTOTP(t, srv, "admin@example.com")
	sender.reset()
	c.postForm("/request", url.Values{"email": {"admin@example.com"}})
	if rec := c.postForm("/verify-code", url.Values{"code": {sender.code()}}); rec.Code != http.StatusOK {
		t.Fatalf("/verify-code on re-auth = %d, want 200 (TOTP challenge)", rec.Code)
	}
	totpCode, err := pqtotp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rec := c.postForm("/totp", url.Values{"code": {totpCode}}); rec.Code != http.StatusFound {
		t.Fatalf("/totp re-auth = %d, want 302", rec.Code)
	}
	if rec := c.get("/verify", requireGroups("admin")); rec.Code != http.StatusOK {
		t.Fatalf("/verify after TOTP re-auth = %d, want 200", rec.Code)
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

// The per-account TOTP cap holds under concurrency: however many submissions
// arrive together, at most OTP_MAX_ATTEMPTS codes are checked within the
// window and the rest are refused as locked out. The attempt is reserved
// before the check, so there is no window in which every submission passes a
// not-yet-updated counter.
func TestTOTPAttemptCapHoldsUnderConcurrency(t *testing.T) {
	srv, sender := testServer(t)
	srv.cfg.TOTPEnabled = true
	provisionTOTP(t, srv, "admin@example.com")
	c := newClient(t, srv.Handler())
	c.postForm("/request", url.Values{"email": {"admin@example.com"}})
	c.postForm("/verify-code", url.Values{"code": {sender.code()}})
	pending := c.cookies[session.PendingCookie]
	if pending == nil {
		t.Fatal("no pending cookie after the email step")
	}

	const n = 60
	start := make(chan struct{})
	codes := make(chan int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			req := httptest.NewRequest(http.MethodPost, "/totp", strings.NewReader("code=000000"))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.RemoteAddr = "192.0.2.1:1234"
			req.AddCookie(pending)
			rr := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rr, req)
			codes <- rr.Code
		}()
	}
	close(start)
	wg.Wait()
	close(codes)
	checked, locked := 0, 0
	for code := range codes {
		switch code {
		case http.StatusUnauthorized:
			checked++
		case http.StatusTooManyRequests:
			locked++
		}
	}
	if checked > srv.cfg.OTPMaxAttempts {
		t.Fatalf("%d codes were checked, cap is %d", checked, srv.cfg.OTPMaxAttempts)
	}
	if checked+locked != n {
		t.Errorf("checked %d + locked %d != %d submissions", checked, locked, n)
	}
}

// reserveFails is a store whose attempt reservation always errors, standing in
// for a database that cannot be written to.
type reserveFails struct{ store.Store }

func (reserveFails) ReserveTOTPAttempt(context.Context, string, time.Duration, time.Time) (int, error) {
	return 0, errors.New("disk full")
}

// When an attempt cannot be recorded the code is not checked at all: the cap
// must not switch off during a store outage. The admin gets a temporary
// refusal and no session, even with the correct code.
func TestTOTPRefusesWhenAttemptCannotBeRecorded(t *testing.T) {
	srv, sender := testServer(t)
	srv.cfg.TOTPEnabled = true
	secret := provisionTOTP(t, srv, "admin@example.com")
	c := newClient(t, srv.Handler())
	c.postForm("/request", url.Values{"email": {"admin@example.com"}})
	c.postForm("/verify-code", url.Values{"code": {sender.code()}})

	srv.store = reserveFails{srv.store}
	totpCode, err := pqtotp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec := c.postForm("/totp", url.Values{"code": {totpCode}})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/totp with a failing store = %d, want 503", rec.Code)
	}
	if c.cookies[session.SessionCookie] != nil {
		t.Fatal("a session was issued although the attempt could not be recorded")
	}
	if !strings.Contains(rec.Body.String(), "try again in a moment") {
		t.Errorf("refusal page lacks the retry message:\n%s", rec.Body.String())
	}
}

// An admin demoted or removed between the email step and the second factor
// does not come out of the TOTP step with the permissions saved at the first
// step: the role is recomputed from the current policy when the session is
// issued.
func TestTOTPCompletionUsesCurrentPolicy(t *testing.T) {
	t.Run("demoted to user", func(t *testing.T) {
		srv, sender := testServer(t)
		srv.cfg.TOTPEnabled = true
		secret := provisionTOTP(t, srv, "admin@example.com")
		c := newClient(t, srv.Handler())
		c.postForm("/request", url.Values{"email": {"admin@example.com"}})
		if rec := c.postForm("/verify-code", url.Values{"code": {sender.code()}}); rec.Code != http.StatusOK {
			t.Fatalf("/verify-code = %d, want 200 (TOTP challenge)", rec.Code)
		}
		srv.policy = authz.NewPolicy([]string{"example.com"}, nil) // no admins any more
		totpCode, err := pqtotp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if rec := c.postForm("/totp", url.Values{"code": {totpCode}}); rec.Code != http.StatusFound {
			t.Fatalf("/totp = %d, want 302 (signed in as a user)", rec.Code)
		}
		if rec := c.get("/verify", requireGroups("admin")); rec.Code != http.StatusFound {
			t.Errorf("admin-only route after demotion = %d, want 302 (denied)", rec.Code)
		}
		if rec := c.get("/verify", protectedAny()); rec.Code != http.StatusOK || rec.Header().Get("Remote-Groups") != "user" {
			t.Errorf("plain route after demotion = %d groups=%q, want 200 user", rec.Code, rec.Header().Get("Remote-Groups"))
		}
	})
	t.Run("removed entirely", func(t *testing.T) {
		srv, sender := testServer(t)
		srv.cfg.TOTPEnabled = true
		secret := provisionTOTP(t, srv, "admin@example.com")
		c := newClient(t, srv.Handler())
		c.postForm("/request", url.Values{"email": {"admin@example.com"}})
		c.postForm("/verify-code", url.Values{"code": {sender.code()}})
		srv.policy = authz.NewPolicy([]string{"other.org"}, nil) // address no longer permitted
		totpCode, err := pqtotp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		rec := c.postForm("/totp", url.Values{"code": {totpCode}})
		if c.cookies[session.SessionCookie] != nil {
			t.Fatalf("a session was issued to a removed principal (status %d)", rec.Code)
		}
		if rec := c.get("/verify", protectedAny()); rec.Code != http.StatusFound {
			t.Errorf("removed principal reached /verify with %d", rec.Code)
		}
	})
}
