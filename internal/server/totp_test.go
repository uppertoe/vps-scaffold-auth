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

// stepUp takes an administrator through the admin door with the given TOTP
// code, returning the POST's response.
func stepUp(t *testing.T, c *client, code, rd string) *httptest.ResponseRecorder {
	t.Helper()
	page := c.get("/totp?rd="+url.QueryEscape(rd), nil)
	if page.Code != http.StatusOK {
		t.Fatalf("GET /totp = %d, want 200 (the admin door); loc=%q", page.Code, page.Header().Get("Location"))
	}
	return c.postForm("/totp", url.Values{"code": {code}, "rd": {rd}, "csrf": {extractCSRF(t, page.Body.String())}})
}

// Signing in never asks an administrator for the authenticator code: the
// email code alone opens every site that admits staff, and the session is an
// ordinary user's until the admin door. Admin-only routes and the admin pages
// send the administrator to the door, which returns them where they were.
func TestAdminSignsInWithoutTOTP(t *testing.T) {
	srv, sender := testServer(t)
	srv.cfg.TOTPEnabled = true
	provisionTOTP(t, srv, "admin@example.com")
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", url.Values{"rd": {"https://app.example.com/ward"}})

	rec := c.get("/verify", protectedAny())
	if rec.Code != http.StatusOK || rec.Header().Get("Remote-Groups") != "user" {
		t.Fatalf("staff route = %d groups=%q, want 200 user", rec.Code, rec.Header().Get("Remote-Groups"))
	}
	rec = c.get("/verify", requireGroups("admin"))
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "https://auth.example.com/totp?rd=") {
		t.Fatalf("admin-only route = %d loc=%q, want the admin door", rec.Code, rec.Header().Get("Location"))
	}
	rec = c.get("/admin/break", nil)
	want := "https://auth.example.com/totp?rd=" + url.QueryEscape("https://auth.example.com/admin/break")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != want {
		t.Fatalf("/admin = %d loc=%q, want %q", rec.Code, rec.Header().Get("Location"), want)
	}
	// A route that admits staff by domain is not the admin door's business.
	if rec := c.get("/verify", requireDomains("example.com")); rec.Code != http.StatusOK {
		t.Fatalf("domain route = %d, want 200", rec.Code)
	}
	// Someone who is not an administrator is denied an admin-only route, not
	// sent to the door.
	u := newClient(t, srv.Handler())
	loginAs(t, u, sender, "user@example.com", nil)
	if rec := u.get("/verify", requireGroups("admin")); !strings.Contains(rec.Header().Get("Location"), "/denied") {
		t.Fatalf("staff on admin route: loc=%q, want /denied", rec.Header().Get("Location"))
	}
	if rec := u.get("/totp", nil); !strings.Contains(rec.Header().Get("Location"), "/denied") {
		t.Fatalf("staff at the admin door: %d loc=%q, want /denied", rec.Code, rec.Header().Get("Location"))
	}
}

// The admin door with a provisioned secret: a valid code gives the session the
// admin tier and returns to the page asked for.
func TestAdminDoorGivesAdminTier(t *testing.T) {
	srv, sender := testServer(t)
	srv.cfg.TOTPEnabled = true
	secret := provisionTOTP(t, srv, "admin@example.com")
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)

	page := c.get("/totp?rd="+url.QueryEscape("https://db.example.com/x"), nil)
	if !strings.Contains(page.Body.String(), "Open the admin pages") ||
		!strings.Contains(page.Body.String(), `name="rd" value="https://db.example.com/x"`) {
		t.Fatalf("admin door page:\n%s", page.Body.String())
	}
	rec := stepUp(t, c, totpNow(t, secret, time.Now()), "https://db.example.com/x")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://db.example.com/x" {
		t.Fatalf("/totp = %d loc=%q, want 302 to the page asked for", rec.Code, rec.Header().Get("Location"))
	}
	rec = c.get("/verify", requireGroups("admin"))
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Remote-Groups"), "admin") {
		t.Fatalf("admin route after the door = %d groups=%q", rec.Code, rec.Header().Get("Remote-Groups"))
	}
	if rec := c.get("/admin/break", nil); rec.Code != http.StatusOK {
		t.Fatalf("/admin after the door = %d, want 200", rec.Code)
	}
	// The door, visited again, goes straight on.
	if rec := c.get("/totp", nil); rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://auth.example.com/admin/" {
		t.Fatalf("door with the tier held = %d loc=%q", rec.Code, rec.Header().Get("Location"))
	}
	// A second tap of the same submission goes on too, although the code is spent.
	rec = c.postForm("/totp", url.Values{"code": {totpNow(t, secret, time.Now())}, "rd": {"https://db.example.com/x"}})
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://db.example.com/x" {
		t.Fatalf("second tap = %d loc=%q", rec.Code, rec.Header().Get("Location"))
	}
}

// The admin tier lasts adminStepMaxAge from the second step, however long the
// session lasts; then the admin group leaves the apps' headers at once and
// the admin pages ask again. The session itself carries on.
func TestAdminTierLapsesAfterTwelveHours(t *testing.T) {
	srv, sender := testServer(t)
	srv.cfg.TOTPEnabled = true
	srv.cfg.SessionRememberTTL = 30 * 24 * time.Hour
	secret := provisionTOTP(t, srv, "admin@example.com")
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", url.Values{"remember": {"1"}})
	if rec := stepUp(t, c, totpNow(t, secret, time.Now()), ""); rec.Code != http.StatusFound {
		t.Fatalf("/totp = %d", rec.Code)
	}
	srv.now = func() time.Time { return time.Now().Add(adminStepMaxAge - time.Minute) }
	if rec := c.get("/admin/break", nil); rec.Code != http.StatusOK {
		t.Fatalf("/admin just inside the limit = %d, want 200", rec.Code)
	}
	srv.now = func() time.Time { return time.Now().Add(adminStepMaxAge + time.Minute) }
	rec := c.get("/verify", protectedAny())
	if rec.Code != http.StatusOK || rec.Header().Get("Remote-Groups") != "user" {
		t.Fatalf("staff route after the limit = %d groups=%q, want 200 user", rec.Code, rec.Header().Get("Remote-Groups"))
	}
	if rec := c.get("/verify", requireGroups("admin")); !strings.Contains(rec.Header().Get("Location"), "/totp?rd=") {
		t.Fatalf("admin route after the limit: loc=%q, want the admin door", rec.Header().Get("Location"))
	}
	if rec := c.get("/admin/break", nil); !strings.Contains(rec.Header().Get("Location"), "/totp?rd=") {
		t.Fatalf("/admin after the limit: %d loc=%q, want the admin door", rec.Code, rec.Header().Get("Location"))
	}
}

// Removing an address from ADMIN_EMAILS takes the admin group out of the apps'
// headers at the next request, not at the next scheduled renewal.
func TestDemotedAdminLosesAdminGroupAtNextRequest(t *testing.T) {
	srv, sender := testServer(t)
	srv.cfg.TOTPEnabled = true
	secret := provisionTOTP(t, srv, "admin@example.com")
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	stepUp(t, c, totpNow(t, secret, time.Now()), "")
	if rec := c.get("/verify", requireGroups("admin")); rec.Code != http.StatusOK {
		t.Fatalf("admin route = %d", rec.Code)
	}
	srv.policy = authz.NewPolicy([]string{"example.com"}, nil)
	rec := c.get("/verify", protectedAny())
	if rec.Code != http.StatusOK || rec.Header().Get("Remote-Groups") != "user" {
		t.Fatalf("after demotion = %d groups=%q, want 200 user", rec.Code, rec.Header().Get("Remote-Groups"))
	}
	if rec := c.get("/verify", requireGroups("admin")); !strings.Contains(rec.Header().Get("Location"), "/denied") {
		t.Fatalf("admin route after demotion: loc=%q, want /denied", rec.Header().Get("Location"))
	}
}

// An administrator with no provisioned secret signs in as staff, and the admin
// door refuses them with the setup message: nothing is self-enrolled.
func TestTOTPNoSelfEnrolment(t *testing.T) {
	srv, sender := testServer(t)
	srv.cfg.TOTPEnabled = true
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	rec := c.get("/totp", nil)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "Two-factor setup required") {
		t.Fatalf("door without a secret = %d:\n%s", rec.Code, rec.Body.String())
	}
	if _, ok, _ := srv.store.GetTOTPSecret(context.Background(), "admin@example.com"); ok {
		t.Error("a TOTP secret was self-enrolled")
	}
	if rec := c.get("/admin/break", nil); rec.Code == http.StatusOK {
		t.Error("the admin pages opened without a second factor")
	}
}

// A TOTP code stays valid for its whole step; a second use of the same code is
// refused, even in another session.
func TestTOTPCodeCannotBeReplayed(t *testing.T) {
	srv, sender := testServer(t)
	srv.cfg.TOTPEnabled = true
	secret := provisionTOTP(t, srv, "admin@example.com")
	code := totpNow(t, secret, time.Now())
	try := func() int {
		c := newClient(t, srv.Handler())
		loginAs(t, c, sender, "admin@example.com", nil)
		return stepUp(t, c, code, "").Code
	}
	if got := try(); got != http.StatusFound {
		t.Fatalf("first use = %d, want 302", got)
	}
	if got := try(); got != http.StatusUnauthorized {
		t.Fatalf("replayed code = %d, want 401", got)
	}
}

// The door's form needs its CSRF token and the same-origin check, and a POST
// with no session goes to sign in with the door as the destination.
func TestAdminDoorNeedsTokenAndSession(t *testing.T) {
	srv, sender := testServer(t)
	srv.cfg.TOTPEnabled = true
	secret := provisionTOTP(t, srv, "admin@example.com")
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	c.get("/totp", nil) // sets the CSRF cookie
	rec := c.postForm("/totp", url.Values{"code": {totpNow(t, secret, time.Now())}, "csrf": {"forged"}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("forged token = %d, want 403", rec.Code)
	}
	if rec := c.get("/admin/break", nil); rec.Code == http.StatusOK {
		t.Fatal("a forged token gave the admin tier")
	}
	rec = c.postWith("/totp", url.Values{"code": {totpNow(t, secret, time.Now())}}, map[string]string{"Origin": "https://evil.example.org"})
	if rec.Code == http.StatusFound {
		t.Fatalf("cross-origin POST = %d, want refused", rec.Code)
	}
	anon := newClient(t, srv.Handler())
	rec = anon.postForm("/totp", url.Values{"code": {"123456"}, "rd": {"https://db.example.com/"}})
	want := "https://auth.example.com/login?rd=" + url.QueryEscape("https://auth.example.com/totp?rd="+url.QueryEscape("https://db.example.com/"))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != want {
		t.Fatalf("no session = %d loc=%q, want %q", rec.Code, rec.Header().Get("Location"), want)
	}
}

// Turning TOTP on takes the admin tier from every session that lacks the
// second step, at its next request, and the admin door restores it.
func TestEnablingTOTPReChallengesExistingAdminSession(t *testing.T) {
	srv, sender := testServer(t) // TOTP off: the email code alone gives the admin tier
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	if rec := c.get("/verify", requireGroups("admin")); rec.Code != http.StatusOK {
		t.Fatalf("/verify before enabling TOTP = %d, want 200", rec.Code)
	}
	if rec := c.get("/admin/break", nil); rec.Code != http.StatusOK {
		t.Fatalf("/admin before enabling TOTP = %d, want 200", rec.Code)
	}
	srv.cfg.TOTPEnabled = true
	secret := provisionTOTP(t, srv, "admin@example.com")
	if rec := c.get("/verify", protectedAny()); rec.Header().Get("Remote-Groups") != "user" {
		t.Fatalf("staff route after enabling TOTP: groups=%q, want user", rec.Header().Get("Remote-Groups"))
	}
	if rec := c.get("/verify", requireGroups("admin")); !strings.Contains(rec.Header().Get("Location"), "/totp?rd=") {
		t.Fatalf("admin route after enabling TOTP: loc=%q, want the admin door", rec.Header().Get("Location"))
	}
	if rec := c.get("/admin/break", nil); !strings.Contains(rec.Header().Get("Location"), "/totp?rd=") {
		t.Fatalf("/admin after enabling TOTP: loc=%q, want the admin door", rec.Header().Get("Location"))
	}
	if rec := stepUp(t, c, totpNow(t, secret, time.Now()), ""); rec.Code != http.StatusFound {
		t.Fatalf("/totp = %d", rec.Code)
	}
	if rec := c.get("/verify", requireGroups("admin")); rec.Code != http.StatusOK {
		t.Fatalf("/verify after the door = %d, want 200", rec.Code)
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
	loginAs(t, c, sender, "admin@example.com", nil)
	tok := extractCSRF(t, c.get("/totp", nil).Body.String())
	form := url.Values{"code": {"000000"}, "csrf": {tok}}.Encode()

	const n = 60
	start := make(chan struct{})
	codes := make(chan int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			req := httptest.NewRequest(http.MethodPost, "/totp", strings.NewReader(form))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.RemoteAddr = "192.0.2.1:1234"
			for _, ck := range c.cookies {
				req.AddCookie(ck)
			}
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
// refusal and no admin tier, even with the correct code.
func TestTOTPRefusesWhenAttemptCannotBeRecorded(t *testing.T) {
	srv, sender := testServer(t)
	srv.cfg.TOTPEnabled = true
	secret := provisionTOTP(t, srv, "admin@example.com")
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	tok := extractCSRF(t, c.get("/totp", nil).Body.String())

	srv.store = reserveFails{srv.store}
	rec := c.postForm("/totp", url.Values{"code": {totpNow(t, secret, time.Now())}, "csrf": {tok}})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/totp with a failing store = %d, want 503", rec.Code)
	}
	if got := c.get("/verify", protectedAny()).Header().Get("Remote-Groups"); got != "user" {
		t.Fatalf("groups = %q: the admin tier was given although the attempt could not be recorded", got)
	}
	if !strings.Contains(rec.Body.String(), "try again in a moment") {
		t.Errorf("refusal page lacks the retry message:\n%s", rec.Body.String())
	}
}
