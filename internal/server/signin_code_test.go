// Tests of email-code sign-in: sending, resending, decoys and checking the code.

package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/breakglass"
	"github.com/uppertoe/vps-scaffold-auth/internal/ratelimit"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

func TestFullLoginCycle(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())

	// 1. request a code
	rec := c.postForm("/request", url.Values{
		"email": {"user@example.com"},
		"rd":    {"https://app.example.com/secret"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("/request status = %d", rec.Code)
	}
	code := sender.code()
	if code == "" {
		t.Fatal("no code captured")
	}

	// 2. verify the code
	rec = c.postForm("/verify-code", url.Values{"code": {code}})
	if rec.Code != http.StatusFound {
		t.Fatalf("/verify-code status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://app.example.com/secret" {
		t.Fatalf("post-login redirect = %q", loc)
	}

	// 3. now /verify grants and emits identity headers
	rec = c.get("/verify", anyGuard(t, srv))
	if rec.Code != http.StatusOK {
		t.Fatalf("/verify status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Remote-Email"); got != "user@example.com" {
		t.Errorf("Remote-Email = %q", got)
	}
	if got := sessionOf(t, srv, c).Groups; got != "user" {
		t.Errorf("groups = %q, want user", got)
	}
}

func TestWrongCodeRejected(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv.Handler())
	c.postForm("/request", url.Values{"email": {"user@example.com"}})
	rec := c.postForm("/verify-code", url.Values{"code": {"000000"}})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	// Still unauthenticated.
	rec = c.get("/verify", nil)
	if rec.Code == http.StatusOK {
		t.Error("/verify should not grant after a wrong code")
	}
}

// TestResendWithinCooldownIsNoOp is the regression for the resend-abuse path: a
// re-request while a live code is still fresh must not mint a new code, must not
// email, and — critically — must leave the existing code (and its attempt
// counter) intact, so a back-button / refresh / new-tab re-request can't reset
// the brute-force cap or spam the inbox. The original code must still verify.
func TestResendWithinCooldownIsNoOp(t *testing.T) {
	srv, sender := testServer(t)
	srv.cfg.OTPResendCooldown = time.Minute
	base := time.Unix(1_700_000_000, 0)
	clock := base
	srv.now = func() time.Time { return clock }
	c := newClient(t, srv.Handler())

	c.postForm("/request", url.Values{"email": {"user@example.com"}})
	first := sender.code()
	if first == "" {
		t.Fatal("no first code captured")
	}
	sender.reset()

	// Re-request 30s later, well within the 60s cooldown.
	clock = base.Add(30 * time.Second)
	rec := c.postForm("/request", url.Values{"email": {"user@example.com"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("re-request status = %d, want 200", rec.Code)
	}
	if got := sender.code(); got != "" {
		t.Fatalf("a second email was sent within the cooldown (code %q)", got)
	}

	// The original code is untouched and still verifies.
	rec = c.postForm("/verify-code", url.Values{"code": {first}})
	if rec.Code != http.StatusFound {
		t.Fatalf("verify with original code status = %d, want 302 (still valid)", rec.Code)
	}
}

// TestResendWithinCooldownDoesNotResetAttempts is the security core: a
// within-cooldown resend must not reset the brute-force attempt counter (which is
// how the resend abuse would otherwise let an attacker retry a code indefinitely).
// It burns attempts to one below the cap, resends within the cooldown, then
// confirms the next wrong code locks out rather than starting a fresh budget.
func TestResendWithinCooldownDoesNotResetAttempts(t *testing.T) {
	srv, _ := testServer(t)
	srv.cfg.OTPResendCooldown = time.Minute // OTPMaxAttempts stays at the default 5
	base := time.Unix(1_700_000_000, 0)
	clock := base
	srv.now = func() time.Time { return clock }
	c := newClient(t, srv.Handler())

	c.postForm("/request", url.Values{"email": {"user@example.com"}})

	// Four wrong codes: attempts = 4, still one below the cap of 5.
	for i := 0; i < 4; i++ {
		rec := c.postForm("/verify-code", url.Values{"code": {"000000"}})
		if !strings.Contains(rec.Body.String(), "Incorrect code") {
			t.Fatalf("attempt %d: body = %q, want \"Incorrect code\"", i+1, rec.Body.String())
		}
	}

	// Resend within the cooldown. If this reset the counter, the next wrong code
	// would merely be "Incorrect code" again instead of tripping the cap.
	clock = base.Add(10 * time.Second)
	c.postForm("/request", url.Values{"email": {"user@example.com"}})

	rec := c.postForm("/verify-code", url.Values{"code": {"000000"}}) // 5th wrong overall
	if !strings.Contains(rec.Body.String(), "entered incorrectly too many times") {
		t.Fatalf("expected lockout after the cap; the resend reset the counter. body = %q", rec.Body.String())
	}
}

// TestResendAfterCooldownMintsFresh confirms that once the cooldown lapses a
// re-request behaves as normal: a fresh code is minted and emailed, and the
// stale code is overwritten (SaveCode resets the row), so it no longer verifies.
func TestResendAfterCooldownMintsFresh(t *testing.T) {
	srv, sender := testServer(t)
	srv.cfg.OTPResendCooldown = time.Minute
	base := time.Unix(1_700_000_000, 0)
	clock := base
	srv.now = func() time.Time { return clock }
	c := newClient(t, srv.Handler())

	c.postForm("/request", url.Values{"email": {"user@example.com"}})
	first := sender.code()
	if first == "" {
		t.Fatal("no first code captured")
	}
	sender.reset()

	// Re-request after the cooldown has fully lapsed.
	clock = base.Add(2 * time.Minute)
	c.postForm("/request", url.Values{"email": {"user@example.com"}})
	second := sender.code()
	if second == "" {
		t.Fatal("no fresh code emailed after the cooldown lapsed")
	}

	// The stale code is gone (row overwritten); the fresh code verifies.
	rec := c.postForm("/verify-code", url.Values{"code": {first}})
	if rec.Code == http.StatusFound {
		t.Fatal("stale code still verified after a fresh code was minted")
	}
	rec = c.postForm("/verify-code", url.Values{"code": {second}})
	if rec.Code != http.StatusFound {
		t.Fatalf("verify with fresh code status = %d, want 302", rec.Code)
	}
}

// TestResendOverSendLimitDoesNotClobber covers the over-limit branch: when a
// permitted address is past its per-email send limit and its live code is stale
// (so the no-op guard doesn't fire), the request must fall back to the decoy
// path (insert-if-absent) rather than overwriting a code it can no longer
// re-deliver. The still-live code must keep working.
func TestResendOverSendLimitDoesNotClobber(t *testing.T) {
	srv, sender := testServer(t)
	srv.cfg.OTPResendCooldown = time.Minute
	srv.emailLimiter = ratelimit.New(1, time.Minute) // one send, then over-limit
	base := time.Unix(1_700_000_000, 0)
	clock := base
	srv.now = func() time.Time { return clock }
	c := newClient(t, srv.Handler())

	c.postForm("/request", url.Values{"email": {"user@example.com"}}) // spends the one token
	first := sender.code()
	if first == "" {
		t.Fatal("no first code captured")
	}
	sender.reset()

	// Past the cooldown (so not a no-op) but over the send limit: must not clobber.
	clock = base.Add(2 * time.Minute)
	c.postForm("/request", url.Values{"email": {"user@example.com"}})
	if got := sender.code(); got != "" {
		t.Fatalf("a code was emailed while over the send limit (code %q)", got)
	}

	// The original (still within its 10m TTL) code was not overwritten.
	rec := c.postForm("/verify-code", url.Values{"code": {first}})
	if rec.Code != http.StatusFound {
		t.Fatalf("verify with original code status = %d, want 302 (not clobbered)", rec.Code)
	}
}

func TestDisallowedEmailNoCodeButSameResponse(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	sender.reset()
	rec := c.postForm("/request", url.Values{"email": {"outsider@evil.com"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (no enumeration)", rec.Code)
	}
	if sender.code() != "" {
		t.Error("a code was sent to a disallowed address")
	}
}

// TestVerifyCodeDoesNotEnumerate confirms that submitting a wrong code yields an
// identical outcome for a permitted address and a non-permitted one. Without the
// decoy code stored in handleRequest, a non-permitted address has no stored code
// and lands on the login page with "expired", while a permitted address gets the
// code page with "Incorrect code" — a difference that would reveal allow-list
// (e.g. admin) membership.
func TestVerifyCodeDoesNotEnumerate(t *testing.T) {
	srv, _ := testServer(t)

	attempt := func(emailAddr string) (int, string) {
		c := newClient(t, srv.Handler())
		c.postForm("/request", url.Values{"email": {emailAddr}})
		rec := c.postForm("/verify-code", url.Values{"code": {"000000"}})
		return rec.Code, rec.Body.String()
	}

	permStatus, permBody := attempt("user@example.com")  // permitted (allowed domain)
	offStatus, offBody := attempt("nobody@outsider.com") // not permitted at all

	if permStatus != offStatus {
		t.Errorf("status differs: permitted=%d non-permitted=%d", permStatus, offStatus)
	}
	for _, b := range []string{permBody, offBody} {
		if !strings.Contains(b, "Incorrect code") {
			t.Errorf("wrong-code response missing the neutral \"Incorrect code\" message: %q", b)
		}
		if strings.Contains(b, "expired") {
			t.Errorf("wrong-code response leaks a distinguishing \"expired\" message: %q", b)
		}
	}
}

// TestDecoyAddressHitsAttemptCap confirms a non-permitted address walks the same
// attempt-cap state machine as a permitted one (rather than reporting ConsumeNoCode
// forever), so the cap can't be used as a second enumeration signal.
func TestDecoyAddressHitsAttemptCap(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv.Handler())
	c.postForm("/request", url.Values{"email": {"nobody@outsider.com"}})

	var last *httptest.ResponseRecorder
	for i := 0; i < 5; i++ {
		last = c.postForm("/verify-code", url.Values{"code": {"000000"}})
	}
	if !strings.Contains(last.Body.String(), "entered incorrectly too many times") {
		t.Errorf("non-permitted address did not reach the attempt cap like a permitted one: %q", last.Body.String())
	}
}

func TestBuildCodeEmail(t *testing.T) {
	srv, _ := testServer(t)
	srv.cfg.BrandName = "Acme <Health>" // includes chars that must be HTML-escaped

	msg := srv.buildCodeEmail(context.Background(), "user@example.com", "123456")

	if msg.To != "user@example.com" || msg.Subject == "" {
		t.Fatalf("unexpected envelope: %+v", msg)
	}
	// HTML part: code present, brand name escaped, MSO comments preserved, accent applied.
	if !strings.Contains(msg.HTML, "123456") {
		t.Error("HTML missing the code")
	}
	if !strings.Contains(msg.HTML, "Acme &lt;Health&gt;") {
		t.Error("brand name was not HTML-escaped in the email body")
	}
	if strings.Contains(msg.HTML, "Acme <Health>") {
		t.Error("unescaped brand name leaked into the HTML body")
	}
	if !strings.Contains(msg.HTML, "[if mso]") {
		t.Error("MSO conditional comment was stripped — Outlook width would break (use text/template, not html/template)")
	}
	if !strings.Contains(msg.HTML, breakglass.DefaultPalette.Accent) {
		t.Error("accent colour not applied to the email")
	}
	if !strings.Contains(msg.HTML, "10 minutes") {
		t.Error("expiry line missing/incorrect in HTML (OTPTTL is 10m)")
	}
	// Text part: code + raw brand name (no escaping in plaintext).
	if !strings.Contains(msg.Text, "123456") || !strings.Contains(msg.Text, "Acme <Health>") {
		t.Errorf("text part wrong: %q", msg.Text)
	}
}

func TestEmailTextOnContrast(t *testing.T) {
	cases := map[string]string{
		"#003a5c": "#ffffff", // dark navy → white text
		"#fdb913": "#1e2328", // light yellow → dark text
		"bogus":   "#ffffff", // invalid → safe default
	}
	for bg, want := range cases {
		if got := emailTextOn(bg); got != want {
			t.Errorf("emailTextOn(%q) = %q, want %q", bg, got, want)
		}
	}
}

// The code form must re-carry the destination as a hidden field: the state
// cookie alone is fragile (it expires with OTP_TTL and a parallel /request
// overwrites it), and the form is the only other place rd can survive.
func TestCodeFormCarriesRedirect(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv.Handler())
	rec := c.postForm("/request", url.Values{
		"email": {"user@example.com"},
		"rd":    {"https://app.example.com/secret"},
	})
	if !strings.Contains(rec.Body.String(), `name="rd" value="https://app.example.com/secret"`) {
		t.Errorf("code form missing hidden rd field; body:\n%s", rec.Body.String())
	}
}

// A missing/expired state cookie (it only lives OTP_TTL) must not strand the
// destination: the bounce back to /login carries the posted rd, so the user
// restarts the flow but still lands on the app they were headed to.
func TestVerifyCodeLostStateCarriesRedirect(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	c.postForm("/request", url.Values{
		"email": {"user@example.com"},
		"rd":    {"https://app.example.com/secret"},
	})
	code := sender.code()
	// Simulate state-cookie expiry (or a different browser context).
	delete(c.cookies, session.StateCookie)

	rec := c.postForm("/verify-code", url.Values{
		"code": {code},
		"rd":   {"https://app.example.com/secret"},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("/verify-code without state = %d, want 302", rec.Code)
	}
	want := "/login?rd=" + url.QueryEscape("https://app.example.com/secret")
	if loc := rec.Header().Get("Location"); loc != want {
		t.Fatalf("lost-state bounce = %q, want %q (rd dropped)", loc, want)
	}
}

// A double-submit of the code form must not strand a user who has already
// logged in. The first POST consumes the OTP, sets the session, and 302s to the
// app; a re-tap (un-disabled button on a slow app load, or an iOS autofill race)
// fires a second POST whose state is gone but whose session is now valid. That
// second request must forward to the app, NOT bounce back to /login — otherwise
// an already-authenticated user lands on the login page (the "stuck on auth"
// reports). The page CSP forbids JS, so this can only be fixed server-side.
func TestVerifyCodeDoubleSubmitForwardsToApp(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	c.postForm("/request", url.Values{
		"email": {"user@example.com"},
		"rd":    {"https://app.example.com/secret"},
	})
	code := sender.code()

	// First submission succeeds: session set, redirect to the app. The client
	// threads the new session cookie and the cleared state cookie forward.
	rec := c.postForm("/verify-code", url.Values{
		"code": {code},
		"rd":   {"https://app.example.com/secret"},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("first /verify-code = %d, want 302", rec.Code)
	}
	if c.cookies[session.SessionCookie] == nil {
		t.Fatal("first /verify-code issued no session cookie")
	}

	// Second submission of the same form: OTP already consumed and state cleared,
	// but the session cookie now rides along. Must land on the app, not /login.
	rec = c.postForm("/verify-code", url.Values{
		"code": {code},
		"rd":   {"https://app.example.com/secret"},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("double-submit /verify-code = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://app.example.com/secret" {
		t.Fatalf("double-submit redirect = %q, want the app (not a /login bounce)", loc)
	}
}

// Two tabs share the single host-only state cookie, so the /request submitted
// last overwrites the first tab's destination. The final redirect must follow
// the form the user actually completes (the posted rd), not whichever tab last
// wrote the cookie.
func TestVerifyCodePostedRedirectBeatsClobberedState(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())

	// Tab A: arrives from the app, rd intact.
	c.postForm("/request", url.Values{
		"email": {"user@example.com"},
		"rd":    {"https://app.example.com/secret"},
	})
	_ = sender.code() // wait for the first email so reset() can't race it
	sender.reset()

	// Tab B: a bare login page — overwrites the state cookie with an empty rd
	// and invalidates tab A's code (SaveCode overwrites).
	c.postForm("/request", url.Values{"email": {"user@example.com"}})
	code := sender.code()

	// The user completes tab A's form: latest code + tab A's hidden rd.
	rec := c.postForm("/verify-code", url.Values{
		"code": {code},
		"rd":   {"https://app.example.com/secret"},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("/verify-code = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://app.example.com/secret" {
		t.Fatalf("post-login redirect = %q, want tab A's destination (cookie clobber won)", loc)
	}
}

// A tampered posted rd must not become an open redirect: it is validated and,
// when invalid, the state cookie's destination still governs.
func TestVerifyCodeRejectsForeignPostedRedirect(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	c.postForm("/request", url.Values{
		"email": {"user@example.com"},
		"rd":    {"https://app.example.com/secret"},
	})
	rec := c.postForm("/verify-code", url.Values{
		"code": {sender.code()},
		"rd":   {"https://evil.com/phish"},
	})
	if loc := rec.Header().Get("Location"); loc != "https://app.example.com/secret" {
		t.Fatalf("post-login redirect = %q, want the cookie rd (foreign posted rd must be ignored)", loc)
	}
}

// The login-progress cookie is set for anyone who requests a code. Presented
// under the session cookie's name it must not read as a session, let alone one
// that renewal would upgrade to the claimed address's real groups.
func TestStateCookieCannotBecomeSession(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv.Handler())
	c.postForm("/request", url.Values{"email": {"admin@example.com"}})
	state := c.cookies[session.StateCookie]
	if state == nil {
		t.Fatal("no state cookie after /request")
	}
	c.cookies[session.SessionCookie] = &http.Cookie{Name: session.SessionCookie, Value: state.Value}

	// Past the renewal threshold, where a decoded identity with iat=0 would be
	// re-derived from policy.
	srv.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if rec := c.get("/verify", anyGuard(t, srv)); rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/login") {
		t.Fatalf("/verify with a state token as session = %d %q, want 302 to login", rec.Code, rec.Header().Get("Location"))
	}
	srv.now = time.Now
	if rec := c.get("/admin/groups", nil); rec.Code != http.StatusFound {
		t.Errorf("/admin/groups with a state token as session = %d, want 302", rec.Code)
	}
	if rec := c.get("/welcome", nil); rec.Code != http.StatusFound {
		t.Errorf("/welcome with a state token as session = %d, want 302", rec.Code)
	}
}

// A re-request behaves identically for a permitted and an unlisted address:
// within the cooldown neither resets its attempt counter, and after the
// cooldown both do. Any difference would reveal allow-list membership.
func TestResendTransitionsMatchForDecoy(t *testing.T) {
	srv, _ := testServer(t)
	srv.cfg.OTPMaxAttempts = 2
	srv.cfg.OTPResendCooldown = 30 * time.Second
	base := time.Now()
	srv.now = func() time.Time { return base }
	// "Incorrect" and "locked out" both answer 401, so the page's state is what
	// is compared: the wrong-code page offers another try, the locked-out page
	// asks for a new code. The guess is a letter string, which no minted code
	// can equal.
	const wrongGuess = "nope"
	state := func(rec *httptest.ResponseRecorder) string {
		body := rec.Body.String()
		switch {
		case strings.Contains(body, "entered incorrectly too many times"):
			return "locked"
		case strings.Contains(body, "Incorrect code"):
			return "mismatch"
		}
		return fmt.Sprintf("other(%d)", rec.Code)
	}
	run := func(addr string) (withinCooldown, afterCooldown string) {
		c := newClient(t, srv.Handler())
		c.postForm("/request", url.Values{"email": {addr}})
		for i := 0; i < srv.cfg.OTPMaxAttempts; i++ {
			c.postForm("/verify-code", url.Values{"code": {wrongGuess}})
		}
		// Re-request inside the cooldown: the counter must survive.
		c.postForm("/request", url.Values{"email": {addr}})
		withinCooldown = state(c.postForm("/verify-code", url.Values{"code": {wrongGuess}}))
		// Re-request after the cooldown: a fresh code with a fresh counter.
		srv.now = func() time.Time { return base.Add(srv.cfg.OTPResendCooldown + time.Second) }
		c.postForm("/request", url.Values{"email": {addr}})
		afterCooldown = state(c.postForm("/verify-code", url.Values{"code": {wrongGuess}}))
		srv.now = func() time.Time { return base }
		return
	}
	pw, pa := run("user@example.com")
	dw, da := run("stranger@other.org")
	if pw != "locked" || pa != "mismatch" {
		t.Fatalf("permitted address: within cooldown = %s, after = %s; want locked then mismatch", pw, pa)
	}
	if dw != pw || da != pa {
		t.Fatalf("resend transitions differ: permitted within/after = %s/%s, decoy = %s/%s", pw, pa, dw, da)
	}
}

// recentCheckFails is a store whose cooldown read always errors.
type recentCheckFails struct{ store.Store }

func (recentCheckFails) HasRecentCode(context.Context, string, time.Time) (bool, error) {
	return false, errors.New("disk read error")
}

// A failed cooldown read is treated as "within the cooldown": the live code
// and its attempt counters survive, so a transient error cannot hand a
// guesser a fresh budget.
func TestRecentCodeReadErrorKeepsCounters(t *testing.T) {
	srv, _ := testServer(t)
	srv.cfg.OTPMaxAttempts = 2
	c := newClient(t, srv.Handler())
	c.postForm("/request", url.Values{"email": {"user@example.com"}})
	for i := 0; i < srv.cfg.OTPMaxAttempts; i++ {
		c.postForm("/verify-code", url.Values{"code": {"nope"}})
	}
	srv.store = recentCheckFails{srv.store}
	c.postForm("/request", url.Values{"email": {"user@example.com"}})
	rec := c.postForm("/verify-code", url.Values{"code": {"nope"}})
	if !strings.Contains(rec.Body.String(), "entered incorrectly too many times") {
		t.Fatalf("counters were reset by a re-request during a read error; got %d:\n%s", rec.Code, rec.Body.String())
	}
}
