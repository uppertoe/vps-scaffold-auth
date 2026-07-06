package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/breakglass"
	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/email"
	"github.com/uppertoe/vps-scaffold-auth/internal/ratelimit"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

var reDigits = regexp.MustCompile(`\d{6}`)

// captureSender records the last message so tests can read back the OTP code.
// Sends now happen on a detached goroutine (see sendCode), so code() blocks
// briefly for a message to arrive rather than assuming one is already present.
type captureSender struct {
	mu   sync.Mutex
	last *email.Message
	sent chan email.Message
}

func newCaptureSender() *captureSender {
	return &captureSender{sent: make(chan email.Message, 16)}
}

func (c *captureSender) Send(_ context.Context, msg email.Message) error {
	c.mu.Lock()
	m := msg
	c.last = &m
	c.mu.Unlock()
	select {
	case c.sent <- m:
	default:
	}
	return nil
}

func (c *captureSender) code() string {
	c.mu.Lock()
	last := c.last
	c.mu.Unlock()
	if last != nil {
		return reDigits.FindString(last.Text)
	}
	select {
	case m := <-c.sent:
		return reDigits.FindString(m.Text)
	case <-time.After(2 * time.Second):
		return ""
	}
}

func (c *captureSender) reset() {
	c.mu.Lock()
	c.last = nil
	c.mu.Unlock()
	for {
		select {
		case <-c.sent:
		default:
			return
		}
	}
}

// client threads cookies across requests like a browser would.
type client struct {
	t       *testing.T
	h       http.Handler
	cookies map[string]*http.Cookie
}

func newClient(t *testing.T, h http.Handler) *client {
	return &client{t: t, h: h, cookies: map[string]*http.Cookie{}}
}

func (c *client) do(req *http.Request) *httptest.ResponseRecorder {
	req.RemoteAddr = "10.0.0.1:1234"
	for _, ck := range c.cookies {
		req.AddCookie(ck)
	}
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	for _, ck := range rec.Result().Cookies() {
		if ck.MaxAge < 0 {
			delete(c.cookies, ck.Name)
		} else {
			c.cookies[ck.Name] = ck
		}
	}
	return rec
}

func (c *client) get(target string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return c.do(req)
}

func (c *client) postForm(target string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.do(req)
}

func testServer(t *testing.T) (*Server, *captureSender) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	cfg := &config.Config{
		PublicURL:         "https://auth.example.com",
		Domain:            "example.com",
		DefaultRedirect:   "https://app.example.com/",
		AllowedDomains:    []string{"example.com"},
		AdminEmails:       []string{"admin@example.com"},
		SessionSecret:     []byte("0123456789abcdef0123456789abcdef"),
		CookieDomain:      ".example.com",
		CookieInsecure:    true,
		SessionTTL:        time.Hour,
		SessionRenew:      30 * time.Minute,
		OTPTTL:            10 * time.Minute,
		OTPLength:         6,
		OTPMaxAttempts:    5,
		EmailBackend:      "log",
		EmailFrom:         "auth@example.com",
		RateLimitPerEmail: config.RateLimit{Count: 100, Window: time.Minute},
		RateLimitPerIP:    config.RateLimit{Count: 100, Window: time.Minute},
	}
	sender := newCaptureSender()
	srv, err := New(cfg, st, sender)
	if err != nil {
		t.Fatal(err)
	}
	return srv, sender
}

func TestVerifyRedirectsWhenUnauthenticated(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv.Handler())
	rec := c.get("/verify", map[string]string{
		"X-Forwarded-Proto": "https",
		"X-Forwarded-Host":  "app.example.com",
		"X-Forwarded-Uri":   "/secret",
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://auth.example.com/login?rd=") {
		t.Fatalf("Location = %q", loc)
	}
	if !strings.Contains(loc, url.QueryEscape("https://app.example.com/secret")) {
		t.Errorf("redirect target not preserved in %q", loc)
	}
}

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
	rec = c.get("/verify", protectedAny())
	if rec.Code != http.StatusOK {
		t.Fatalf("/verify status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Remote-Email"); got != "user@example.com" {
		t.Errorf("Remote-Email = %q", got)
	}
	if got := rec.Header().Get("Remote-Groups"); got != "user" {
		t.Errorf("Remote-Groups = %q, want user", got)
	}
}

func TestAdminGetsAdminGroup(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	c.postForm("/request", url.Values{"email": {"admin@example.com"}})
	c.postForm("/verify-code", url.Values{"code": {sender.code()}})
	rec := c.get("/verify", protectedAny())
	if got := rec.Header().Get("Remote-Groups"); got != "admin" {
		t.Errorf("Remote-Groups = %q, want admin", got)
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
	if !strings.Contains(rec.Body.String(), "Too many incorrect attempts") {
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
	if !strings.Contains(last.Body.String(), "Too many incorrect attempts") {
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

func TestDirectLoginLandsOnWelcome(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	// Direct login: no app rd carried. Must land on the auth-host signed-in page,
	// not bounce to DEFAULT_REDIRECT (which may be unservable, e.g. a certless apex).
	c.postForm("/request", url.Values{"email": {"user@example.com"}})
	rec := c.postForm("/verify-code", url.Values{"code": {sender.code()}})
	if rec.Code != http.StatusFound {
		t.Fatalf("/verify-code status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://auth.example.com/welcome" {
		t.Fatalf("direct-login redirect = %q, want the auth-host welcome page", loc)
	}
	// The welcome page renders for the now-authenticated session.
	rec = c.get("/welcome", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "signed in") {
		t.Errorf("welcome page: status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestApexRedirectFallsToWelcome(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	// A redirect to the bare apex (typically no TLS cert on a subdomain gateway)
	// must be treated as not-a-destination and fall back to the welcome page.
	c.postForm("/request", url.Values{"email": {"user@example.com"}, "rd": {"https://example.com"}})
	rec := c.postForm("/verify-code", url.Values{"code": {sender.code()}})
	if loc := rec.Header().Get("Location"); loc != "https://auth.example.com/welcome" {
		t.Fatalf("apex redirect should fall back to welcome; got %q", loc)
	}
}

func TestRootRedirectsBySession(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())

	// Unauthenticated: the auth-host root sends you to the login page.
	rec := c.get("/", nil)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/login" {
		t.Fatalf("unauthenticated / = %d %q; want 302 /login", rec.Code, rec.Header().Get("Location"))
	}

	// Signed in: the root lands on the signed-in welcome page instead of
	// re-showing the login form.
	c.postForm("/request", url.Values{"email": {"user@example.com"}})
	c.postForm("/verify-code", url.Values{"code": {sender.code()}})
	rec = c.get("/", nil)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/welcome" {
		t.Fatalf("signed-in / = %d %q; want 302 /welcome", rec.Code, rec.Header().Get("Location"))
	}
}

func TestWelcomeAdminLink(t *testing.T) {
	srv, sender := testServer(t)

	// A normal user sees no Admin link.
	c := newClient(t, srv.Handler())
	c.postForm("/request", url.Values{"email": {"user@example.com"}})
	c.postForm("/verify-code", url.Values{"code": {sender.code()}})
	if body := c.get("/welcome", nil).Body.String(); strings.Contains(body, `href="/admin/"`) {
		t.Errorf("non-admin /welcome should not offer an Admin link")
	}

	// An admin does (TOTP is off in the test config, so login completes directly).
	sender.reset()
	ca := newClient(t, srv.Handler())
	ca.postForm("/request", url.Values{"email": {"admin@example.com"}})
	ca.postForm("/verify-code", url.Values{"code": {sender.code()}})
	if body := ca.get("/welcome", nil).Body.String(); !strings.Contains(body, `href="/admin/"`) {
		t.Errorf("admin /welcome should offer an Admin link; body:\n%s", body)
	}
}

func TestWelcomeRequiresSession(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv.Handler())
	rec := c.get("/welcome", nil)
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/login") {
		t.Errorf("unauthenticated /welcome should redirect to login; got %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestLogoutGetConfirmsThenPostSignsOut(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	c.postForm("/request", url.Values{"email": {"user@example.com"}})
	c.postForm("/verify-code", url.Values{"code": {sender.code()}})

	// GET /logout renders a confirmation with a POST form — and does NOT log out.
	rec := c.get("/logout", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /logout = %d, want 200 confirm page", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `action="/logout"`) || !strings.Contains(rec.Body.String(), "Sign out") {
		t.Errorf("confirm page missing POST sign-out form: %q", rec.Body.String())
	}
	if rec := c.get("/verify", protectedAny()); rec.Code != http.StatusOK {
		t.Errorf("GET /logout must not end the session; /verify = %d", rec.Code)
	}

	// POST /logout actually clears the session.
	if rec := c.postForm("/logout", url.Values{}); rec.Code != http.StatusFound {
		t.Fatalf("POST /logout = %d, want 302", rec.Code)
	}
	if rec := c.get("/verify", nil); rec.Code == http.StatusOK {
		t.Error("POST /logout should have cleared the session")
	}
}

func TestLogoutGetWhenSignedOutRedirectsToLogin(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv.Handler())
	rec := c.get("/logout", nil)
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/login") {
		t.Errorf("GET /logout when signed out should redirect to login; got %d %q", rec.Code, rec.Header().Get("Location"))
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

// The login pages' CSP must permit form-submission redirects to the deployment's
// own app subdomains. With a bare form-action 'self', Chrome/Safari (and newer
// Firefox) silently refuse to follow the cross-subdomain 302 a successful login
// returns, stranding the user on the auth host. The permitted set mirrors the
// post-login destinations servedTarget allows (subdomains of cfg.Domain).
func TestLoginCSPAllowsAppSubdomainRedirects(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv.Handler())
	rec := c.get("/login", nil)
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action 'self' https://*.example.com") {
		t.Fatalf("CSP form-action does not allow app subdomains; got %q", csp)
	}
}

func TestHealthz(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv.Handler())
	rec := c.get("/healthz", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("healthz status = %d", rec.Code)
	}
}
