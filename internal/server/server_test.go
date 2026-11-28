package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/email"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

var reDigits = regexp.MustCompile(`\d{6}`)

// captureSender records the last message so tests can read back the OTP code.
// Sends now happen on a detached goroutine (see sendCode), so code() blocks
// briefly for a message to arrive rather than assuming one is already present.
type captureSender struct {
	mu      sync.Mutex
	last    *email.Message
	sent    chan email.Message
	notices []email.Message // messages with no code (the passkey notice)
}

func newCaptureSender() *captureSender {
	return &captureSender{sent: make(chan email.Message, 16)}
}

func (c *captureSender) Send(_ context.Context, msg email.Message) error {
	c.mu.Lock()
	if !reDigits.MatchString(msg.Text) {
		c.notices = append(c.notices, msg)
		c.mu.Unlock()
		return nil
	}
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

// scan does what a person does with a card: opens its address, then, if the
// page offers the button, presses it. It returns the last response.
func (c *client) scan(token string) *httptest.ResponseRecorder {
	rec := c.get("/break/"+token, nil)
	if rec.Code != http.StatusOK {
		return rec
	}
	return c.postForm("/break", url.Values{"token": {token}})
}

// withoutViews drops the "viewed" rows a scan's first step records, for tests
// about what the button then did.
func withoutViews(events []store.BreakGlassEvent, err error) ([]store.BreakGlassEvent, error) {
	var out []store.BreakGlassEvent
	for _, e := range events {
		if e.Outcome != store.OutcomeViewed {
			out = append(out, e)
		}
	}
	return out, err
}

func testServer(t *testing.T) (*Server, *captureSender) {
	t.Helper()
	return testServerWith(t, nil)
}

// testServerWith builds the standard test server, letting the caller adjust
// the config before construction (some settings, like the CSP, are precomputed).
// Staff are everyone at example.com: a domain group, staffHarnessGroup, holds
// the User role of an app of its own (staffHarnessApp, on
// harness.example.com), as a server's department domain group would. A test
// that decides who is staff itself uses testServerNoStaff.
func testServerWith(t *testing.T, adjust func(*config.Config)) (*Server, *captureSender) {
	t.Helper()
	srv, sender := testServerNoStaff(t, adjust)
	seedStaff(t, srv, "example.com")
	return srv, sender
}

// The harness's own staff domain group and the app it holds a role in.
const (
	staffHarnessGroup = "harness-staff"
	staffHarnessApp   = "harness"
)

// seedStaff makes the addresses at domains staff, through staffHarnessGroup
// and staffHarnessApp, which no test otherwise names.
func seedStaff(t *testing.T, srv *Server, domains ...string) {
	t.Helper()
	testGuardApp(t, srv, staffHarnessApp)
	mustDomainGroup(t, srv, staffHarnessGroup, domains...)
	mustAssign(t, srv, store.RoleAssignment{App: staffHarnessApp, Role: "user", Kind: store.AssignDomainGroup, Ref: staffHarnessGroup})
}

// unseedStaff takes staffHarnessGroup's role away, so nobody at its domains
// is staff any longer.
func unseedStaff(t *testing.T, srv *Server) {
	t.Helper()
	if err := srv.store.RemoveRoleAssignment(context.Background(), staffHarnessApp, "user", store.AssignDomainGroup, staffHarnessGroup); err != nil {
		t.Fatal(err)
	}
	srv.forgetRoles()
}

// testServerNoStaff is testServerWith without the harness's staff: only the
// administrators in ADMIN_EMAILS, and whoever the test gives a role, may
// sign in.
func testServerNoStaff(t *testing.T, adjust func(*config.Config)) (*Server, *captureSender) {
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
	if adjust != nil {
		adjust(cfg)
	}
	// The gateway refuses to start without a manifest that declares an app,
	// so a test that names none gets one declaring only staffHarnessApp.
	// Tests add apps of their own in memory (testGuardApp).
	if cfg.AppRolesFile == "" {
		cfg.AppRolesFile = filepath.Join(t.TempDir(), "app-roles.tsv")
		if err := os.WriteFile(cfg.AppRolesFile, []byte(staffHarnessApp+"\tuser\tUser\t"+staffHarnessApp+".{$DOMAIN}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sender := newCaptureSender()
	srv, err := New(cfg, st, sender)
	if err != nil {
		t.Fatal(err)
	}
	// The transitional rule (carriedOverAsGuest) is off unless a test turns
	// it on, so a session a test starts on a fake clock is never taken for
	// one from before the release.
	srv.guestsReleasedAt = time.Time{}
	return srv, sender
}

func TestAdminGetsAdminGroup(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	c.postForm("/request", url.Values{"email": {"admin@example.com"}})
	c.postForm("/verify-code", url.Values{"code": {sender.code()}})
	if got := groupsAfter(t, srv, c, anyGuard(t, srv)); got != "admin" {
		t.Errorf("groups = %q, want admin", got)
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

// An administrator removed from ADMIN_EMAILS loses the admin UI at once, not
// at cookie expiry: the admin gate re-checks the current policy.
func TestRemovedAdminLosesAdminUI(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	if rec := c.get("/admin/groups", nil); rec.Code != http.StatusOK {
		t.Fatalf("admin before removal = %d, want 200", rec.Code)
	}
	srv.policy = authz.NewPolicy(nil)
	if rec := c.get("/admin/groups", nil); rec.Code != http.StatusFound {
		t.Errorf("admin after removal = %d, want 302 to login", rec.Code)
	}
	if body := c.get("/welcome", nil).Body.String(); strings.Contains(body, `href="/admin`) {
		t.Error("/welcome still offers the Admin link after removal")
	}
}

// Someone signed in who is not an administrator is shown the no-access page,
// naming the address they used, rather than the email page: the email page
// looked as though the sign-in had failed. A visitor with no session is still
// sent to sign in.
func TestNonAdminSeesNoAccessOnAdminPages(t *testing.T) {
	srv, sender := testServer(t)
	user := newClient(t, srv.Handler())
	loginAs(t, user, sender, "user@example.com", nil)
	rec := user.get("/admin/groups", nil)
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.Contains(loc, "/denied?rd=") || !strings.Contains(loc, "%2Fadmin%2Fgroups") {
		t.Fatalf("non-admin on an admin page = %d to %q, want the no-access page", rec.Code, loc)
	}
	page := user.get(strings.TrimPrefix(loc, "https://auth.example.com"), nil)
	if !strings.Contains(page.Body.String(), "user@example.com") {
		t.Errorf("no-access page does not name the address signed in")
	}
	anon := newClient(t, srv.Handler())
	if rec := anon.get("/admin/groups", nil); !strings.Contains(rec.Header().Get("Location"), "/login?") {
		t.Errorf("visitor on an admin page = %q, want sign in", rec.Header().Get("Location"))
	}
}
