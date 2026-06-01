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

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/email"
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
	rec = c.get("/verify", nil)
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
	rec := c.get("/verify", nil)
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

func TestHealthz(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv.Handler())
	rec := c.get("/healthz", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("healthz status = %d", rec.Code)
	}
}
