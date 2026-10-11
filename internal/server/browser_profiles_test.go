package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/session"
)

// browserProfile is the set of request headers a real browser sends with a
// sign-in form submission. These are recorded shapes, not guesses: the
// 2026-10-11 outage came from a check that was right for every shape the
// author imagined and wrong for the one phones actually send (Origin: null
// under the page's no-referrer policy). Every profile here must complete the
// whole flow: request a code, enter it, reach a protected app, sign out.
type browserProfile struct {
	name    string
	headers map[string]string
}

var signInProfiles = []browserProfile{
	{"iOS Safari 17, navigation POST under no-referrer", map[string]string{
		"Origin": "null", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document",
		"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
	}},
	{"Android Chrome 128, navigation POST under no-referrer", map[string]string{
		"Origin": "null", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Sec-Fetch-User": "?1",
		"User-Agent": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36",
	}},
	{"Android Firefox 129, navigation POST under no-referrer", map[string]string{
		"Origin": "null", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document",
		"User-Agent": "Mozilla/5.0 (Android 14; Mobile; rv:129.0) Gecko/129.0 Firefox/129.0",
	}},
	{"desktop Chrome, same-origin POST with Origin and Referer", map[string]string{
		"Origin": "https://auth.example.com", "Referer": "https://auth.example.com/login", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document",
	}},
	{"desktop Firefox, same-origin POST", map[string]string{
		"Origin": "https://auth.example.com", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document",
	}},
	{"Safari 16.3 (no Sec-Fetch-* support), Origin null under no-referrer", map[string]string{
		"Origin": "null",
	}},
	{"Safari 16.3, Origin present, no Sec-Fetch-*", map[string]string{
		"Origin": "https://auth.example.com",
	}},
	{"typed-URL navigation (Sec-Fetch-Site none)", map[string]string{
		"Origin": "null", "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate",
	}},
	{"non-browser client, no origin headers at all", map[string]string{}},
}

// Request shapes that must be refused: a form posted from another host on the
// same site, or from a foreign site, whatever Origin says.
var refusedProfiles = []browserProfile{
	{"sibling host form, Origin set", map[string]string{"Origin": "https://app.example.com", "Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "navigate"}},
	{"sibling host form, Origin null", map[string]string{"Origin": "null", "Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "navigate"}},
	{"foreign site form, Origin set", map[string]string{"Origin": "https://evil.example.org", "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"}},
	{"foreign site form, Origin null (sandboxed iframe)", map[string]string{"Origin": "null", "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"}},
	{"foreign site fetch", map[string]string{"Origin": "https://evil.example.org", "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors"}},
}

func (c *client) postWith(path string, form url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return c.do(req)
}

func TestSignInCompletesForEveryBrowserProfile(t *testing.T) {
	for _, p := range signInProfiles {
		t.Run(p.name, func(t *testing.T) {
			srv, sender := testServer(t)
			c := newClient(t, srv.Handler())
			sender.reset()
			if rec := c.postWith("/request", url.Values{"email": {"user@example.com"}}, p.headers); rec.Code != http.StatusOK {
				t.Fatalf("/request = %d, want 200 (code page)", rec.Code)
			}
			code := sender.code()
			if code == "" {
				t.Fatal("no code was sent")
			}
			rec := c.postWith("/verify-code", url.Values{"code": {code}}, p.headers)
			if rec.Code != http.StatusFound || c.cookies[session.SessionCookie] == nil {
				t.Fatalf("/verify-code = %d, session=%v; want 302 with a session", rec.Code, c.cookies[session.SessionCookie] != nil)
			}
			if rec := c.get("/verify", protectedAny()); rec.Code != http.StatusOK {
				t.Fatalf("/verify after sign-in = %d, want 200", rec.Code)
			}
			if rec := c.postWith("/logout", nil, p.headers); rec.Code != http.StatusFound {
				t.Fatalf("/logout = %d, want 302", rec.Code)
			}
			if c.cookies[session.SessionCookie] != nil && c.cookies[session.SessionCookie].Value != "" {
				t.Fatal("session survived sign-out")
			}
		})
	}
}

func TestSignInRefusedForForeignShapes(t *testing.T) {
	for _, p := range refusedProfiles {
		t.Run(p.name, func(t *testing.T) {
			srv, sender := testServer(t)
			c := newClient(t, srv.Handler())
			sender.reset()
			for _, path := range []string{"/request", "/verify-code", "/totp", "/logout"} {
				if rec := c.postWith(path, url.Values{"email": {"user@example.com"}, "code": {"000000"}}, p.headers); rec.Code != http.StatusForbidden {
					t.Errorf("%s = %d, want 403", path, rec.Code)
				}
			}
			if !noEmailSent(sender) {
				t.Error("a refused request still sent mail")
			}
		})
	}
}
