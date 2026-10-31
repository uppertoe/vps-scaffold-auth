package server

import (
	"bytes"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/session"
)

// These tests take the list of routes from the source files themselves, so a
// route added later is covered without anyone remembering to add it here.

var rePostRoute = regexp.MustCompile(`"POST (/[^"]*)"`)

// postRoutes returns every POST pattern registered in file, with path
// parameters filled in with sample values.
func postRoutes(t *testing.T, file string) []string {
	t.Helper()
	src, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	fill := strings.NewReplacer("{name}", "reports", "{id}", "1", "{$}", "")
	var out []string
	for _, m := range rePostRoute.FindAllStringSubmatch(string(src), -1) {
		out = append(out, fill.Replace(m[1]))
	}
	if len(out) == 0 {
		t.Fatalf("no POST routes found in %s; has the registration style changed?", file)
	}
	return out
}

// TestEveryAdminPostRequiresCSRF signs in as an administrator and posts to
// every state-changing admin route without the form token. Each must refuse
// with the CSRF page before it acts. A route that checked something else
// first, or forgot the check, would answer differently and fail here.
func TestEveryAdminPostRequiresCSRF(t *testing.T) {
	srv, sender := testServer(t)
	mintCode(t, srv, "Lab 1", "reports") // so {id}=1 exists
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	c.postForm("/admin/groups", url.Values{}) // warm the session; result irrelevant

	routes := postRoutes(t, "admin.go")
	if len(routes) < 10 {
		t.Fatalf("found only %d admin POST routes; the census is not reading admin.go", len(routes))
	}
	fields := map[string]string{"name": "reports", "email": "x@example.com", "label": "x", "group": "reports"}
	for _, path := range routes {
		// Multipart, as the branding forms send it; the other handlers read
		// the same fields from either encoding.
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		for k, v := range fields {
			mw.WriteField(k, v)
		}
		mw.Close()
		req := httptest.NewRequest(http.MethodPost, path, &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		rec := c.do(req)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "Invalid or expired form token") {
			t.Errorf("POST %s without a CSRF token: status %d, want the 403 CSRF refusal", path, rec.Code)
		}
	}
}

// TestEveryPublicPostRefusesASiblingHost posts to every public POST route as
// a browser would from another host on the same site (the cookie domain's
// sibling apps), with and without an Origin header. Every route must refuse:
// the sign-in forms by the same-origin check, the break-glass activation by
// its CSRF token. None may set a session cookie.
func TestEveryPublicPostRefusesASiblingHost(t *testing.T) {
	srv, sender := testServer(t)
	var routes []string
	for _, p := range postRoutes(t, "server.go") {
		if !strings.HasPrefix(p, "/admin") {
			routes = append(routes, p)
		}
	}
	if len(routes) < 5 {
		t.Fatalf("found only %d public POST routes: %v", len(routes), routes)
	}
	shapes := []map[string]string{
		{"Origin": "https://app.example.com", "Sec-Fetch-Site": "same-site"},
		{"Sec-Fetch-Site": "same-site"},
		{"Origin": "https://evil.example.net", "Sec-Fetch-Site": "cross-site"},
	}
	for _, path := range routes {
		for _, hdr := range shapes {
			// A visitor who is already signed in, so a forced action has
			// something to act on.
			c := newClient(t, srv.Handler())
			loginAs(t, c, sender, "user@example.com", nil)
			before := c.cookies[session.SessionCookie].Value
			rec := c.postWith(path, url.Values{"email": {"victim@example.com"}, "code": {"000000"}}, hdr)
			if rec.Code != http.StatusForbidden {
				t.Errorf("POST %s with %v: status %d, want 403", path, hdr, rec.Code)
			}
			for _, ck := range rec.Result().Cookies() {
				if ck.Name == session.SessionCookie {
					t.Errorf("POST %s with %v changed the session cookie", path, hdr)
				}
			}
			if after := c.cookies[session.SessionCookie]; after == nil || after.Value != before {
				t.Errorf("POST %s with %v altered the visitor's session", path, hdr)
			}
		}
	}
}

// TestSecretsNeverReachTheLog runs a sign-in, a break-glass scan and the
// admin pages with the process log captured, then requires that no code,
// cookie value or card token appears in it. Addresses may appear; secrets
// may not.
func TestSecretsNeverReachTheLog(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	srv, sender := testServer(t)
	token := mintCode(t, srv, "Lab 1", "reports")
	var secrets []string

	c := newClient(t, srv.Handler())
	sender.reset()
	c.postForm("/request", url.Values{"email": {"admin@example.com"}})
	for _, ck := range c.cookies {
		secrets = append(secrets, ck.Value) // the state cookie
	}
	code := sender.code()
	c.postForm("/verify-code", url.Values{"code": {"000000"}}) // a wrong guess is logged as an event
	c.postForm("/verify-code", url.Values{"code": {code}})
	c.get("/admin/break", nil)
	c.get("/verify", map[string]string{"X-Auth-Policy": "any", "X-Forwarded-Host": "app.example.com"})
	for _, ck := range c.cookies {
		secrets = append(secrets, ck.Value) // session and CSRF
	}

	bg := newClient(t, srv.Handler())
	bg.get("/break/"+token, nil)
	bg.get("/break/not-a-real-token-but-shaped-like-one", nil)
	for _, ck := range bg.cookies {
		secrets = append(secrets, ck.Value)
	}

	secrets = append(secrets, code, token)
	logged := buf.String()
	for _, s := range secrets {
		if len(s) >= 6 && strings.Contains(logged, s) {
			t.Errorf("the log contains a secret value (%d chars, starts %q)", len(s), s[:4])
		}
	}
	if !strings.Contains(logged, "break-glass") && !strings.Contains(logged, "denied") {
		// A guard against capturing nothing: the unknown-token scan logs a line.
		t.Fatalf("captured log looks empty; the capture is not working:\n%s", logged)
	}
}
