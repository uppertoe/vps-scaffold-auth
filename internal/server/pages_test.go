// Tests of the welcome and sign-out pages, redirects, the sign-in page's CSP, same-origin checks and the session cookie at /verify.

package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
)

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

func TestApexRedirectFollowedWhenAllowed(t *testing.T) {
	srv, sender := testServer(t)
	srv.cfg.AllowApexRedirect = true
	c := newClient(t, srv.Handler())
	// Deployments whose apex is a real gated site (ALLOW_APEX_REDIRECT=true)
	// get sent back to it after login, like any subdomain destination.
	c.postForm("/request", url.Values{"email": {"user@example.com"}, "rd": {"https://example.com/useful-numbers/"}})
	rec := c.postForm("/verify-code", url.Values{"code": {sender.code()}})
	if loc := rec.Header().Get("Location"); loc != "https://example.com/useful-numbers/" {
		t.Fatalf("apex redirect should be followed when allowed; got %q", loc)
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
	if rec := c.get("/verify", anyGuard(t, srv)); rec.Code != http.StatusOK {
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

// An app's sign-out link may carry rd; it survives the confirmation form and
// reaches the login page, so the person returns to the app they left. Anything
// off-domain or not https is dropped, as on the login page.
func TestLogoutCarriesRedirectToLogin(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	c.postForm("/request", url.Values{"email": {"user@example.com"}})
	c.postForm("/verify-code", url.Values{"code": {sender.code()}})

	rec := c.get("/logout?rd=https%3A%2F%2Fapp.example.com%2F", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `name="rd" value="https://app.example.com/"`) {
		t.Fatalf("GET /logout?rd should carry rd into the form: %d %q", rec.Code, rec.Body.String())
	}
	rec = c.postForm("/logout", url.Values{"rd": {"https://app.example.com/"}})
	if loc := rec.Header().Get("Location"); rec.Code != http.StatusFound || loc != "https://auth.example.com/login?rd=https%3A%2F%2Fapp.example.com%2F" {
		t.Errorf("POST /logout with rd should land on login with the same rd; got %d %q", rec.Code, loc)
	}

	c.postForm("/request", url.Values{"email": {"user@example.com"}})
	c.postForm("/verify-code", url.Values{"code": {sender.code()}})
	rec = c.get("/logout?rd=https%3A%2F%2Fevil.example.org%2F", nil)
	if strings.Contains(rec.Body.String(), `name="rd"`) {
		t.Errorf("an off-domain rd must be dropped from the confirmation form")
	}
	rec = c.postForm("/logout", url.Values{"rd": {"http://app.example.com/"}})
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "rd=") {
		t.Errorf("a non-https rd must be dropped: %q", loc)
	}
	// Signed out, GET /logout?rd goes to the login page with rd intact.
	rec = c.get("/logout?rd=https%3A%2F%2Fapp.example.com%2F", nil)
	if loc := rec.Header().Get("Location"); rec.Code != http.StatusFound || !strings.Contains(loc, "/login?rd=https%3A%2F%2Fapp.example.com%2F") {
		t.Errorf("signed-out GET /logout?rd should keep rd on the way to login: %d %q", rec.Code, loc)
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

// With ALLOW_APEX_REDIRECT the bare domain is also a post-login destination,
// and https://*.example.com does not match https://example.com. Safari enforces
// form-action on the post-submission redirect, so the apex must be listed
// explicitly or an apex sign-in silently goes nowhere there.
func TestLoginCSPAllowsApexRedirectWhenEnabled(t *testing.T) {
	for _, allow := range []bool{false, true} {
		csp := cspPolicy("example.com", allow)
		hasApex := strings.Contains(csp, "form-action 'self' https://example.com https://*.example.com")
		if allow && !hasApex {
			t.Fatalf("apex allowed but CSP form-action omits it; got %q", csp)
		}
		if !allow && strings.Contains(csp, " https://example.com") {
			t.Fatalf("apex not allowed but CSP form-action lists it; got %q", csp)
		}
	}
}

// formActionAllows reports whether the CSP's form-action source list permits a
// navigation to target from a document on self, using the host-source forms the
// policy actually emits ('self', https://host, https://*.host). Browsers apply
// form-action to the redirect that follows a form submission (Safari still
// does), so this is the check that decides whether a sign-in lands.
func formActionAllows(t *testing.T, csp, self, target string) bool {
	t.Helper()
	var sources []string
	for _, d := range strings.Split(csp, ";") {
		f := strings.Fields(d)
		if len(f) > 0 && f[0] == "form-action" {
			sources = f[1:]
		}
	}
	if sources == nil {
		t.Fatalf("CSP has no form-action directive: %q", csp)
	}
	tu, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	su, _ := url.Parse(self)
	for _, src := range sources {
		switch {
		case src == "'self'":
			if tu.Scheme == su.Scheme && tu.Host == su.Host {
				return true
			}
		case strings.HasPrefix(src, "https://*."):
			if tu.Scheme == "https" && strings.HasSuffix(tu.Hostname(), strings.TrimPrefix(src, "https://*")) {
				return true
			}
		case strings.HasPrefix(src, "https://"):
			if tu.Scheme == "https" && tu.Hostname() == strings.TrimPrefix(src, "https://") {
				return true
			}
		}
	}
	return false
}

// Wherever a completed sign-in redirects, the login page's own CSP must let the
// browser follow it. This drives the real flow (request → code → verify) and
// checks the resulting Location against the policy, for both apex settings —
// the header-only tests above cannot catch the policy and servedTarget
// disagreeing, which is exactly how apex sign-ins broke on Safari.
func TestPostLoginRedirectIsAllowedByCSP(t *testing.T) {
	for _, allowApex := range []bool{false, true} {
		for _, rd := range []string{
			"https://app.example.com/secret",
			"https://example.com/gated/",
			"https://example.com/",
		} {
			srv, sender := testServerWith(t, func(cfg *config.Config) { cfg.AllowApexRedirect = allowApex })
			c := newClient(t, srv.Handler())
			rec := c.postForm("/request", url.Values{"email": {"user@example.com"}, "rd": {rd}})
			csp := rec.Header().Get("Content-Security-Policy")
			rec = c.postForm("/verify-code", url.Values{"code": {sender.code()}, "rd": {rd}})
			if rec.Code != http.StatusFound {
				t.Fatalf("apex=%v rd=%s: /verify-code = %d, want 302", allowApex, rd, rec.Code)
			}
			loc := rec.Header().Get("Location")
			if !formActionAllows(t, csp, "https://auth.example.com", loc) {
				t.Errorf("apex=%v rd=%s: sign-in redirects to %s but form-action forbids it: %q", allowApex, rd, loc, csp)
			}
			if allowApex && !strings.HasPrefix(loc, rd) {
				t.Errorf("apex=%v rd=%s: expected redirect to the destination, got %s", allowApex, rd, loc)
			}
		}
	}
}

// The sign-in forms accept a browser submission only from the auth host's own
// origin. A form posted from another origin, including a sibling host on the
// same site, is refused, so no app on the domain can drive a visitor's
// browser through the sign-in flow on their behalf. A client that sends
// neither header is not a browser and is unaffected.
func TestLoginFormsRequireSameOrigin(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv.Handler())
	post := func(path string, hdr map[string]string) int {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("email=user@example.com&code=000000"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		return c.do(req).Code
	}
	for _, path := range []string{"/request", "/verify-code", "/totp", "/logout"} {
		if code := post(path, map[string]string{"Origin": "https://app.example.com"}); code != http.StatusForbidden {
			t.Errorf("%s from a sibling origin = %d, want 403", path, code)
		}
		if code := post(path, map[string]string{"Origin": "https://evil.example.org"}); code != http.StatusForbidden {
			t.Errorf("%s from a foreign origin = %d, want 403", path, code)
		}
		if code := post(path, map[string]string{"Sec-Fetch-Site": "same-site"}); code != http.StatusForbidden {
			t.Errorf("%s with Sec-Fetch-Site same-site = %d, want 403", path, code)
		}
		if code := post(path, map[string]string{"Origin": "https://auth.example.com", "Sec-Fetch-Site": "same-origin"}); code == http.StatusForbidden {
			t.Errorf("%s from the auth origin was refused", path)
		}
		// Mobile browsers under a no-referrer policy send the literal "null" for
		// a same-origin navigation POST; the Sec-Fetch-Site value decides.
		if code := post(path, map[string]string{"Origin": "null", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate"}); code == http.StatusForbidden {
			t.Errorf("%s with Origin null and Sec-Fetch-Site same-origin was refused (breaks mobile sign-in)", path)
		}
		if code := post(path, map[string]string{"Origin": "null", "Sec-Fetch-Site": "none"}); code == http.StatusForbidden {
			t.Errorf("%s with Origin null and Sec-Fetch-Site none was refused", path)
		}
		if code := post(path, map[string]string{"Origin": "null", "Sec-Fetch-Site": "same-site"}); code != http.StatusForbidden {
			t.Errorf("%s with Origin null from a sibling host = %d, want 403", path, code)
		}
		if code := post(path, map[string]string{"Origin": "null", "Sec-Fetch-Site": "cross-site"}); code != http.StatusForbidden {
			t.Errorf("%s with Origin null from a foreign site = %d, want 403", path, code)
		}
		if code := post(path, nil); code == http.StatusForbidden {
			t.Errorf("%s without browser headers was refused", path)
		}
	}
}

// An explicit default port in AUTH_PUBLIC_URL does not make a browser's
// portless Origin look foreign.
func TestSameOriginToleratesExplicitDefaultPort(t *testing.T) {
	srv, _ := testServer(t)
	srv.cfg.PublicURL = "https://auth.example.com:443"
	c := newClient(t, srv.Handler())
	req := httptest.NewRequest(http.MethodPost, "/request", strings.NewReader("email=user@example.com"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://auth.example.com")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if code := c.do(req).Code; code == http.StatusForbidden {
		t.Fatal("a same-origin post was refused because the public URL carries :443")
	}
	srv.cfg.PublicURL = "https://auth.example.com"
	req = httptest.NewRequest(http.MethodPost, "/request", strings.NewReader("email=user@example.com"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://auth.example.com:8443")
	if code := c.do(req).Code; code != http.StatusForbidden {
		t.Fatalf("a post from a different port was accepted (%d)", code)
	}
}

// publicOrigin matches what a browser sends as Origin for the public URL.
func TestPublicOriginForms(t *testing.T) {
	srv, _ := testServer(t)
	for in, want := range map[string]string{
		"https://auth.example.com":      "https://auth.example.com",
		"https://auth.example.com:443":  "https://auth.example.com",
		"https://auth.example.com:8443": "https://auth.example.com:8443",
		"http://auth.example.com:80":    "http://auth.example.com",
		"https://[::1]:443":             "https://[::1]",
		"https://[::1]:8443":            "https://[::1]:8443",
	} {
		srv.cfg.PublicURL = in
		if got := srv.publicOrigin(); got != want {
			t.Errorf("publicOrigin(%q) = %q, want %q", in, got, want)
		}
	}
}

// An unreadable session cookie is cleared on the redirect to login, so an app
// route that keys on the cookie's presence stops bouncing the visitor.
func TestVerifyClearsUnreadableSessionCookie(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv.Handler())
	c.cookies[session.SessionCookie] = &http.Cookie{Name: session.SessionCookie, Value: "stale.garbage"}
	rec := c.get("/verify", anyGuard(t, srv))
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/login") {
		t.Fatalf("/verify with a stale cookie = %d %q, want 302 to login", rec.Code, rec.Header().Get("Location"))
	}
	cleared := false
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == session.SessionCookie && ck.MaxAge < 0 && ck.Value == "" {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("stale session cookie was not cleared; Set-Cookie=%v", rec.Header()["Set-Cookie"])
	}
	// No cookie at all: nothing to clear, no Set-Cookie emitted.
	c2 := newClient(t, srv.Handler())
	if sc := c2.get("/verify", anyGuard(t, srv)).Header()["Set-Cookie"]; len(sc) != 0 {
		t.Errorf("Set-Cookie emitted with no cookie present: %v", sc)
	}
}

// Two cookies by the session's name are refused but NOT cleared: the clear
// would carry the shared Domain and delete the real cookie while leaving the
// planted one.
func TestVerifyDoesNotClearAmbiguousSessionCookies(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)
	real := c.cookies[session.SessionCookie]
	req := httptest.NewRequest(http.MethodGet, "/verify", nil)
	for k, v := range anyGuard(t, srv) {
		req.Header.Set(k, v)
	}
	req.AddCookie(&http.Cookie{Name: session.SessionCookie, Value: "planted.garbage"})
	req.AddCookie(real)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("ambiguous cookies = %d, want 302 (refused)", rec.Code)
	}
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == session.SessionCookie {
			t.Fatalf("ambiguous cookie set triggered a clear: %v", ck)
		}
	}
}
