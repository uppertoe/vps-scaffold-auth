//go:build e2e

// Package e2e tests the whole security chain: a browser, the production
// Caddy with the guard snippets from deploy/auth.caddy, the gateway image
// built from this repository, and an app that echoes what it receives. Run it
// with scripts/e2e.sh, which starts the stack and sets the environment.
//
// The unit tests prove what the gateway decides. These tests prove what the
// chain delivers: what reaches the browser, and what reaches the app. Every
// finding that escaped the unit tests before October 2026 (renewals dropped by
// Caddy, a cookie read as the wrong kind) sits at that boundary.
package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

const (
	domain    = "e2e.test"
	authHost  = "https://auth." + domain
	cookieKey = "vps_auth_session"
)

var (
	addr        = envOr("E2E_ADDR", "127.0.0.1:18443")
	composeArgs = strings.Fields(envOr("E2E_COMPOSE", "docker compose -p vpsauth-e2e -f e2e/compose.yml"))
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// browser is a cookie-carrying client that never follows redirects, so each
// hop can be inspected, and that sends every connection to the test Caddy
// whatever the host name.
type browser struct {
	t   *testing.T
	c   *http.Client
	jar *cookiejar.Jar
}

func newBrowser(t *testing.T) *browser {
	t.Helper()
	pool := x509.NewCertPool()
	pem, err := os.ReadFile(envOr("E2E_CA", "e2e/.root.crt"))
	if err != nil {
		t.Fatalf("read Caddy's root certificate: %v", err)
	}
	pool.AppendCertsFromPEM(pem)
	jar, _ := cookiejar.New(nil)
	d := &net.Dialer{Timeout: 5 * time.Second}
	return &browser{t: t, jar: jar, c: &http.Client{
		Jar:     jar,
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return d.DialContext(ctx, network, addr)
			},
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

type reply struct {
	status int
	header http.Header
	body   string
}

func (r reply) location() string { return r.header.Get("Location") }

// setCookies returns the raw Set-Cookie lines, which the jar would hide.
func (r reply) setCookies(name string) []string {
	var out []string
	for _, l := range r.header.Values("Set-Cookie") {
		if strings.HasPrefix(l, name+"=") {
			out = append(out, l)
		}
	}
	return out
}

func (b *browser) do(method, target string, form url.Values, hdr map[string]string) reply {
	b.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		b.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := b.c.Do(req)
	if err != nil {
		b.t.Fatalf("%s %s: %v", method, target, err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	return reply{status: res.StatusCode, header: res.Header, body: string(data)}
}

func (b *browser) get(target string, hdr map[string]string) reply {
	return b.do(http.MethodGet, target, nil, hdr)
}

// submit posts a form from the gateway's own page, with the headers a
// same-origin navigation sends under the page's no-referrer policy (the
// "Origin: null" that mobile browsers send, which caused the 11 October 2026
// outage when it was refused).
func (b *browser) submit(path string, form url.Values) reply {
	return b.do(http.MethodPost, authHost+path, form, map[string]string{
		"Origin": "null", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate",
	})
}

func (b *browser) cookie(host, name string) string {
	u, _ := url.Parse("https://" + host + "/")
	for _, c := range b.jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func (b *browser) setCookie(host, name, value string) {
	u, _ := url.Parse("https://" + host + "/")
	b.jar.SetCookies(u, []*http.Cookie{{Name: name, Value: value, Path: "/"}})
}

var reHidden = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)

// hidden returns the hidden fields of the forms on a page, as a browser would
// submit them.
func hidden(page string) url.Values {
	v := url.Values{}
	for _, m := range reHidden.FindAllStringSubmatch(page, -1) {
		v.Set(m[1], html.UnescapeString(m[2]))
	}
	return v
}

// appSees parses the echo app's reply into the request headers the app was
// given.
func appSees(t *testing.T, r reply) http.Header {
	t.Helper()
	if r.status != http.StatusOK || !strings.Contains(r.body, "Hostname:") {
		t.Fatalf("expected the echo app, got %d: %.300s", r.status, r.body)
	}
	h := http.Header{}
	for _, line := range strings.Split(r.body, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), ": "); ok {
			h.Add(k, v)
		}
	}
	return h
}

// --- reading the stack ---

func compose(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command(composeArgs[0], append(composeArgs[1:], args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v\n%s", cmd.Args, err, out)
	}
	return string(out)
}

// codeFor waits for the code most recently mailed to addr, read from the
// gateway's log (the test stack uses the log mail backend).
func codeFor(t *testing.T, addr string, after int) (string, int) {
	t.Helper()
	re := regexp.MustCompile(`to=` + regexp.QuoteMeta(addr) + ` subject="(\d+) is your sign-in code"`)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		logs := compose(t, "logs", "--no-log-prefix", "auth")
		if all := re.FindAllStringSubmatch(logs, -1); len(all) > after {
			return all[len(all)-1][1], len(all)
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("no code mailed to %s", addr)
	return "", 0
}

func mailsTo(t *testing.T, addr string) int {
	re := regexp.MustCompile(`to=` + regexp.QuoteMeta(addr) + ` subject=`)
	return len(re.FindAllString(compose(t, "logs", "--no-log-prefix", "auth"), -1))
}

// --- flows ---

// startAt requests a protected page without a session and follows the
// gateway to its sign-in page, returning that page.
func (b *browser) startAt(target string) reply {
	b.t.Helper()
	r := b.get(target, nil)
	if r.status != http.StatusFound || !strings.HasPrefix(r.location(), authHost+"/login?") {
		b.t.Fatalf("GET %s without a session: %d to %q, want a redirect to sign in", target, r.status, r.location())
	}
	page := b.get(r.location(), nil)
	if page.status != http.StatusOK {
		b.t.Fatalf("sign-in page: %d", page.status)
	}
	return page
}

// requestCode submits the email step from a sign-in page.
func (b *browser) requestCode(login reply, email string, remember bool) reply {
	b.t.Helper()
	form := hidden(login.body)
	form.Set("email", email)
	if remember {
		form.Set("remember", "1")
	}
	return b.submit("/request", form)
}

// signIn goes from a protected page to that page, signed in, and returns the
// final redirect's reply (the hop that sets the session).
func (b *browser) signIn(target, email string) reply {
	b.t.Helper()
	before := mailsTo(b.t, email)
	codePage := b.requestCode(b.startAt(target), email, false)
	if codePage.status != http.StatusOK {
		b.t.Fatalf("request a code for %s: %d", email, codePage.status)
	}
	code, _ := codeFor(b.t, email, before)
	form := hidden(codePage.body)
	form.Set("code", code)
	r := b.submit("/verify-code", form)
	if r.status != http.StatusFound {
		b.t.Fatalf("enter the code for %s: %d: %.300s", email, r.status, r.body)
	}
	return r
}

// --- the chain ---

func TestChain(t *testing.T) {
	// The order matters: later steps build on sessions made earlier, and the
	// rate-limit step spends the client IP's allowance, so it runs last.
	alice := newBrowser(t) // a member of staff at example.org

	t.Run("an unauthenticated request is sent to sign in, with its destination", func(t *testing.T) {
		r := newBrowser(t).get("https://app."+domain+"/secret?q=1", nil)
		want := authHost + "/login?rd=" + url.QueryEscape("https://app."+domain+"/secret?q=1")
		if r.status != http.StatusFound || r.location() != want {
			t.Fatalf("got %d to %q, want 302 to %q", r.status, r.location(), want)
		}
	})

	t.Run("forged forwarding headers do not change the destination", func(t *testing.T) {
		r := newBrowser(t).get("https://app."+domain+"/x", map[string]string{
			"X-Forwarded-Host": "evil.example", "X-Forwarded-Proto": "http", "X-Forwarded-Uri": "/stolen",
		})
		if !strings.Contains(r.location(), url.QueryEscape("https://app."+domain+"/x")) {
			t.Fatalf("destination taken from forged headers: %q", r.location())
		}
	})

	t.Run("forged identity and rule headers do not admit a visitor with no session", func(t *testing.T) {
		forged := map[string]string{
			"Remote-User": "boss@admins.example", "Remote-Email": "boss@admins.example",
			"Remote-Groups": "admin", "X-Auth-Policy": "any;guests=allow",
		}
		for _, host := range []string{"app", "reports", "admin"} {
			r := newBrowser(t).get("https://"+host+"."+domain+"/", forged)
			if r.status != http.StatusFound || !strings.Contains(r.location(), "/login?") {
				t.Errorf("%s with forged headers: %d to %q", host, r.status, r.location())
			}
		}
		// A public route admits everyone, so what matters is that the app is
		// not handed the forged identity (strip_public).
		for _, target := range []string{"https://public." + domain + "/", "https://mixed." + domain + "/webhooks/x"} {
			h := appSees(t, newBrowser(t).get(target, forged))
			for _, k := range []string{"Remote-User", "Remote-Email", "Remote-Groups"} {
				if v := h.Get(k); v != "" {
					t.Errorf("%s handed the app a forged %s: %q", target, k, v)
				}
			}
		}
	})

	t.Run("signing in lands on the app with the gateway's identity only", func(t *testing.T) {
		final := alice.signIn("https://app."+domain+"/after", "alice@example.org")
		if final.location() != "https://app."+domain+"/after" {
			t.Fatalf("landed on %q", final.location())
		}
		sc := final.setCookies(cookieKey)
		if len(sc) != 1 {
			t.Fatalf("session Set-Cookie lines: %v", sc)
		}
		for _, attr := range []string{"Domain=" + domain, "HttpOnly", "SameSite=Lax", "Path=/"} {
			if !strings.Contains(sc[0], attr) {
				t.Errorf("session cookie lacks %s: %s", attr, sc[0])
			}
		}
		alice.setCookie("app."+domain, "app_own", "kept")
		h := appSees(t, alice.get("https://app."+domain+"/after", map[string]string{
			"Remote-User": "boss@admins.example", "Remote-Groups": "admin", "X-Auth-Policy": "groups=admin",
		}))
		if got := h.Get("Remote-User"); got != "alice@example.org" {
			t.Errorf("app saw Remote-User %q", h["Remote-User"])
		}
		if got := h["Remote-Groups"]; len(got) != 1 || got[0] != "user" {
			t.Errorf("app saw Remote-Groups %q, want exactly [user]", got)
		}
		cookies := strings.Join(h["Cookie"], "; ")
		if strings.Contains(cookies, cookieKey) {
			t.Errorf("the session cookie reached the app: %s", cookies)
		}
		if !strings.Contains(cookies, "app_own=kept") {
			t.Errorf("the app's own cookie was lost: %q", cookies)
		}
	})

	t.Run("the sign-in pages carry their security headers through Caddy", func(t *testing.T) {
		r := newBrowser(t).get(authHost+"/login", nil)
		for k, want := range map[string]string{
			"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
			"Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
		} {
			if got := r.header.Get(k); got != want {
				t.Errorf("%s = %q, want %q", k, got, want)
			}
		}
		if csp := r.header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "script-src") {
			t.Errorf("Content-Security-Policy = %q", csp)
		}
	})

	t.Run("the cookie given to anyone who asks for a code is not a session", func(t *testing.T) {
		mallory := newBrowser(t)
		mallory.requestCode(mallory.startAt("https://app."+domain+"/"), "alice@example.org", false)
		state := mallory.cookie("auth."+domain, "vps_auth_state")
		if state == "" {
			t.Fatal("no state cookie was set")
		}
		r := newBrowser(t).get("https://app."+domain+"/", map[string]string{"Cookie": cookieKey + "=" + state})
		if r.status != http.StatusFound || !strings.Contains(r.location(), "/login?") {
			t.Fatalf("a state cookie presented as a session: %d to %q", r.status, r.location())
		}
	})

	t.Run("a renewed session reaches the browser beside the app's own cookie", func(t *testing.T) {
		before := alice.cookie("app."+domain, cookieKey)
		time.Sleep(4 * time.Second) // past the stack's 3s renewal interval
		r := alice.get("https://app."+domain+"/", nil)
		appSees(t, r)
		if len(r.setCookies(cookieKey)) != 1 {
			t.Fatalf("no renewed session cookie reached the browser; Set-Cookie: %v", r.header.Values("Set-Cookie"))
		}
		if len(r.setCookies("app_own")) != 1 {
			t.Errorf("the app's own Set-Cookie was lost on a renewal: %v", r.header.Values("Set-Cookie"))
		}
		if after := alice.cookie("app."+domain, cookieKey); after == before {
			t.Error("the browser still holds the old session after renewal")
		}
	})

	t.Run("each guard admits and refuses as its rule says", func(t *testing.T) {
		admitted := map[string]bool{
			"app": true, "staff": true, "public": true, "mixed": true,
			"reports": false, "admin": false, "either": false, "broken": false, "open": true,
		}
		for host, want := range admitted {
			r := alice.get("https://"+host+"."+domain+"/", nil)
			if want {
				appSees(t, r)
				continue
			}
			if r.status != http.StatusFound || !strings.HasPrefix(r.location(), authHost+"/denied?") {
				t.Errorf("%s: %d to %q, want the no-access page", host, r.status, r.location())
			}
		}
		// The session survives a refusal.
		appSees(t, alice.get("https://app."+domain+"/", nil))
	})

	t.Run("a forged rule header cannot widen a guard", func(t *testing.T) {
		r := alice.get("https://reports."+domain+"/", map[string]string{"X-Auth-Policy": "any"})
		if !strings.HasPrefix(r.location(), authHost+"/denied?") {
			t.Fatalf("reports with a forged rule: %d to %q", r.status, r.location())
		}
	})

	t.Run("the session cookie never reaches a public app or a public path", func(t *testing.T) {
		for _, target := range []string{"https://public." + domain + "/", "https://mixed." + domain + "/webhooks/x"} {
			h := appSees(t, alice.get(target, nil))
			if c := strings.Join(h["Cookie"], ";"); strings.Contains(c, cookieKey) {
				t.Errorf("%s received the session cookie: %s", target, c)
			}
		}
	})

	t.Run("an address at the wrong domain is declined before a code is sent", func(t *testing.T) {
		b := newBrowser(t)
		before := mailsTo(t, "bob@outside.example")
		r := b.requestCode(b.startAt("https://staff."+domain+"/"), "bob@outside.example", false)
		if r.status != http.StatusForbidden {
			t.Fatalf("wrong-domain request: %d", r.status)
		}
		time.Sleep(time.Second)
		if mailsTo(t, "bob@outside.example") != before {
			t.Error("a code was mailed to an address the route declines")
		}
	})

	t.Run("a guest reaches only the app open to the public", func(t *testing.T) {
		g := newBrowser(t)
		g.signIn("https://open."+domain+"/", "stranger@outside.example")
		h := appSees(t, g.get("https://open."+domain+"/", nil))
		if groups := h.Get("Remote-Groups"); !strings.HasPrefix(groups, "guest") {
			t.Errorf("guest's groups = %q", groups)
		}
		for _, host := range []string{"app", "staff", "reports", "admin", "either"} {
			r := g.get("https://"+host+"."+domain+"/", nil)
			if !strings.HasPrefix(r.location(), authHost+"/denied?") {
				t.Errorf("guest at %s: %d to %q", host, r.status, r.location())
			}
		}
		if r := g.get(authHost+"/admin/", nil); r.status != http.StatusFound || !strings.Contains(r.location(), "/login") {
			t.Errorf("guest reached the admin pages: %d", r.status)
		}
	})

	boss := newBrowser(t) // an administrator at a domain no rule names

	t.Run("an administrator must pass the second factor", func(t *testing.T) {
		out := compose(t, "exec", "-T", "auth", "/app", "-totp-enroll", "boss@admins.example")
		m := regexp.MustCompile(`Setup key:\s+([A-Z2-7]+)`).FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("no setup key in enrolment output")
		}
		secret := m[1]

		before := mailsTo(t, "boss@admins.example")
		codePage := boss.requestCode(boss.startAt("https://admin."+domain+"/"), "boss@admins.example", false)
		code, _ := codeFor(t, "boss@admins.example", before)
		form := hidden(codePage.body)
		form.Set("code", code)
		step := boss.submit("/verify-code", form)
		if step.status != http.StatusOK || !strings.Contains(step.body, `action="/totp"`) {
			t.Fatalf("after the email code an admin got %d, want the authenticator step", step.status)
		}
		if boss.cookie("admin."+domain, cookieKey) != "" {
			t.Fatal("a session was issued before the second factor")
		}
		wrong := hidden(step.body)
		wrong.Set("code", "000000")
		if r := boss.submit("/totp", wrong); r.status != http.StatusUnauthorized {
			t.Errorf("a wrong authenticator code: %d", r.status)
		}
		otpCode, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		right := hidden(step.body)
		right.Set("code", otpCode)
		if r := boss.submit("/totp", right); r.status != http.StatusFound {
			t.Fatalf("the right authenticator code: %d: %.200s", r.status, r.body)
		}
		h := appSees(t, boss.get("https://admin."+domain+"/", nil))
		if h.Get("Remote-Groups") != "admin" {
			t.Errorf("admin's groups = %q", h.Get("Remote-Groups"))
		}
		// The domain door refuses an administrator at another domain.
		if r := boss.get("https://staff."+domain+"/", nil); !strings.HasPrefix(r.location(), authHost+"/denied?") {
			t.Errorf("off-domain admin at the domain door: %d to %q", r.status, r.location())
		}
	})

	t.Run("staff cannot open the admin pages", func(t *testing.T) {
		r := alice.get(authHost+"/admin/", nil)
		if r.status != http.StatusFound || !strings.Contains(r.location(), "/login") {
			t.Fatalf("staff at /admin/: %d to %q", r.status, r.location())
		}
	})

	t.Run("an admin change through Caddy reaches a session at its next renewal", func(t *testing.T) {
		page := boss.get(authHost+"/admin/groups", nil)
		csrf := hidden(page.body).Get("csrf")
		if csrf == "" {
			t.Fatalf("no form token on the groups page (%d)", page.status)
		}
		admin := func(path string, form url.Values) reply {
			form.Set("csrf", csrf)
			return boss.do(http.MethodPost, authHost+path, form, map[string]string{"Origin": authHost, "Sec-Fetch-Site": "same-origin"})
		}
		if r := admin("/admin/groups", url.Values{"name": {"reports"}, "label": {"Reports"}}); r.status >= 400 {
			t.Fatalf("create group: %d", r.status)
		}
		if r := admin("/admin/groups/reports/members", url.Values{"email": {"alice@example.org"}}); r.status >= 400 {
			t.Fatalf("add member: %d", r.status)
		}
		// Without the token the same change is refused.
		bare := boss.do(http.MethodPost, authHost+"/admin/groups", url.Values{"name": {"sneaky"}}, map[string]string{"Origin": authHost, "Sec-Fetch-Site": "same-origin"})
		if bare.status != http.StatusForbidden {
			t.Errorf("admin change without a form token: %d", bare.status)
		}
		time.Sleep(4 * time.Second)
		h := appSees(t, alice.get("https://reports."+domain+"/", nil))
		if h.Get("Remote-Groups") != "user,reports" {
			t.Errorf("alice's groups after renewal = %q", h.Get("Remote-Groups"))
		}
		appSees(t, alice.get("https://either."+domain+"/", nil))
	})

	t.Run("a sign-in form posted from a sibling host is refused", func(t *testing.T) {
		b := newBrowser(t)
		for _, hdr := range []map[string]string{
			{"Origin": "https://app." + domain, "Sec-Fetch-Site": "same-site"},
			{"Sec-Fetch-Site": "same-site"},
			{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
		} {
			r := b.do(http.MethodPost, authHost+"/request", url.Values{"email": {"alice@example.org"}}, hdr)
			if r.status != http.StatusForbidden {
				t.Errorf("POST /request with %v: %d", hdr, r.status)
			}
		}
	})

	t.Run("the gateway's check endpoint reveals nothing to a visitor on the public host", func(t *testing.T) {
		r := newBrowser(t).get(authHost+"/verify", map[string]string{"X-Auth-Policy": "any", "X-Forwarded-Host": "app." + domain})
		if r.header.Get("Remote-User") != "" || r.status == http.StatusOK {
			t.Errorf("an anonymous /verify on the public host answered %d with Remote-User %q", r.status, r.header.Get("Remote-User"))
		}
	})

	t.Run("signing out ends the session for every app", func(t *testing.T) {
		confirm := alice.get(authHost+"/logout", nil)
		r := alice.submit("/logout", hidden(confirm.body))
		if r.status != http.StatusFound {
			t.Fatalf("sign out: %d", r.status)
		}
		for _, host := range []string{"app", "staff", "reports"} {
			if r := alice.get("https://"+host+"."+domain+"/", nil); !strings.Contains(r.location(), "/login?") {
				t.Errorf("%s after sign-out: %d to %q", host, r.status, r.location())
			}
		}
	})

	t.Run("a forged forwarded address does not escape the per-network limit", func(t *testing.T) {
		b := newBrowser(t)
		login := b.startAt("https://app." + domain + "/")
		for i := 0; i < 45; i++ {
			form := hidden(login.body)
			form.Set("email", fmt.Sprintf("flood%d@example.org", i))
			r := b.do(http.MethodPost, authHost+"/request", form, map[string]string{
				"Origin": "null", "Sec-Fetch-Site": "same-origin",
				"X-Forwarded-For": fmt.Sprintf("198.51.100.%d", i+1), "X-Real-IP": fmt.Sprintf("203.0.113.%d", i+1),
			})
			if r.status == http.StatusTooManyRequests {
				t.Logf("refused after %d requests", i+1)
				return
			}
		}
		t.Fatal("45 requests with a new forwarded address each were never refused; the limit is keyed on a forgeable header")
	})
}
