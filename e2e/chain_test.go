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
	"encoding/base64"
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

	"github.com/uppertoe/vps-scaffold-auth/internal/passkey/passkeytest"
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

// fetchFrom runs busybox wget inside a stack container and returns its
// combined output, which shows the HTTP status line for any answer and a
// connection error for none.
func fetchFrom(t *testing.T, service, target string, hdr ...string) string {
	t.Helper()
	args := append(composeArgs[1:], "exec", "-T", service, "wget", "-S", "-q", "-O", "/dev/null", "-T", "3")
	for _, h := range hdr {
		args = append(args, "--header", h)
	}
	out, _ := exec.Command(composeArgs[0], append(args, target)...).CombinedOutput()
	return string(out)
}

// An app on its members network reaches the members endpoint and nothing
// else of the gateway's: the public listener, by either name, closes the
// connection unanswered. Caddy, on the gateway's other network, cannot reach
// the members endpoint at all.
func TestMembersNetworkReachesOnlyTheMembersEndpoint(t *testing.T) {
	const token = "Authorization: Bearer e2e-reader-token-0123456789abcdefghij"
	if out := fetchFrom(t, "reader", "http://auth-members:8081/v1/groups/staff/members", token); !strings.Contains(out, "HTTP/1.1 ") {
		t.Fatalf("the reader could not reach the members endpoint:\n%s", out)
	}
	for _, target := range []string{"http://auth-members:8080/healthz", "http://auth:8080/healthz"} {
		if out := fetchFrom(t, "reader", target); strings.Contains(out, "HTTP/1.1 ") {
			t.Errorf("the reader reached the public listener at %s:\n%s", target, out)
		}
	}
	if out := fetchFrom(t, "caddy", "http://auth:8081/v1/groups/staff/members", token); strings.Contains(out, "HTTP/1.1 ") {
		t.Errorf("Caddy's network reached the members endpoint:\n%s", out)
	}
	if out := fetchFrom(t, "caddy", "http://auth:8080/healthz"); !strings.Contains(out, "HTTP/1.1 200") {
		t.Errorf("Caddy could not reach the public listener:\n%s", out)
	}
}

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
		// Passkeys are on in this stack, so the sign-in page may run exactly one
		// kind of script: its own, from this host. A page with no passkey
		// ceremony runs none.
		if csp := r.header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || !strings.HasSuffix(csp, "; script-src 'self'") || strings.Count(csp, "script-src") != 1 {
			t.Errorf("sign-in page Content-Security-Policy = %q", csp)
		}
		if csp := newBrowser(t).get(authHost+"/logout", nil).header.Get("Content-Security-Policy"); strings.Contains(csp, "script-src") {
			t.Errorf("a page with no passkey ceremony allows scripts: %q", csp)
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

	t.Run("the session cookie in odd forms admits no one and reaches no app", func(t *testing.T) {
		var token string
		for _, c := range alice.jar.Cookies(&url.URL{Scheme: "https", Host: "app." + domain}) {
			if c.Name == cookieKey {
				token = c.Value
			}
		}
		if token == "" {
			t.Fatal("alice has no session cookie")
		}
		// A fresh browser sends hand-written cookie headers, as a sibling
		// site or a script could arrange.
		odd := newBrowser(t)
		refused := map[string]string{
			"a second session cookie beside the real one": cookieKey + "=" + token + "; " + cookieKey + "=forged",
			"the real token under a name in other case":   strings.ToUpper(cookieKey) + "=" + token,
			"the real token under a lookalike name":       cookieKey + "_=" + token,
		}
		for what, cookie := range refused {
			r := odd.get("https://app."+domain+"/", map[string]string{"Cookie": cookie})
			if r.status != http.StatusFound || !strings.HasPrefix(r.location(), authHost+"/login") {
				t.Errorf("%s: %d to %q, want sign-in", what, r.status, r.location())
			}
		}
		// On a public app and a public path, every copy of the session
		// cookie is removed, wherever it sits among the app's own cookies.
		for _, target := range []string{"https://public." + domain + "/", "https://mixed." + domain + "/webhooks/x"} {
			h := appSees(t, odd.get(target, map[string]string{
				"Cookie": "app_a=1; " + cookieKey + "=" + token + "; app_b=2; " + cookieKey + "=second",
			}))
			sent := strings.Join(h["Cookie"], "; ")
			if strings.Contains(sent, cookieKey+"=") {
				t.Errorf("%s received the session cookie: %s", target, sent)
			}
			if !strings.Contains(sent, "app_a=1") || !strings.Contains(sent, "app_b=2") {
				t.Errorf("%s lost the app's own cookies: %s", target, sent)
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

	t.Run("an administrator signs in like staff and takes the second step at the admin door", func(t *testing.T) {
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
		if r := boss.submit("/verify-code", form); r.status != http.StatusFound {
			t.Fatalf("after the email code an admin got %d, want 302 straight on", r.status)
		}
		// The admin-only site sends the administrator to the admin door.
		r := boss.get("https://admin."+domain+"/", nil)
		if !strings.HasPrefix(r.location(), authHost+"/totp?rd=") {
			t.Fatalf("admin site before the second step: %d to %q, want the admin door", r.status, r.location())
		}
		step := boss.get(r.location(), nil)
		if step.status != http.StatusOK || !strings.Contains(step.body, `action="/totp"`) {
			t.Fatalf("the admin door: %d", step.status)
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
		if r := boss.submit("/totp", right); r.status != http.StatusFound || r.location() != "https://admin."+domain+"/" {
			t.Fatalf("the right authenticator code: %d to %q: %.200s", r.status, r.location(), r.body)
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

	t.Run("an admin change through Caddy reaches a session at its next request", func(t *testing.T) {
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
		// No waiting for a renewal: a membership change reaches the session
		// at its next request.
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

	t.Run("a passkey made on a phone signs in on its own, only on the sign-in host, until it is removed", func(t *testing.T) {
		phone := map[string]string{
			"Origin": "null", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate",
			"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
		}
		const rpID = "auth." + domain
		app := "https://app." + domain + "/"
		dataAttr := func(page, name string) []byte {
			m := regexp.MustCompile(`data-` + name + `="([^"]*)"`).FindStringSubmatch(page)
			if m == nil {
				t.Fatalf("page has no data-%s", name)
			}
			b, err := base64.RawURLEncoding.DecodeString(m[1])
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
		enc := base64.RawURLEncoding.EncodeToString

		// An email code on a phone ends on the offer, served through Caddy.
		owner := newBrowser(t)
		before := mailsTo(t, "carol@example.org")
		codePage := owner.requestCode(owner.startAt(app), "carol@example.org", false)
		code, _ := codeFor(t, "carol@example.org", before)
		form := hidden(codePage.body)
		form.Set("code", code)
		offer := owner.do(http.MethodPost, authHost+"/verify-code", form, phone)
		if offer.status != http.StatusOK || !strings.Contains(offer.body, "Sign in faster on this phone") {
			t.Fatalf("no passkey offer on a phone: %d", offer.status)
		}
		js := owner.get(authHost+"/passkey.js", nil)
		if js.status != http.StatusOK || !strings.HasPrefix(js.header.Get("Content-Type"), "text/javascript") || !strings.Contains(js.body, "navigator.credentials") {
			t.Fatalf("passkey.js through Caddy: %d %q", js.status, js.header.Get("Content-Type"))
		}

		a := passkeytest.New()
		reg := a.Register(rpID, authHost, dataAttr(offer.body, "challenge"), dataAttr(offer.body, "userid"))
		added := owner.do(http.MethodPost, authHost+"/passkeys/register", url.Values{
			"rd": {app}, "id": {enc(reg.CredentialID)}, "clientDataJSON": {enc(reg.ClientDataJSON)},
			"authenticatorData": {enc(reg.AuthenticatorData)}, "publicKey": {enc(reg.PublicKey)}, "publicKeyAlg": {"-7"},
		}, phone)
		if added.status != http.StatusOK || !strings.Contains(added.body, "A passkey has been added to this phone.") {
			t.Fatalf("add a passkey: %d: %.300s", added.status, added.body)
		}
		// The account holder is told by email.
		notice := regexp.MustCompile(`to=carol@example\.org subject="A passkey has been added to your account"`)
		for deadline := time.Now().Add(10 * time.Second); !notice.MatchString(compose(t, "logs", "--no-log-prefix", "auth")); time.Sleep(200 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("no email told the account holder that a passkey was added")
			}
		}

		signIn := func(b *browser, rp string) reply {
			login := b.startAt(app)
			as := a.SignIn(rp, authHost, dataAttr(login.body, "challenge"))
			return b.do(http.MethodPost, authHost+"/passkey/login", url.Values{
				"rd": {hidden(login.body).Get("rd")}, "id": {enc(as.CredentialID)}, "clientDataJSON": {enc(as.ClientDataJSON)},
				"authenticatorData": {enc(as.AuthenticatorData)}, "signature": {enc(as.Signature)}, "userHandle": {enc(as.UserHandle)},
			}, phone)
		}
		// A key scoped to the whole domain, which a sibling app could ask for,
		// is refused.
		if r := signIn(newBrowser(t), domain); r.status == http.StatusFound {
			t.Fatal("a ceremony for the whole domain signed in")
		}
		other := newBrowser(t)
		if r := signIn(other, rpID); r.status != http.StatusFound || r.location() != app {
			t.Fatalf("passkey sign-in: %d to %q: %.300s", r.status, r.location(), r.body)
		}
		if h := appSees(t, other.get(app, nil)); h.Get("Remote-User") != "carol@example.org" {
			t.Fatalf("the app sees %q after a passkey sign-in", h.Get("Remote-User"))
		}

		// The owner removes the passkey; the session it started ends at its
		// next renewal (SESSION_RENEW_AFTER is 3s here).
		list := owner.get(authHost+"/passkeys", phone)
		action := regexp.MustCompile(`action="(/passkeys/\d+/remove)"`).FindStringSubmatch(list.body)
		if action == nil {
			t.Fatalf("the passkeys page lists no passkey: %.300s", list.body)
		}
		if r := owner.do(http.MethodPost, authHost+action[1], hidden(list.body), phone); r.status != http.StatusFound {
			t.Fatalf("remove the passkey: %d", r.status)
		}
		time.Sleep(4 * time.Second)
		if r := other.get(app, nil); r.status != http.StatusFound || !strings.Contains(r.location(), "/login?") {
			t.Fatalf("a removed passkey's session still reaches the app: %d", r.status)
		}
		if r := signIn(newBrowser(t), rpID); r.status == http.StatusFound {
			t.Fatal("a removed passkey still signs in")
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
