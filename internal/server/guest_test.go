package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// openHostRD is a destination on the one host opened to guests in these tests;
// closedHostRD is any other app on the same server.
const (
	openHostRD   = "https://apply.example.com/"
	closedHostRD = "https://app.example.com/"
	strangerAddr = "stranger@gmail.com"
)

// guestServer is the standard test server with apply.example.com listed in
// OPEN_REGISTRATION_HOSTS and the allow-list left at example.com.
func guestServer(t *testing.T) (*Server, *captureSender) {
	t.Helper()
	return testServerWith(t, func(c *config.Config) {
		c.OpenRegistrationHosts = []string{"apply.example.com"}
	})
}

// loginGuest signs a stranger in through the open host and fails the test if no
// session results.
func loginGuest(t *testing.T, c *client, sender *captureSender, addr string) {
	t.Helper()
	sender.reset()
	c.postForm("/request", url.Values{"email": {addr}, "rd": {openHostRD}})
	code := sender.code()
	if code == "" {
		t.Fatalf("no code sent to %s via the open host", addr)
	}
	rec := c.postForm("/verify-code", url.Values{"code": {code}, "rd": {openHostRD}})
	if rec.Code != http.StatusFound {
		t.Fatalf("guest verify-code = %d, want 302", rec.Code)
	}
}

// sessionOf decodes the client's session cookie as the server would.
func sessionOf(t *testing.T, srv *Server, c *client) *session.Identity {
	t.Helper()
	ck := c.cookies[session.SessionCookie]
	if ck == nil {
		t.Fatal("no session cookie")
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(ck)
	id, ok := srv.sessions.ReadSession(req, srv.now())
	if !ok {
		t.Fatal("session cookie did not verify")
	}
	return id
}

// noEmailSent reports whether nothing was mailed within a short window. The
// decoy path never starts a send, so a brief wait is enough to tell.
func noEmailSent(sender *captureSender) bool {
	select {
	case <-sender.sent:
		return false
	case <-time.After(200 * time.Millisecond):
		return true
	}
}

// /request mails a real code to an off-allow-list address only when the login
// is headed to an open host. Anywhere else the decoy path is unchanged: nothing
// is sent, but a code is stored so /verify-code behaves the same as for a
// permitted address (a wrong guess is a mismatch, not "no code").
func TestRequestSendsGuestCodeOnlyForOpenHost(t *testing.T) {
	srv, sender := guestServer(t)
	ctx := context.Background()

	c := newClient(t, srv.Handler())
	c.postForm("/request", url.Values{"email": {strangerAddr}, "rd": {closedHostRD}})
	if !noEmailSent(sender) {
		t.Fatal("a code was mailed to a stranger for a host that is not open")
	}
	res, err := srv.store.ConsumeCode(ctx, strangerAddr, "10.0.0.1", srv.hashCode("000000"), 5, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if res != store.ConsumeMismatch {
		t.Fatalf("closed host: consume = %v, want a stored decoy (mismatch)", res)
	}

	sender.reset()
	c2 := newClient(t, srv.Handler())
	c2.postForm("/request", url.Values{"email": {"other@gmail.com"}, "rd": {openHostRD}})
	if sender.code() == "" {
		t.Fatal("open host: no code was mailed to a public address")
	}

	// A bare host that cannot receive public mail is still a decoy on an open host.
	sender.reset()
	c3 := newClient(t, srv.Handler())
	c3.postForm("/request", url.Values{"email": {"x@localhost"}, "rd": {openHostRD}})
	if !noEmailSent(sender) {
		t.Error("open host mailed a code to an implausible address")
	}
}

// With no OPEN_REGISTRATION_HOSTS, the open host is just another app: decoy.
func TestRequestDecoyWhenNoOpenHostsConfigured(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	c.postForm("/request", url.Values{"email": {strangerAddr}, "rd": {openHostRD}})
	if !noEmailSent(sender) {
		t.Error("a code was mailed to a stranger with no open hosts configured")
	}
}

func TestVerifyCodeMintsGuestSession(t *testing.T) {
	srv, sender := guestServer(t)
	c := newClient(t, srv.Handler())
	loginGuest(t, c, sender, strangerAddr)

	id := sessionOf(t, srv, c)
	if id.Kind != session.KindGuest {
		t.Errorf("kind = %q, want %q", id.Kind, session.KindGuest)
	}
	if id.TOTP {
		t.Error("guest session claims a second factor")
	}
	if id.Groups != "guest" {
		t.Errorf("groups = %q, want guest", id.Groups)
	}

	// Audited as an ordinary successful login.
	evs, err := srv.store.ListAuthEvents(context.Background(), strangerAddr, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) == 0 || evs[0].Outcome != store.AuthOutcomeOK || evs[0].EventType != store.AuthEventLogin {
		t.Errorf("guest login not audited as login/ok: %+v", evs)
	}
}

// A code obtained via the open host does not mint a guest session if the code
// is then submitted for a destination that is not open.
func TestVerifyCodeDeniesGuestForClosedHost(t *testing.T) {
	srv, sender := guestServer(t)
	c := newClient(t, srv.Handler())
	c.postForm("/request", url.Values{"email": {strangerAddr}, "rd": {openHostRD}})
	code := sender.code()
	if code == "" {
		t.Fatal("no code sent")
	}
	rec := c.postForm("/verify-code", url.Values{"code": {code}, "rd": {closedHostRD}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("verify-code for a closed host = %d, want 403", rec.Code)
	}
	if c.cookies[session.SessionCookie] != nil {
		t.Error("a session was issued for a stranger outside the open host")
	}
}

// The state cookie's rd is the fallback when the form posts none.
func TestVerifyCodeGuestFromStateCookieRD(t *testing.T) {
	srv, sender := guestServer(t)
	c := newClient(t, srv.Handler())
	c.postForm("/request", url.Values{"email": {strangerAddr}, "rd": {openHostRD}})
	rec := c.postForm("/verify-code", url.Values{"code": {sender.code()}})
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != openHostRD {
		t.Fatalf("verify-code = %d %q, want 302 to the open host", rec.Code, rec.Header().Get("Location"))
	}
	if sessionOf(t, srv, c).Kind != session.KindGuest {
		t.Error("state-cookie rd did not yield a guest session")
	}
}

// The fail-safe property: every guard that does not say guests=allow keeps a
// guest out, including the bare `import protected` ("any").
func TestVerifyGuestPolicies(t *testing.T) {
	srv, sender := guestServer(t)
	ctx := context.Background()
	if err := srv.store.CreateGroup(ctx, "reviewers", ""); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.AddGroupMember(ctx, "reviewers", strangerAddr); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv.Handler())
	loginGuest(t, c, sender, strangerAddr)

	denied := []string{
		"any",
		"domains=example.com",
		"domains=gmail.com", // even the guest's own domain
		"groups=finance",
		"groups=admin",
		"any;guests=yes",
	}
	for _, p := range denied {
		rec := c.get("/verify", map[string]string{"X-Auth-Policy": p})
		if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/denied?rd=") {
			t.Errorf("policy %q: guest got %d %q, want 302 to /denied", p, rec.Code, rec.Header().Get("Location"))
		}
	}

	rec := c.get("/verify", map[string]string{"X-Auth-Policy": "any;guests=allow"})
	if rec.Code != http.StatusOK {
		t.Fatalf("any;guests=allow = %d, want 200", rec.Code)
	}
	if g := rec.Header().Get("Remote-Groups"); g != "guest,reviewers" {
		t.Errorf("Remote-Groups = %q, want guest,reviewers", g)
	}
	if e := rec.Header().Get("Remote-Email"); e != strangerAddr {
		t.Errorf("Remote-Email = %q", e)
	}

	// Explicit opt-in by a DB group the guest was placed in.
	if rec := c.get("/verify", requireGroups("reviewers")); rec.Code != http.StatusOK {
		t.Errorf("groups=reviewers (member) = %d, want 200", rec.Code)
	}
}

// guests=allow does not change what a department user may reach.
func TestGuestsAllowStillAdmitsNormalUsers(t *testing.T) {
	srv, sender := guestServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", url.Values{"rd": {openHostRD}})
	if k := sessionOf(t, srv, c).Kind; k != "" {
		t.Fatalf("allow-listed user on the open host got kind %q, want a normal session", k)
	}
	if rec := c.get("/verify", map[string]string{"X-Auth-Policy": "any;guests=allow"}); rec.Code != http.StatusOK {
		t.Errorf("normal user on any;guests=allow = %d, want 200", rec.Code)
	}
}

// Renewal must not end a guest session because Role says deny: it re-issues
// with kind guest and a recomputed group set.
func TestGuestSessionRenews(t *testing.T) {
	srv, sender := guestServer(t)
	c := newClient(t, srv.Handler())
	loginGuest(t, c, sender, strangerAddr)
	before := c.cookies[session.SessionCookie].Value

	if err := srv.store.CreateGroup(context.Background(), "reviewers", ""); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.AddGroupMember(context.Background(), "reviewers", strangerAddr); err != nil {
		t.Fatal(err)
	}
	srv.now = func() time.Time { return time.Now().Add(45 * time.Minute) }

	rec := c.get("/verify", map[string]string{"X-Auth-Policy": "any;guests=allow"})
	if rec.Code != http.StatusOK {
		t.Fatalf("guest at renewal = %d, want 200", rec.Code)
	}
	ck := c.cookies[session.SessionCookie]
	if ck == nil || ck.Value == before {
		t.Fatal("guest session was not re-issued at renewal")
	}
	id := sessionOf(t, srv, c)
	if id.Kind != session.KindGuest {
		t.Errorf("renewed kind = %q, want guest", id.Kind)
	}
	if id.Groups != "guest,reviewers" {
		t.Errorf("renewed groups = %q, want guest,reviewers", id.Groups)
	}
}

// A guest never carries the admin tier: not at /verify, not in the admin UI,
// not on /welcome, and not even with a forged "admin" in its groups.
func TestGuestNeverAdmin(t *testing.T) {
	srv, sender := guestServer(t)
	srv.cfg.TOTPEnabled = true
	c := newClient(t, srv.Handler())
	loginGuest(t, c, sender, strangerAddr)

	if rec := c.get("/admin/groups", nil); rec.Code != http.StatusFound {
		t.Errorf("guest /admin/groups = %d, want 302", rec.Code)
	}
	if body := c.get("/welcome", nil).Body.String(); strings.Contains(body, `href="/admin`) {
		t.Error("guest /welcome offered an Admin link")
	}
	forged := &session.Identity{Email: strangerAddr, Groups: "guest,admin", Kind: session.KindGuest}
	if isAdminSession(forged) {
		t.Error("isAdminSession admitted a guest whose groups name admin")
	}
	// Even if the address is later made an admin, the live guest session does
	// not step up at renewal; it stays a guest.
	srv.policy = authz.NewPolicy([]string{"example.com"}, []string{"admin@example.com", strangerAddr})
	srv.now = func() time.Time { return time.Now().Add(45 * time.Minute) }
	c.get("/verify", map[string]string{"X-Auth-Policy": "any;guests=allow"})
	if id := sessionOf(t, srv, c); id.Kind != session.KindGuest || strings.Contains(id.Groups, "admin") {
		t.Errorf("guest stepped up at renewal: kind=%q groups=%q", id.Kind, id.Groups)
	}
}

// The denial page tells a guest what they are signed in as and offers sign-out
// (carrying rd), never the emergency or admin paths.
func TestDeniedPageForGuest(t *testing.T) {
	srv, sender := guestServer(t)
	c := newClient(t, srv.Handler())
	loginGuest(t, c, sender, strangerAddr)

	rec := c.get("/denied?rd="+url.QueryEscape(closedHostRD), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("/denied = %d, want 403", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"signed in as a guest with <strong>" + strangerAddr + "</strong>",
		"approved email address",
		`href="https://auth.example.com/logout?rd=` + url.QueryEscape(closedHostRD) + `"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("guest denial page missing %q:\n%s", want, body)
		}
	}
	for _, bad := range []string{"/break/activate", "Sign in to continue", "/admin"} {
		if strings.Contains(body, bad) {
			t.Errorf("guest denial page offers %q", bad)
		}
	}
}

// Sign-out from the guest denial page still carries rd through to the login
// page, so the person can come straight back with an approved address.
func TestGuestLogoutCarriesRedirect(t *testing.T) {
	srv, sender := guestServer(t)
	c := newClient(t, srv.Handler())
	loginGuest(t, c, sender, strangerAddr)

	rec := c.get("/logout?rd="+url.QueryEscape(closedHostRD), nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `name="rd" value="`+closedHostRD+`"`) {
		t.Fatalf("GET /logout?rd for a guest should carry rd: %d", rec.Code)
	}
	rec = c.postForm("/logout", url.Values{"rd": {closedHostRD}})
	if loc := rec.Header().Get("Location"); loc != "https://auth.example.com/login?rd="+url.QueryEscape(closedHostRD) {
		t.Errorf("POST /logout = %q, want the login page with rd", loc)
	}
	if c.cookies[session.SessionCookie] != nil {
		t.Error("guest session survived sign-out")
	}
}

// The login page for an open host does not tell strangers that it is only for
// the allow-listed domain.
func TestOpenHostLoginHasNoDomainHint(t *testing.T) {
	srv, _ := guestServer(t)
	c := newClient(t, srv.Handler())
	body := c.get("/login?rd="+url.QueryEscape(openHostRD), nil).Body.String()
	// (The placeholder is not checked: the template's generic fallback is
	// you@example.com, which is also this test's allow-listed domain.)
	if strings.Contains(body, "This page is for") {
		t.Errorf("open-host login page hints the allow-listed domain:\n%s", body)
	}
	body = c.get("/login?rd="+url.QueryEscape(closedHostRD), nil).Body.String()
	if !strings.Contains(body, "This page is for") {
		t.Error("closed-host login page lost its domain hint")
	}
}

// Guest app access is recorded with its kind and shown as "guest" to admins.
func TestGuestAccessShownInAdminLog(t *testing.T) {
	srv, sender := guestServer(t)
	c := newClient(t, srv.Handler())
	loginGuest(t, c, sender, strangerAddr)
	c.get("/verify", map[string]string{"X-Auth-Policy": "any;guests=allow", "X-Forwarded-Host": "apply.example.com"})

	ac := newClient(t, srv.Handler())
	loginAs(t, ac, sender, "admin@example.com", nil)
	body := ac.get("/admin/access?email="+url.QueryEscape(strangerAddr), nil).Body.String()
	if !strings.Contains(body, `<span class="pill guest">guest</span>`) {
		t.Errorf("admin access log does not mark the guest session:\n%s", body)
	}
}

// A guest who scans a break-glass card is granted directly rather than deferred
// to an offer: the guest denial page never shows the one-tap grant, so deferring
// would strand them.
func TestGuestBreakGlassScanGrantsDirectly(t *testing.T) {
	srv, sender := guestServer(t)
	c := newClient(t, srv.Handler())
	loginGuest(t, c, sender, strangerAddr)
	token := mintCode(t, srv, "Lab 1", "g1")
	if rec := c.get("/break/"+token, nil); rec.Code != http.StatusFound {
		t.Fatalf("scan = %d, want 302", rec.Code)
	}
	if c.cookies[session.OfferCookie] != nil {
		t.Error("a guest scan was deferred to an offer")
	}
	if id := sessionOf(t, srv, c); id.Kind != session.KindBreakGlass {
		t.Errorf("kind after scan = %q, want break-glass", id.Kind)
	}
}

// Emptying OPEN_REGISTRATION_HOSTS ends every guest session at its next
// renewal, the way de-listing a domain ends a user's: a guest only exists
// because some host admits guests.
func TestGuestSessionEndsWhenNoHostIsOpen(t *testing.T) {
	srv, sender := guestServer(t)
	c := newClient(t, srv.Handler())
	loginGuest(t, c, sender, strangerAddr)

	srv.cfg.OpenRegistrationHosts = nil
	// Before renewal the session is still honoured: revocation takes effect at
	// SESSION_RENEW_AFTER, as it does for everyone.
	if rec := c.get("/verify", map[string]string{"X-Auth-Policy": "any;guests=allow"}); rec.Code != http.StatusOK {
		t.Fatalf("guest before renewal = %d, want 200", rec.Code)
	}
	srv.now = func() time.Time { return time.Now().Add(45 * time.Minute) }
	rec := c.get("/verify", map[string]string{"X-Auth-Policy": "any;guests=allow"})
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/login") {
		t.Fatalf("guest at renewal with no open host should be sent to login; got %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if ck := c.cookies[session.SessionCookie]; ck != nil && ck.Value != "" {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(ck)
		if _, ok := srv.sessions.ReadSession(req, srv.now()); ok {
			t.Error("the guest session should have been cleared")
		}
	}
}

// A guest never gets the remember-me lifetime, whatever the form asked for.
// Sessions are stateless, so this bounds how long an unwanted guest can hold a
// cookie before renewal re-checks the host list.
func TestGuestIgnoresRememberMe(t *testing.T) {
	srv, sender := guestServer(t)
	srv.cfg.SessionRememberTTL = 720 * time.Hour
	c := newClient(t, srv.Handler())

	sender.reset()
	c.postForm("/request", url.Values{"email": {strangerAddr}, "rd": {openHostRD}, "remember": {"1"}})
	code := sender.code()
	if code == "" {
		t.Fatal("no code sent to the stranger via the open host")
	}
	if rec := c.postForm("/verify-code", url.Values{"code": {code}, "rd": {openHostRD}}); rec.Code != http.StatusFound {
		t.Fatalf("guest verify-code = %d, want 302", rec.Code)
	}
	ck := c.cookies[session.SessionCookie]
	if ck == nil {
		t.Fatal("no session cookie")
	}
	if ck.MaxAge > int(srv.cfg.SessionTTL.Seconds()) {
		t.Errorf("guest remember-me MaxAge = %d, want <= %d (the short lifetime)", ck.MaxAge, int(srv.cfg.SessionTTL.Seconds()))
	}
	if id := sessionOf(t, srv, c); id.Kind != session.KindGuest {
		t.Errorf("kind = %q, want guest", id.Kind)
	}
}

// The admin groups page marks a member whose address the allow-list does not
// admit: such a membership is a live door for a guest once any host is open.
func TestGroupPageMarksMemberNotOnAllowList(t *testing.T) {
	srv, sender := guestServer(t)
	ctx := context.Background()
	if err := srv.store.CreateGroup(ctx, "reviewers", ""); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.AddGroupMember(ctx, "reviewers", "staff@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.AddGroupMember(ctx, "reviewers", strangerAddr); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	body := c.get("/admin/groups", nil).Body.String()

	const mark = "not on the allow-list"
	if strings.Count(body, mark) != 1 {
		t.Fatalf("want exactly one %q mark, got %d in:\n%s", mark, strings.Count(body, mark), body)
	}
	// The mark sits in the stranger's cell: the member cell is "<td>email mark</td>".
	cell := func(email string) string {
		i := strings.Index(body, "<td>"+email)
		if i < 0 {
			t.Fatalf("no member cell for %s", email)
		}
		return body[i : i+strings.Index(body[i:], "</td>")]
	}
	if !strings.Contains(cell(strangerAddr), mark) {
		t.Errorf("stranger's cell lacks the mark: %q", cell(strangerAddr))
	}
	if strings.Contains(cell("staff@example.com"), mark) {
		t.Errorf("staff member's cell carries the mark: %q", cell("staff@example.com"))
	}
}

// A session whose kind this build does not know is refused at /verify rather
// than read as a normal login. The kind rides inside the signed envelope, so
// only a sibling build sharing SESSION_SECRET could mint one; CanAccessApp
// would otherwise treat it as a department user and admit it to bare
// `protected` routes.
func TestVerifyRefusesUnknownSessionKind(t *testing.T) {
	srv, _ := guestServer(t)
	c := newClient(t, srv.Handler())
	rec := httptest.NewRecorder()
	if err := srv.sessions.IssueSessionTTL(rec, "user@example.com", "user", "future_kind", false, time.Hour, srv.now()); err != nil {
		t.Fatal(err)
	}
	for _, ck := range rec.Result().Cookies() {
		c.cookies[ck.Name] = ck
	}
	res := c.get("/verify", map[string]string{"X-Auth-Policy": "any"})
	if res.Code != http.StatusFound || !strings.Contains(res.Header().Get("Location"), "/login") {
		t.Fatalf("unknown kind at /verify = %d %q, want 302 to login", res.Code, res.Header().Get("Location"))
	}
	if ck := c.cookies[session.SessionCookie]; ck != nil && ck.Value != "" {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(ck)
		if _, ok := srv.sessions.ReadSession(req, srv.now()); ok {
			t.Error("unknown-kind session should have been cleared")
		}
	}
}
