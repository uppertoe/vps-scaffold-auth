package server

import (
	"context"
	"errors"
	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/session"
)

// requireGroups/requireDomains simulate the single X-Auth-Policy header Caddy's
// per-app snippets set on the /verify subrequest via header_up.
func requireDomains(d string) map[string]string {
	return map[string]string{"X-Auth-Policy": "domains=" + d}
}
func requireGroups(g string) map[string]string {
	return map[string]string{"X-Auth-Policy": "groups=" + g}
}

// protectedAny simulates the plain `import protected` door, which sends the
// explicit "any" sentinel (any authenticated non-break-glass user). /verify now
// fails closed on a MISSING policy header, so plain-protected must be explicit.
func protectedAny() map[string]string {
	return map[string]string{"X-Auth-Policy": "any"}
}

func TestPerAppDomainGate(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)

	// App that accepts this user's domain -> allowed.
	if rec := c.get("/verify", requireDomains("example.com")); rec.Code != http.StatusOK {
		t.Fatalf("matching domain = %d, want 200", rec.Code)
	}
	// App that accepts only another domain -> denied (sent to /denied, not login).
	rec := c.get("/verify", requireDomains("partner.com"))
	if rec.Code != http.StatusFound {
		t.Fatalf("non-matching domain = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "/denied?rd=") {
		t.Errorf("denied redirect went to %q, want /denied", loc)
	}
}

func TestPerAppGroupGate(t *testing.T) {
	srv, sender := testServer(t)
	ctx := context.Background()
	if err := srv.store.CreateGroup(ctx, "dashboard", ""); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.AddGroupMember(ctx, "dashboard", "user@example.com"); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)

	if rec := c.get("/verify", requireGroups("dashboard")); rec.Code != http.StatusOK {
		t.Fatalf("member of required group = %d, want 200", rec.Code)
	}
	if rec := c.get("/verify", requireGroups("finance")); rec.Code != http.StatusFound {
		t.Fatalf("not in required group = %d, want 302 (denied)", rec.Code)
	}
}

// A denial must not disturb the session: the user keeps access to apps they
// are allowed on, and the denial page offers a working sign-in link.
func TestDeniedPreservesSessionAndOffersLogin(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)

	// Bounce off an app that requires a different domain.
	if rec := c.get("/verify", requireDomains("partner.com")); rec.Code != http.StatusFound {
		t.Fatalf("expected 302 denied, got %d", rec.Code)
	}
	// Session cookie is untouched...
	if c.cookies[session.SessionCookie] == nil {
		t.Fatal("denial cleared the session cookie")
	}
	// ...so a plain app still grants.
	if rec := c.get("/verify", protectedAny()); rec.Code != http.StatusOK {
		t.Fatalf("plain /verify after denial = %d, want 200 (session intact)", rec.Code)
	}

	// The denial page names the user and links to sign-in (back to the app).
	rd := "https://app.example.com/secret"
	rec := c.get("/denied?rd="+url.QueryEscape(rd), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("/denied status = %d, want 403", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "user@example.com") {
		t.Error("denied page should name the signed-in account")
	}
	wantLogin := "https://auth.example.com/login?rd=" + url.QueryEscape(rd)
	if !strings.Contains(body, wantLogin) {
		t.Errorf("denied page missing sign-in link %q", wantLogin)
	}
}

// Break-glass is deny-by-default: a plain `import protected` app (no
// requirement) rejects it; only a route requiring its group accepts it. The
// denial page frames it as emergency access.
func TestBreakGlassScopedToItsGroup(t *testing.T) {
	srv, _ := testServer(t)
	token := mintCode(t, srv, "Angiography Lab 1", "bg_stroke")
	c := newClient(t, srv.Handler())
	if rec := c.get("/break/"+token, nil); rec.Code != http.StatusFound {
		t.Fatalf("scan = %d", rec.Code)
	}

	// Plain protected app (any signed-in user) -> break-glass still denied.
	if rec := c.get("/verify", protectedAny()); rec.Code != http.StatusFound {
		t.Fatalf("break-glass on plain /verify = %d, want 302 (denied)", rec.Code)
	}
	// An app requiring a different group -> denied.
	if rec := c.get("/verify", requireGroups("bg_other")); rec.Code != http.StatusFound {
		t.Fatalf("break-glass wrong group = %d, want 302 (denied)", rec.Code)
	}
	// The route that opts into this code's group -> allowed.
	rec := c.get("/verify", requireGroups("bg_stroke"))
	if rec.Code != http.StatusOK {
		t.Fatalf("break-glass on its own route = %d, want 200", rec.Code)
	}
	if g := rec.Header().Get("Remote-Groups"); g != "bg_stroke" {
		t.Errorf("Remote-Groups = %q, want bg_stroke", g)
	}

	// Denial page frames it as emergency access and shows the card label.
	body := c.get("/denied?rd="+url.QueryEscape("https://app.example.com/"), nil).Body.String()
	if !strings.Contains(body, "emergency access") || !strings.Contains(body, "Angiography Lab 1") {
		t.Errorf("break-glass denial page missing emergency framing/label:\n%s", body)
	}
}

// TestMissingPolicyFailsClosed verifies the deny-by-default fix: an authenticated
// user hitting /verify with NO X-Auth-Policy (a hand-rolled guard that forgot the
// header) is denied rather than silently granted, while the explicit "any"
// sentinel still admits them.
func TestMissingPolicyFailsClosed(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)

	// No policy header → deny (302 to /denied).
	if rec := c.get("/verify", nil); rec.Code != http.StatusFound {
		t.Fatalf("missing-policy /verify = %d, want 302 (deny-by-default)", rec.Code)
	}
	// Explicit "any" sentinel → allowed.
	if rec := c.get("/verify", protectedAny()); rec.Code != http.StatusOK {
		t.Fatalf("explicit any /verify = %d, want 200", rec.Code)
	}
}

// A person added to a group after signing in is let through at once: the
// refused request re-reads their groups and renews the session cookie.
func TestGroupGateAdmitsNewMemberWithoutRelogin(t *testing.T) {
	srv, sender := testServer(t)
	ctx := context.Background()
	if err := srv.store.CreateGroup(ctx, "planka-users", ""); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)

	if rec := c.get("/verify", requireGroups("planka-users")); rec.Code != http.StatusFound {
		t.Fatalf("before joining = %d, want 302 (denied)", rec.Code)
	}
	// An administrator adds them on the Groups page, which also clears the
	// remembered "unchanged" result from the refusal just above.
	admin := newClient(t, srv.Handler())
	loginAs(t, admin, sender, "admin@example.com", nil)
	tok := extractCSRF(t, admin.get("/admin/groups", nil).Body.String())
	if rec := admin.postForm("/admin/groups/planka-users/members", url.Values{"csrf": {tok}, "email": {"user@example.com"}}); rec.Code != http.StatusFound {
		t.Fatalf("admin add member = %d", rec.Code)
	}
	rec := c.get("/verify", requireGroups("planka-users"))
	if rec.Code != http.StatusOK {
		t.Fatalf("after joining = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Remote-Groups"), "planka-users") {
		t.Errorf("Remote-Groups = %q, want planka-users", rec.Header().Get("Remote-Groups"))
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), session.SessionCookie+"=") {
		t.Error("renewed session cookie not issued")
	}
	// The renewed cookie now carries the group, so the next request passes
	// without another lookup.
	if rec := c.get("/verify", requireGroups("planka-users")); rec.Code != http.StatusOK {
		t.Fatalf("next request = %d, want 200", rec.Code)
	}
}

// A refusal with unchanged groups issues no cookie, so a person repeatedly
// refused does not slide their session forward.
func TestGroupGateRefusalWithUnchangedGroupsKeepsCookie(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)

	rec := c.get("/verify", requireGroups("finance"))
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/denied") {
		t.Fatalf("refusal = %d %q, want 302 to /denied", rec.Code, rec.Header().Get("Location"))
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Errorf("refusal issued a cookie: %q", rec.Header().Get("Set-Cookie"))
	}
}

// The refusal-path renewal keeps the scheduled renewal's guarantees.

func TestGroupRecheckClearsRevokedPrincipal(t *testing.T) {
	srv, sender := testServer(t)
	ctx := context.Background()
	if err := srv.store.CreateGroup(ctx, "team", ""); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)
	// The domain is de-listed and the person added to the group.
	srv.policy = authz.NewPolicy([]string{"other.org"}, []string{"admin@example.com"})
	if err := srv.store.AddGroupMember(ctx, "team", "user@example.com"); err != nil {
		t.Fatal(err)
	}
	rec := c.get("/verify", requireGroups("team"))
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/login") {
		t.Fatalf("revoked principal = %d %q, want a redirect to sign in", rec.Code, rec.Header().Get("Location"))
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Error("revoked principal's session not cleared")
	}
}

func TestGroupRecheckRequiresTOTPForNewAdmin(t *testing.T) {
	srv, sender := testServerWith(t, func(c *config.Config) { c.TOTPEnabled = true })
	ctx := context.Background()
	if err := srv.store.CreateGroup(ctx, "team", ""); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)
	// Promoted to admin since signing in, without a second factor.
	srv.policy = authz.NewPolicy([]string{"example.com"}, []string{"admin@example.com", "user@example.com"})
	if err := srv.store.AddGroupMember(ctx, "team", "user@example.com"); err != nil {
		t.Fatal(err)
	}
	rec := c.get("/verify", requireGroups("team"))
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/login") {
		t.Fatalf("new admin without TOTP = %d %q, want a redirect to sign in", rec.Code, rec.Header().Get("Location"))
	}
}

func TestGroupRecheckKeepsGuestKind(t *testing.T) {
	srv, sender := guestServer(t)
	ctx := context.Background()
	if err := srv.store.CreateGroup(ctx, "applicants", ""); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv.Handler())
	loginGuest(t, c, sender, "stranger@other.org")
	before := sessionOf(t, srv, c)
	if err := srv.store.AddGroupMember(ctx, "applicants", "stranger@other.org"); err != nil {
		t.Fatal(err)
	}
	if rec := c.get("/verify", requireGroups("applicants")); rec.Code != http.StatusOK {
		t.Fatalf("guest added to group = %d, want 200", rec.Code)
	}
	after := sessionOf(t, srv, c)
	if after.Kind != session.KindGuest {
		t.Errorf("kind = %q, want guest", after.Kind)
	}
	if after.TTL != before.TTL {
		t.Errorf("TTL changed from %d to %d", before.TTL, after.TTL)
	}
}

func TestGroupRecheckSkipsBreakGlass(t *testing.T) {
	srv, _ := testServer(t)
	token := mintCode(t, srv, "Ward 4", "bg_ward")
	c := newClient(t, srv.Handler())
	if rec := c.get("/break/"+token, nil); rec.Code != http.StatusFound {
		t.Fatalf("scan = %d", rec.Code)
	}
	rec := c.get("/verify", requireGroups("bg_other"))
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/denied") {
		t.Fatalf("break-glass on another group = %d %q, want /denied", rec.Code, rec.Header().Get("Location"))
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Errorf("break-glass session renewed or cleared: %q", rec.Header().Get("Set-Cookie"))
	}
	// The card still works on its own group.
	if rec := c.get("/verify", requireGroups("bg_ward")); rec.Code != http.StatusOK {
		t.Errorf("break-glass on its group = %d, want 200", rec.Code)
	}
}

// A database error refuses without renewing.
type groupsReadFails struct{ store.Store }

func (groupsReadFails) GroupsForEmail(context.Context, string) ([]string, error) {
	return nil, errors.New("disk read error")
}

func TestGroupRecheckRefusesOnDatabaseError(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)
	srv.store = groupsReadFails{srv.store}
	rec := c.get("/verify", requireGroups("team"))
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/denied") {
		t.Fatalf("db error = %d %q, want /denied", rec.Code, rec.Header().Get("Location"))
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Errorf("db error issued a cookie: %q", rec.Header().Get("Set-Cookie"))
	}
}

// An unchanged result is remembered, so a repeat refusal does not query.
type countingGroups struct {
	store.Store
	n *int
}

func (c countingGroups) GroupsForEmail(ctx context.Context, email string) ([]string, error) {
	*c.n++
	return c.Store.GroupsForEmail(ctx, email)
}

func TestGroupRecheckRemembersUnchanged(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)
	n := 0
	srv.store = countingGroups{srv.store, &n}
	for i := 0; i < 5; i++ {
		c.get("/verify", requireGroups("finance"))
	}
	if n != 1 {
		t.Errorf("group reads for 5 refusals = %d, want 1", n)
	}
}
