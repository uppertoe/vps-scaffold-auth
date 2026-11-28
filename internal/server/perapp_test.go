package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/roles"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"

	"github.com/uppertoe/vps-scaffold-auth/internal/session"
)

// testGuardApp adds an app to the server's app-roles manifest, on the host
// <name>.example.com with a user and an admin role, and turns the model on.
// Tests that only need "a guard that admits a signed-in person" use the
// helpers below rather than writing a manifest of their own.
func testGuardApp(t *testing.T, srv *Server, name string) {
	t.Helper()
	if srv.appRoles.Apps == nil {
		srv.appRoles.Apps = map[string]*roles.App{}
	}
	if srv.cfg.AppRolesFile == "" {
		srv.cfg.AppRolesFile = "test"
	}
	if _, ok := srv.appRoles.Apps[name]; ok {
		return
	}
	srv.appRoles.Apps[name] = &roles.App{
		Name: name, Label: name,
		Roles:     map[string]string{"user": "User", "admin": "Administrator"},
		RoleOrder: []string{"user", "admin"},
		Hosts:     []string{name + ".example.com"},
	}
}

// guardFor is the headers a role guard for app's user role sends.
func guardFor(app string) map[string]string {
	return map[string]string{"X-Auth-App": app, "X-Forwarded-Host": app + ".example.com"}
}

// anyGuard is a role guard whose User role is held by guests, so it admits
// any signed-in person who is not a break-glass card. Its app is on
// any.example.com, which guests holding its role opens to guest sign-in;
// the tests sign in on other hosts.
func anyGuard(t *testing.T, srv *Server) map[string]string {
	t.Helper()
	if _, ok := srv.appRoles.Apps[anyApp]; !ok {
		testGuardApp(t, srv, anyApp)
		mustAssign(t, srv, store.RoleAssignment{App: anyApp, Role: "user", Kind: store.AssignGuests})
	}
	return guardFor(anyApp)
}

// anyApp is anyGuard's app.
const anyApp = "any"

// appForGroup names the app groupGuard makes for the group g.
func appForGroup(g string) string {
	return "g-" + strings.NewReplacer("_", "-", " ", "-").Replace(g)
}

// groupGuard is a role guard whose User role is held by the list group g,
// which it creates when there is none.
func groupGuard(t *testing.T, srv *Server, g string) map[string]string {
	t.Helper()
	name := appForGroup(g)
	if _, ok := srv.appRoles.Apps[name]; !ok {
		ctx := context.Background()
		gs, err := srv.store.ListGroups(ctx)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, have := range gs {
			found = found || have.Name == g
		}
		if !found {
			if err := srv.store.CreateGroup(ctx, g, ""); err != nil {
				t.Fatal(err)
			}
		}
		testGuardApp(t, srv, name)
		mustAssign(t, srv, store.RoleAssignment{App: name, Role: "user", Kind: store.AssignList, Ref: g})
	}
	return guardFor(name)
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

	if rec := c.get("/verify", groupGuard(t, srv, "dashboard")); rec.Code != http.StatusOK {
		t.Fatalf("member of required group = %d, want 200", rec.Code)
	}
	if rec := c.get("/verify", groupGuard(t, srv, "finance")); rec.Code != http.StatusFound {
		t.Fatalf("not in required group = %d, want 302 (denied)", rec.Code)
	}
}

// A denial must not disturb the session: the user keeps access to apps they
// are allowed on, and the denial page offers a working sign-in link.
func TestDeniedPreservesSessionAndOffersLogin(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)

	// Bounce off an app whose role the user does not hold.
	if rec := c.get("/verify", groupGuard(t, srv, "finance")); rec.Code != http.StatusFound {
		t.Fatalf("expected 302 denied, got %d", rec.Code)
	}
	// Session cookie is untouched...
	if c.cookies[session.SessionCookie] == nil {
		t.Fatal("denial cleared the session cookie")
	}
	// ...so a plain app still grants.
	if rec := c.get("/verify", anyGuard(t, srv)); rec.Code != http.StatusOK {
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

// Break-glass is deny-by-default: a role given to guests does not admit it,
// nor another app's role; only its card's app does.
func TestBreakGlassScopedToItsGroup(t *testing.T) {
	srv, _ := testServer(t)
	token := mintCode(t, srv, "Angiography Lab 1", "bg_stroke")
	c := newClient(t, srv.Handler())
	if rec := c.scan(token); rec.Code != http.StatusFound {
		t.Fatalf("scan = %d", rec.Code)
	}

	// A role held by guests (any signed-in person) -> break-glass denied.
	if rec := c.get("/verify", anyGuard(t, srv)); rec.Code != http.StatusFound {
		t.Fatalf("break-glass on a role held by guests = %d, want 302 (denied)", rec.Code)
	}
	// An app requiring a different group -> denied.
	if rec := c.get("/verify", groupGuard(t, srv, "bg_other")); rec.Code != http.StatusFound {
		t.Fatalf("break-glass wrong group = %d, want 302 (denied)", rec.Code)
	}
	// The route that opts into this code's group -> allowed.
	rec := c.get("/verify", groupGuard(t, srv, "bg_stroke"))
	if rec.Code != http.StatusOK {
		t.Fatalf("break-glass on its own route = %d, want 200", rec.Code)
	}
	if g := rec.Header().Get("Remote-Roles"); g != "user" {
		t.Errorf("Remote-Roles = %q, want user", g)
	}

	// The denial page names the card and the app it opens.
	body := c.get("/denied?rd="+url.QueryEscape("https://app.example.com/"), nil).Body.String()
	if !strings.Contains(body, "The card for Angiography Lab 1 opens g-bg-stroke only.") {
		t.Errorf("break-glass denial page missing the card and its app:\n%s", body)
	}
}

// A guard that names no app (a hand-rolled one, or an older guard left in a
// snippet) is denied, whatever else it sends, while a role guard admits.
func TestGuardWithNoAppFailsClosed(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)

	for _, h := range []map[string]string{nil, {"X-Auth-Policy": "any"}, {"X-Auth-Policy": "domains=example.com"}} {
		wantDenied(t, fmt.Sprintf("a guard with no app, %v", h), c.get("/verify", h))
	}
	if rec := c.get("/verify", anyGuard(t, srv)); rec.Code != http.StatusOK {
		t.Fatalf("role guard = %d, want 200", rec.Code)
	}
	// An older guard sends a policy and does not delete a client's
	// X-Auth-App, so a request naming an app beside a policy may carry the
	// client's own choice of app: it is refused, signed in or not.
	forged := anyGuard(t, srv)
	forged["X-Auth-Policy"] = "groups=admin"
	wantDenied(t, "an app beside a policy", c.get("/verify", forged))
	if rec := newClient(t, srv.Handler()).get("/verify", forged); rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/login?") {
		t.Errorf("an app beside a policy, no session = %d %q, want sign in", rec.Code, rec.Header().Get("Location"))
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

	if rec := c.get("/verify", groupGuard(t, srv, "planka-users")); rec.Code != http.StatusFound {
		t.Fatalf("before joining = %d, want 302 (denied)", rec.Code)
	}
	// An administrator adds them on the Groups page, which also clears the
	// remembered "unchanged" result from the refusal just above.
	admin := newClient(t, srv.Handler())
	loginAs(t, admin, sender, "admin@example.com", nil)
	tok := extractCSRF(t, admin.get("/admin/groups/new", nil).Body.String())
	if rec := admin.postForm("/admin/groups/planka-users/members", url.Values{"csrf": {tok}, "email": {"user@example.com"}}); rec.Code != http.StatusFound {
		t.Fatalf("admin add member = %d", rec.Code)
	}
	rec := c.get("/verify", groupGuard(t, srv, "planka-users"))
	if rec.Code != http.StatusOK {
		t.Fatalf("after joining = %d, want 200", rec.Code)
	}
	if !strings.Contains(sessionOf(t, srv, c).Groups, "planka-users") {
		t.Errorf("groups = %q, want planka-users", sessionOf(t, srv, c).Groups)
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), session.SessionCookie+"=") {
		t.Error("renewed session cookie not issued")
	}
	// The renewed cookie now carries the group, so the next request passes
	// without another lookup.
	if rec := c.get("/verify", groupGuard(t, srv, "planka-users")); rec.Code != http.StatusOK {
		t.Fatalf("next request = %d, want 200", rec.Code)
	}
}

// A refusal with unchanged groups issues no cookie, so a person repeatedly
// refused does not slide their session forward.
func TestGroupGateRefusalWithUnchangedGroupsKeepsCookie(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)

	rec := c.get("/verify", groupGuard(t, srv, "finance"))
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
	// The domain group loses its role and the person is added to the group.
	unseedStaff(t, srv)
	if err := srv.store.AddGroupMember(ctx, "team", "user@example.com"); err != nil {
		t.Fatal(err)
	}
	rec := c.get("/verify", groupGuard(t, srv, "team"))
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/login") {
		t.Fatalf("revoked principal = %d %q, want a redirect to sign in", rec.Code, rec.Header().Get("Location"))
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Error("revoked principal's session not cleared")
	}
}

// Someone promoted to administrator since signing in keeps their session and
// reaches a group just given to them, but without the admin tier: that needs
// the second step at the admin door.
func TestGroupRecheckGivesNewAdminNoAdminTier(t *testing.T) {
	srv, sender := testServerWith(t, func(c *config.Config) { c.TOTPEnabled = true })
	ctx := context.Background()
	if err := srv.store.CreateGroup(ctx, "team", ""); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)
	srv.policy = authz.NewPolicy([]string{"admin@example.com", "user@example.com"})
	if err := srv.store.AddGroupMember(ctx, "team", "user@example.com"); err != nil {
		t.Fatal(err)
	}
	rec := c.get("/verify", groupGuard(t, srv, "team"))
	if rec.Code != http.StatusOK || authz.HasGroup(sessionOf(t, srv, c).Groups, "admin") {
		t.Fatalf("new admin on a group route = %d groups=%q, want 200 without admin", rec.Code, sessionOf(t, srv, c).Groups)
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
	if rec := c.get("/verify", groupGuard(t, srv, "applicants")); rec.Code != http.StatusOK {
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
	if rec := c.scan(token); rec.Code != http.StatusFound {
		t.Fatalf("scan = %d", rec.Code)
	}
	rec := c.get("/verify", groupGuard(t, srv, "bg_other"))
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/denied") {
		t.Fatalf("break-glass on another group = %d %q, want /denied", rec.Code, rec.Header().Get("Location"))
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Errorf("break-glass session renewed or cleared: %q", rec.Header().Get("Set-Cookie"))
	}
	// The card still works on its own group.
	if rec := c.get("/verify", groupGuard(t, srv, "bg_ward")); rec.Code != http.StatusOK {
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
	rec := c.get("/verify", groupGuard(t, srv, "team"))
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
		c.get("/verify", groupGuard(t, srv, "finance"))
	}
	if n != 1 {
		t.Errorf("group reads for 5 refusals = %d, want 1", n)
	}
}

// Someone refused a group route while signed in with a username address
// (no dot before the "@") is told the app needs their firstname.lastname
// address; someone signed in with such an address sees the ordinary line.
func TestDeniedPageHintsAtNameAddress(t *testing.T) {
	srv, sender := testServer(t)
	for _, tc := range []struct {
		email string
		hint  bool
	}{{"upperteam@example.com", true}, {"646332@example.com", true}, {"joe.bloggs@example.com", false}} {
		c := newClient(t, srv.Handler())
		loginAs(t, c, sender, tc.email, nil)
		body := c.get("/denied?rd=https://app.example.com/", nil).Body.String()
		got := strings.Contains(body, "This app needs your email address in the form firstname.lastname, such as joe.bloggs@example.com.")
		if got != tc.hint {
			t.Errorf("%s: hint shown = %v, want %v", tc.email, got, tc.hint)
		}
	}
}
