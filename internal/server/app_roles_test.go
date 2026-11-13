package server

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

const testAppRoles = "caffeine\tuser\tUser\tcaffeine.{$DOMAIN}\n" +
	"caffeine\tadmin\tAdministrator\tcaffeine.{$DOMAIN}\n" +
	"enquiries\tuser\tUser\tenquiries.{$DOMAIN}\n" +
	"enquiries\tadmin\tAdministrator\tenquiries.{$DOMAIN}\n" +
	"nd\tuser\tUser\tnd.{$DOMAIN}\n" +
	"orphan\tadmin\tAdministrator\torphan.{$DOMAIN}\n" // no user role: left out

// rolesServer is the standard test server with the app-roles manifest above
// and, when networks is not empty, NETWORK_RANGES. The test client connects
// from 10.0.0.1.
func rolesServer(t *testing.T, networks string) (*Server, *captureSender) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app-roles.tsv")
	if err := os.WriteFile(path, []byte(testAppRoles), 0o600); err != nil {
		t.Fatal(err)
	}
	ranges, err := config.ParseNetworkRanges(networks)
	if err != nil {
		t.Fatal(err)
	}
	return testServerWith(t, func(c *config.Config) {
		c.AppRolesFile = path
		c.NetworkRanges = ranges
	})
}

func roleGuard(app, role string) map[string]string {
	h := map[string]string{"X-Auth-App": app}
	if role != "" {
		h["X-Auth-Role"] = role
	}
	return h
}

func mustAssign(t *testing.T, srv *Server, a store.RoleAssignment) {
	t.Helper()
	if err := srv.store.AddRoleAssignment(context.Background(), a); err != nil {
		t.Fatalf("assign %+v: %v", a, err)
	}
	srv.forgetRoles()
}

func mustDomainGroup(t *testing.T, srv *Server, name string, domains ...string) {
	t.Helper()
	ctx := context.Background()
	if err := srv.store.CreateGroupOfKind(ctx, name, "", store.GroupKindDomain); err != nil {
		t.Fatal(err)
	}
	for _, d := range domains {
		if err := srv.store.AddGroupDomain(ctx, name, d); err != nil {
			t.Fatal(err)
		}
	}
}

func wantDenied(t *testing.T, what string, rec interface {
	Result() *http.Response
}) {
	t.Helper()
	res := rec.Result()
	if res.StatusCode != http.StatusFound || !strings.Contains(res.Header.Get("Location"), "/denied?rd=") {
		t.Errorf("%s: status %d to %q, want a redirect to /denied", what, res.StatusCode, res.Header.Get("Location"))
	}
}

func TestRoleGuardDomainGroup(t *testing.T) {
	srv, sender := rolesServer(t, "")
	mustDomainGroup(t, srv, "staff", "example.com")
	mustAssign(t, srv, store.RoleAssignment{App: "caffeine", Role: "user", Kind: store.AssignDomainGroup, Ref: "staff"})
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)

	rec := c.get("/verify", roleGuard("caffeine", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("user role by domain = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Remote-Roles"); got != "user" {
		t.Errorf("Remote-Roles = %q, want user", got)
	}
	if got := rec.Header().Get("Remote-Email"); got != "user@example.com" {
		t.Errorf("Remote-Email = %q", got)
	}
	wantDenied(t, "admin role not held", c.get("/verify", roleGuard("caffeine", "admin")))
	wantDenied(t, "another app", c.get("/verify", roleGuard("enquiries", "")))
}

func TestRoleGuardRefusesMisconfiguredGuards(t *testing.T) {
	srv, sender := rolesServer(t, "")
	mustDomainGroup(t, srv, "staff", "example.com")
	mustAssign(t, srv, store.RoleAssignment{App: "caffeine", Role: "user", Kind: store.AssignDomainGroup, Ref: "staff"})
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)

	wantDenied(t, "unknown app", c.get("/verify", roleGuard("nope", "")))
	wantDenied(t, "undeclared role", c.get("/verify", roleGuard("caffeine", "editor")))
	wantDenied(t, "app without a user role", c.get("/verify", roleGuard("orphan", "admin")))
	both := roleGuard("caffeine", "")
	both["X-Auth-Policy"] = "any"
	wantDenied(t, "app and policy together", c.get("/verify", both))
	wantDenied(t, "role and policy together", c.get("/verify", map[string]string{"X-Auth-Role": "user", "X-Auth-Policy": "any"}))
	// The legacy guard is unchanged.
	if rec := c.get("/verify", protectedAny()); rec.Code != http.StatusOK {
		t.Errorf("legacy guard = %d, want 200", rec.Code)
	}
}

func TestRoleGuardRefusedWhenModelOff(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)
	wantDenied(t, "no manifest", c.get("/verify", roleGuard("caffeine", "")))
}

func TestAnyRoleAdmitsTheUserRole(t *testing.T) {
	srv, sender := rolesServer(t, "")
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "admin", Kind: store.AssignPerson, Ref: "user@example.com", How: store.AssignedByAdmin})
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)
	for _, role := range []string{"", "admin"} {
		rec := c.get("/verify", roleGuard("enquiries", role))
		if rec.Code != http.StatusOK {
			t.Fatalf("role %q = %d, want 200", role, rec.Code)
		}
		if got := rec.Header().Get("Remote-Roles"); got != "admin" {
			t.Errorf("Remote-Roles = %q, want admin", got)
		}
	}
}

func TestRoleGuardNetworkWithoutSession(t *testing.T) {
	srv, _ := rolesServer(t, "rch=10.0.0.0/8")
	mustAssign(t, srv, store.RoleAssignment{App: "nd", Role: "user", Kind: store.AssignNetwork, Ref: "rch"})
	c := newClient(t, srv.Handler())

	rec := c.get("/verify", roleGuard("nd", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("inside the network = %d, want 200", rec.Code)
	}
	if rec.Header().Get("Remote-User") != "" || rec.Header().Get("Remote-Email") != "" {
		t.Errorf("identity sent for a request with no session: %v", rec.Header())
	}
	if got := rec.Header().Get("Remote-Roles"); got != "user" {
		t.Errorf("Remote-Roles = %q, want user", got)
	}
	// Caddy appends the real peer, so a client's own X-Forwarded-For entry
	// cannot place it inside the network.
	h := roleGuard("nd", "")
	h["X-Forwarded-For"] = "10.1.1.1, 203.0.113.9"
	rec = c.get("/verify", h)
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/login?") {
		t.Errorf("outside the network = %d to %q, want a redirect to sign in", rec.Code, rec.Header().Get("Location"))
	}
	// A role the network does not hold still needs a sign-in.
	mustAssign(t, srv, store.RoleAssignment{App: "caffeine", Role: "user", Kind: store.AssignGuests})
	if rec := c.get("/verify", roleGuard("caffeine", "")); rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/login?") {
		t.Errorf("no network role = %d to %q, want sign in", rec.Code, rec.Header().Get("Location"))
	}
	wantDenied(t, "unknown app without a session", c.get("/verify", roleGuard("nope", "")))
}

func TestRoleGuardBreakGlassCard(t *testing.T) {
	srv, _ := rolesServer(t, "")
	ctx := context.Background()
	mustDomainGroup(t, srv, "everyone", "example.com")
	mustAssign(t, srv, store.RoleAssignment{App: "caffeine", Role: "user", Kind: store.AssignDomainGroup, Ref: "everyone"})
	token := mintCode(t, srv, "Lab 1", "bg_lab")
	codes, err := srv.store.ListBreakGlassCodes(ctx)
	if err != nil || len(codes) != 1 {
		t.Fatalf("codes = %v, %v", codes, err)
	}
	if err := srv.store.SetBreakGlassRole(ctx, codes[0].ID, "nd", "user"); err != nil {
		t.Fatal(err)
	}
	srv.forgetRoles()
	c := newClient(t, srv.Handler())
	if rec := c.scan(token); rec.Code != http.StatusFound {
		t.Fatalf("scan = %d, want 302", rec.Code)
	}
	rec := c.get("/verify", roleGuard("nd", ""))
	if rec.Code != http.StatusOK || rec.Header().Get("Remote-Roles") != "user" {
		t.Fatalf("card's own app = %d, roles %q; want 200, user", rec.Code, rec.Header().Get("Remote-Roles"))
	}
	wantDenied(t, "card on another app", c.get("/verify", roleGuard("caffeine", "")))

	// A card that still targets a group opens no role.
	legacy := mintCode(t, srv, "Lab 2", "bg_lab2")
	srv.forgetRoles()
	c2 := newClient(t, srv.Handler())
	c2.scan(legacy)
	wantDenied(t, "group card on a role guard", c2.get("/verify", roleGuard("nd", "")))
}

func TestSignInByRole(t *testing.T) {
	srv, sender := rolesServer(t, "")
	ctx := context.Background()
	now := time.Now()
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "admin", Kind: store.AssignPerson, Ref: "p@partner.org", How: store.AssignedByInvite, Until: now.Add(24 * time.Hour)})
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "admin", Kind: store.AssignPerson, Ref: "old@partner.org", How: store.AssignedByInvite, Until: now.Add(-time.Hour)})
	if err := srv.store.CreateGroup(ctx, "exec", ""); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.AddGroupMember(ctx, "exec", "x@partner.org"); err != nil {
		t.Fatal(err)
	}
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "user", Kind: store.AssignList, Ref: "exec"})
	mustAssign(t, srv, store.RoleAssignment{App: "caffeine", Role: "user", Kind: store.AssignGuests})

	cases := []struct {
		email string
		want  string
	}{
		{"user@example.com", authz.RoleUser},   // the allow-list, as before
		{"p@partner.org", authz.RoleMember},    // a current person assignment
		{"x@partner.org", authz.RoleMember},    // a list assigned to a role
		{"old@partner.org", authz.RoleDeny},    // an ended assignment
		{"nobody@partner.org", authz.RoleDeny}, // a guests role is not a reason to sign in
	}
	for _, c := range cases {
		if got := srv.loginRole(ctx, c.email, false); got != c.want {
			t.Errorf("loginRole(%q) = %q, want %q", c.email, got, c.want)
		}
	}

	// A person outside the allow-list signs in, keeps the session across
	// requests, and holds the role.
	cl := newClient(t, srv.Handler())
	loginAs(t, cl, sender, "p@partner.org", nil)
	for i := 0; i < 2; i++ {
		rec := cl.get("/verify", roleGuard("enquiries", "admin"))
		if rec.Code != http.StatusOK || rec.Header().Get("Remote-Roles") != "admin" {
			t.Fatalf("request %d: %d, roles %q; want 200, admin", i, rec.Code, rec.Header().Get("Remote-Roles"))
		}
	}
	wantDenied(t, "a role-only person on a legacy domain guard", cl.get("/verify", requireDomains("example.com")))

	// With the model off, a role does not let an address sign in.
	off, _ := testServer(t)
	if err := off.store.AddRoleAssignment(ctx, store.RoleAssignment{App: "enquiries", Role: "admin", Kind: store.AssignPerson, Ref: "p@partner.org", How: store.AssignedByAdmin}); err != nil {
		t.Fatal(err)
	}
	if got := off.loginRole(ctx, "p@partner.org", false); got != authz.RoleDeny {
		t.Errorf("model off: loginRole = %q, want deny", got)
	}
}

// Remote-Roles lists every role held, separated by commas, as the apps split it.
func TestRemoteRolesAreCommaSeparated(t *testing.T) {
	srv, sender := rolesServer(t, "")
	for _, role := range []string{"admin", "user"} {
		mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: role, Kind: store.AssignPerson, Ref: "user@example.com", How: store.AssignedByAdmin})
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)
	rec := c.get("/verify", roleGuard("enquiries", ""))
	if got := rec.Header().Get("Remote-Roles"); got != "admin,user" {
		t.Errorf("Remote-Roles = %q, want admin,user", got)
	}
}

// A gateway administrator without a recent second step holds no app role
// above user: an admin route sends them to the admin door, and a user route
// shows the app the user role only, as the older groups=admin guard did. A
// person who holds the role but is not a gateway administrator is unaffected.
func TestAppAdminRoleNeedsTheAdminStep(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app-roles.tsv")
	if err := os.WriteFile(path, []byte(testAppRoles), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, sender := testServerWith(t, func(c *config.Config) {
		c.AppRolesFile = path
		c.TOTPEnabled = true
		c.AdminEmails = []string{"admin@example.com"}
	})
	for _, who := range []string{"admin@example.com", "user@example.com"} {
		mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "admin", Kind: store.AssignPerson, Ref: who, How: store.AssignedByAdmin})
	}
	admin := newClient(t, srv.Handler())
	loginAs(t, admin, sender, "admin@example.com", nil)
	if rec := admin.get("/verify", roleGuard("enquiries", "admin")); !strings.Contains(rec.Header().Get("Location"), "/totp?rd=") {
		t.Errorf("admin without the step on the admin role = %d %q, want the admin door", rec.Code, rec.Header().Get("Location"))
	}
	rec := admin.get("/verify", roleGuard("enquiries", ""))
	if rec.Code != http.StatusOK || rec.Header().Get("Remote-Roles") != "user" {
		t.Errorf("admin without the step on a user route = %d, roles %q; want 200, user", rec.Code, rec.Header().Get("Remote-Roles"))
	}
	other := newClient(t, srv.Handler())
	loginAs(t, other, sender, "user@example.com", nil)
	if rec := other.get("/verify", roleGuard("enquiries", "admin")); rec.Code != http.StatusOK || rec.Header().Get("Remote-Roles") != "admin" {
		t.Errorf("non-gateway-admin holder = %d, roles %q; want 200, admin", rec.Code, rec.Header().Get("Remote-Roles"))
	}
}
