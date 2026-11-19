package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// staffServer is a server shaped like the department's: app roles, route
// manifests with application-role lists, a refused list in the settings, a
// feed, a members reader, an open host, and a domain group "staff" carrying
// example.com. With allowList, ALLOWED_EMAIL_DOMAINS is example.com, as
// before; without it the setting is empty and the domain group stands in.
// A second domain group, "partner", carries partner.org, which the
// allow-list does not name.
func staffServer(t *testing.T, allowList bool, feedURL string) (*Server, *captureSender) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	rolesFile := write("app-roles.tsv", testAppRoles)
	groups := write("route-groups.tsv", appRoleRouteGroups)
	access := write("route-access.tsv", appRoleRouteAccess)
	srv, sender := testServerWith(t, func(c *config.Config) {
		if !allowList {
			c.AllowedDomains = nil
		}
		c.AppRolesFile = rolesFile
		c.RouteGroupsFile = groups
		c.RouteAccessFile = access
		c.BreakGlassRefusedGroups = []string{"insights-admins"}
		c.OpenRegistrationHosts = []string{"apply.example.com"}
		if feedURL != "" {
			c.GroupFeeds = []config.GroupFeed{{Group: "rch-consultants", URL: feedURL, Token: testFeedToken}}
		}
	})
	mustDomainGroup(t, srv, "staff", "example.com")
	mustDomainGroup(t, srv, "partner", "partner.org")
	srv.forgetRoles()
	return srv, sender
}

// bothWays runs a check with ALLOWED_EMAIL_DOMAINS set and with it empty, so
// each place that asks whether an address is staff is shown to answer the
// same way in both.
func bothWays(t *testing.T, check func(t *testing.T, allowList bool)) {
	for _, allowList := range []bool{true, false} {
		name := "allow-list set"
		if !allowList {
			name = "allow-list empty"
		}
		t.Run(name, func(t *testing.T) { check(t, allowList) })
	}
}

// Who is known: an administrator, an address at a staff domain; not a
// stranger, and not a person who only holds a role (a member) or signs in on
// an open host (a guest).
func TestKnownWithAndWithoutAllowList(t *testing.T) {
	bothWays(t, func(t *testing.T, allowList bool) {
		srv, _ := staffServer(t, allowList, "")
		ctx := context.Background()
		mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "user", Kind: store.AssignPerson, Ref: "p@elsewhere.org", How: store.AssignedByAdmin})
		cases := []struct {
			email           string
			known, login    string
			loginOnOpenHost string
		}{
			{"admin@example.com", authz.RoleAdmin, authz.RoleAdmin, authz.RoleAdmin},
			{"amy@example.com", authz.RoleUser, authz.RoleUser, authz.RoleUser},
			{"AMY@Example.com", authz.RoleUser, authz.RoleUser, authz.RoleUser},
			{strangerAddr, authz.RoleDeny, authz.RoleDeny, authz.RoleGuest},
			{"p@elsewhere.org", authz.RoleDeny, authz.RoleMember, authz.RoleMember},
			{"@example.com", authz.RoleDeny, authz.RoleDeny, authz.RoleDeny},
		}
		for _, c := range cases {
			if c.email == "@example.com" && allowList {
				continue // the allow-list's own parsing, unchanged here
			}
			if got := srv.knownRole(ctx, c.email); got != c.known {
				t.Errorf("knownRole(%q) = %q, want %q", c.email, got, c.known)
			}
			if got := srv.loginRole(ctx, c.email, false); got != c.login {
				t.Errorf("loginRole(%q) = %q, want %q", c.email, got, c.login)
			}
			if got := srv.loginRole(ctx, c.email, true); got != c.loginOnOpenHost {
				t.Errorf("loginRole(%q) on the open host = %q, want %q", c.email, got, c.loginOnOpenHost)
			}
		}
		// A domain group outside the allow-list adds no one while the
		// allow-list is set; without it, the domain group decides.
		want := authz.RoleDeny
		if !allowList {
			want = authz.RoleUser
		}
		if got := srv.knownRole(ctx, "x@partner.org"); got != want {
			t.Errorf("knownRole(x@partner.org) = %q, want %q", got, want)
		}
	})
}

// Without the allow-list and with the app-roles model off, the domain groups
// count for nothing: only the administrators can sign in.
func TestDomainGroupsNeedTheRolesModel(t *testing.T) {
	srv, _ := testServerWith(t, func(c *config.Config) { c.AllowedDomains = nil })
	mustDomainGroup(t, srv, "staff", "example.com")
	srv.forgetRoles()
	ctx := context.Background()
	if got := srv.loginRole(ctx, "amy@example.com", false); got != authz.RoleDeny {
		t.Errorf("loginRole(amy) with the model off = %q, want deny", got)
	}
	if got := srv.loginRole(ctx, "admin@example.com", false); got != authz.RoleAdmin {
		t.Errorf("loginRole(admin) = %q, want admin", got)
	}
}

// A member of staff signs in as an ordinary session (not a member), reaches
// a plain `protected` app, and is suggested the staff domain; a stranger on
// the open host is still a guest. Without the allow-list, deleting the
// domain group ends the staff session at its next request.
func TestSignInWithAndWithoutAllowList(t *testing.T) {
	bothWays(t, func(t *testing.T, allowList bool) {
		srv, sender := staffServer(t, allowList, "")
		if page := newClient(t, srv.Handler()).get("/login", nil).Body.String(); !strings.Contains(page, "This page is for <strong>example.com") {
			t.Error("the sign-in page does not suggest the staff domain")
		}

		c := newClient(t, srv.Handler())
		loginAs(t, c, sender, "amy@example.com", nil)
		if id := sessionOf(t, srv, c); id.Kind != "" || !strings.HasPrefix(id.Groups, authz.RoleUser) {
			t.Fatalf("staff session = kind %q groups %q, want an ordinary user session", id.Kind, id.Groups)
		}
		if rec := c.get("/verify", protectedAny()); rec.Code != http.StatusOK {
			t.Errorf("staff on a plain protected app = %d, want 200", rec.Code)
		}

		g := newClient(t, srv.Handler())
		loginGuest(t, g, sender, strangerAddr)
		if id := sessionOf(t, srv, g); id.Kind != session.KindGuest || !strings.HasPrefix(id.Groups, authz.RoleGuest) {
			t.Errorf("stranger session = kind %q groups %q, want a guest", id.Kind, id.Groups)
		}
		wantDenied(t, "a guest on a plain protected app", g.get("/verify", protectedAny()))

		if allowList {
			return
		}
		if err := srv.store.DeleteGroup(context.Background(), "staff"); err != nil {
			t.Fatal(err)
		}
		srv.forgetRoles()
		rec := c.get("/verify", protectedAny())
		if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/login") {
			t.Errorf("after the domain group is deleted: %d to %q, want sign-in", rec.Code, rec.Header().Get("Location"))
		}
	})
}

// A feed keeps the addresses of staff and skips strangers and anything that
// is not a plain address.
func TestFeedKeepsStaffWithAndWithoutAllowList(t *testing.T) {
	bothWays(t, func(t *testing.T, allowList bool) {
		var body atomic.Value
		var hits atomic.Int32
		body.Store(`["a@example.com","B@example.com","` + strangerAddr + `","not-an-email","admin@example.com"]`)
		ts := feedEndpoint(t, &body, &hits)
		srv, _ := staffServer(t, allowList, ts.URL)
		st, err := srv.syncFeed(context.Background(), "rch-consultants", "group feed", "")
		if err != nil || st.Status != store.GroupSyncOK {
			t.Fatalf("sync = %+v, %v", st, err)
		}
		if got := members(t, srv); !reflect.DeepEqual(got, []string{"a@example.com", "admin@example.com", "b@example.com"}) {
			t.Errorf("members = %v, want the staff and the administrator only", got)
		}
		if !strings.Contains(st.Detail, "2 entries were skipped") {
			t.Errorf("detail = %q", st.Detail)
		}
	})
}

// The members endpoint returns staff and leaves out a stranger kept on the
// list.
func TestMembersEndpointWithAndWithoutAllowList(t *testing.T) {
	bothWays(t, func(t *testing.T, allowList bool) {
		srv, _ := staffServer(t, allowList, "")
		srv.members = newMembersAPI([]config.MemberReader{{App: "digest", Token: digestToken, Groups: []string{"coordinators"}}})
		ctx := context.Background()
		if err := srv.store.CreateGroup(ctx, "coordinators", ""); err != nil {
			t.Fatal(err)
		}
		for _, e := range []string{"amy@example.com", strangerAddr, "admin@example.com"} {
			if err := srv.store.AddGroupMember(ctx, "coordinators", e); err != nil {
				t.Fatal(err)
			}
		}
		rec := membersGet(srv.MembersHandler(), "/v1/groups/coordinators/members", digestToken, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("read = %d %s", rec.Code, rec.Body)
		}
		var got struct {
			Members []string `json:"members"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		slices.Sort(got.Members)
		if !reflect.DeepEqual(got.Members, []string{"admin@example.com", "amy@example.com"}) {
			t.Errorf("members = %v, want the staff and the administrator", got.Members)
		}
	})
}

// A list that the settings or a manifest close to outsiders is dropped from
// a stranger's and a member's groups, and kept in a member of staff's.
func TestRefusedListsStrippedWithAndWithoutAllowList(t *testing.T) {
	bothWays(t, func(t *testing.T, allowList bool) {
		srv, _ := staffServer(t, allowList, "")
		ctx := context.Background()
		mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "user", Kind: store.AssignPerson, Ref: "p@elsewhere.org", How: store.AssignedByAdmin})
		for _, g := range []string{"prototypes", "insights-admins", "planka-users"} {
			if err := srv.store.CreateGroup(ctx, g, ""); err != nil {
				t.Fatal(err)
			}
			for _, e := range []string{"amy@example.com", strangerAddr, "p@elsewhere.org"} {
				if err := srv.store.AddGroupMember(ctx, g, e); err != nil {
					t.Fatal(err)
				}
			}
		}
		if got := srv.computeGroups(ctx, "amy@example.com", authz.RoleUser); got != "user,insights-admins,planka-users,prototypes" {
			t.Errorf("staff groups = %q", got)
		}
		for _, e := range []string{strangerAddr, "p@elsewhere.org"} {
			if got := srv.computeGroups(ctx, e, authz.RoleGuest); got != "guest,planka-users" {
				t.Errorf("%s groups = %q, want guest,planka-users", e, got)
			}
		}
	})
}

// The Groups page marks a stranger, and not a member of staff, as not staff.
func TestGroupsPageMarksWithAndWithoutAllowList(t *testing.T) {
	bothWays(t, func(t *testing.T, allowList bool) {
		srv, sender := staffServer(t, allowList, "")
		ctx := context.Background()
		if err := srv.store.CreateGroup(ctx, "reviewers", ""); err != nil {
			t.Fatal(err)
		}
		for _, e := range []string{"amy@example.com", strangerAddr} {
			if err := srv.store.AddGroupMember(ctx, "reviewers", e); err != nil {
				t.Fatal(err)
			}
		}
		c := newClient(t, srv.Handler())
		loginAs(t, c, sender, "admin@example.com", nil)
		body := c.get("/admin/groups/reviewers", nil).Body.String()
		if n := strings.Count(body, ">not staff</span>"); n != 1 {
			t.Fatalf("want one mark, got %d", n)
		}
		i := strings.Index(body, "<span>"+strangerAddr)
		if i < 0 || !strings.Contains(body[i:i+400], "not staff") {
			t.Error("the mark is not in the stranger's row")
		}
	})
}

// Without the allow-list, a member whose domain a domain group takes on
// becomes an ordinary session at the next request, and a member of staff
// whose domain leaves every domain group but who still holds a role becomes
// a member.
func TestDomainGroupChangesTheTierAtTheNextRequest(t *testing.T) {
	srv, sender := staffServer(t, false, "")
	ctx := context.Background()
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "user", Kind: store.AssignPerson, Ref: "p@elsewhere.org", How: store.AssignedByAdmin})
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "user", Kind: store.AssignPerson, Ref: "amy@example.com", How: store.AssignedByAdmin})

	m := newClient(t, srv.Handler())
	loginAs(t, m, sender, "p@elsewhere.org", nil)
	if id := sessionOf(t, srv, m); id.Kind != session.KindMember {
		t.Fatalf("p@elsewhere.org signed in as kind %q, want a member", id.Kind)
	}
	s := newClient(t, srv.Handler())
	loginAs(t, s, sender, "amy@example.com", nil)

	if err := srv.store.AddGroupDomain(ctx, "partner", "elsewhere.org"); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.RemoveGroupDomain(ctx, "staff", "example.com"); err != nil {
		t.Fatal(err)
	}
	srv.forgetRoles()
	m.get("/verify", protectedAny())
	if id := sessionOf(t, srv, m); id.Kind != "" || !strings.HasPrefix(id.Groups, authz.RoleUser) {
		t.Errorf("after its domain joined a domain group: kind %q groups %q, want an ordinary session", id.Kind, id.Groups)
	}
	s.get("/verify", protectedAny())
	if id := sessionOf(t, srv, s); id.Kind != session.KindMember || !strings.HasPrefix(id.Groups, authz.RoleGuest) {
		t.Errorf("after its domain left every domain group: kind %q groups %q, want a member", id.Kind, id.Groups)
	}
}

// A guest session stays a stranger's: when the guest's domain later becomes
// a staff domain, the session still loses the lists closed to outsiders, and
// is still kept off a plain protected app, until its person signs in again.
func TestGuestStaysAGuestWhenItsDomainBecomesStaff(t *testing.T) {
	bothWays(t, func(t *testing.T, allowList bool) {
		srv, sender := staffServer(t, allowList, "")
		ctx := context.Background()
		const addr = "visitor@newdomain.org"
		for _, g := range []string{"prototypes", "planka-users"} {
			if err := srv.store.CreateGroup(ctx, g, ""); err != nil {
				t.Fatal(err)
			}
			if err := srv.store.AddGroupMember(ctx, g, addr); err != nil {
				t.Fatal(err)
			}
		}
		c := newClient(t, srv.Handler())
		loginGuest(t, c, sender, addr)
		if allowList {
			srv.policy = authz.NewPolicy([]string{"example.com", "newdomain.org"}, srv.cfg.AdminEmails)
		} else {
			if err := srv.store.AddGroupDomain(ctx, "partner", "newdomain.org"); err != nil {
				t.Fatal(err)
			}
			srv.forgetRoles()
		}
		if !srv.known(ctx, addr) {
			t.Fatal("the address should now be staff")
		}
		wantDenied(t, "a guest on a list closed to outsiders", c.get("/verify", requireGroups("prototypes")))
		if rec := c.get("/verify", requireGroups("planka-users")); rec.Code != http.StatusOK {
			t.Errorf("a guest on an ordinary list it is in = %d, want 200", rec.Code)
		}
		wantDenied(t, "a guest on a plain protected app", c.get("/verify", protectedAny()))
		if id := sessionOf(t, srv, c); id.Kind != session.KindGuest {
			t.Errorf("session kind = %q, want guest", id.Kind)
		}
	})
}
