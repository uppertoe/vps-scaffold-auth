package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// staffServer is a server shaped like the department's: app roles, route
// manifests with application-role lists, a refused list in the settings, a
// feed, a members reader, an open host, and a domain group "staff" carrying
// example.com and holding caffeine's User role. With allowList,
// ALLOWED_EMAIL_DOMAINS is example.com, as before; without it the setting is
// empty and the domain group stands in. A second domain group, "partner",
// carries partner.org, which the allow-list does not name, and holds no
// role.
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
		c.BreakGlassRefusedGroups = []string{"insights-admins", "rch-consultants"}
		c.OpenRegistrationHosts = []string{"apply.example.com"}
		if feedURL != "" {
			c.GroupFeeds = []config.GroupFeed{{Group: "rch-consultants", URL: feedURL, Token: testFeedToken}}
		}
	})
	mustDomainGroup(t, srv, "staff", "example.com")
	mustDomainGroup(t, srv, "partner", "partner.org")
	mustAssign(t, srv, store.RoleAssignment{App: "caffeine", Role: "user", Kind: store.AssignDomainGroup, Ref: "staff"})
	return srv, sender
}

// partnerRole gives the partner domain group caffeine's User role, or takes
// it away, through the store, and forgets the cached role data as the app
// page does.
func partnerRole(t *testing.T, srv *Server, give bool) {
	t.Helper()
	a := store.RoleAssignment{App: "caffeine", Role: "user", Kind: store.AssignDomainGroup, Ref: "partner"}
	if give {
		mustAssign(t, srv, a)
		return
	}
	if err := srv.store.RemoveRoleAssignment(context.Background(), a.App, a.Role, a.Kind, a.Ref); err != nil {
		t.Fatal(err)
	}
	srv.forgetRoles()
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
		}
		for _, c := range cases {
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
		// A domain group that holds no role knows nobody.
		if got := srv.knownRole(ctx, "x@partner.org"); got != authz.RoleDeny {
			t.Errorf("knownRole(x@partner.org) with no role = %q, want deny", got)
		}
		// Given a role, it knows its domain at once, but only without the
		// allow-list; taking the role away reverses it at once.
		partnerRole(t, srv, true)
		want := authz.RoleDeny
		if !allowList {
			want = authz.RoleUser
		}
		if got := srv.knownRole(ctx, "x@partner.org"); got != want {
			t.Errorf("knownRole(x@partner.org) with a role = %q, want %q", got, want)
		}
		partnerRole(t, srv, false)
		if got := srv.knownRole(ctx, "x@partner.org"); got != authz.RoleDeny {
			t.Errorf("knownRole(x@partner.org) after the role is removed = %q, want deny", got)
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
// a role guard, and is suggested the staff domain; a stranger on
// the open host is still a guest. Without the allow-list, removing the domain
// group's last role ends the staff session at its next request.
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
		if rec := c.get("/verify", anyGuard(t, srv)); rec.Code != http.StatusOK {
			t.Errorf("staff on a role guard = %d, want 200", rec.Code)
		}

		g := newClient(t, srv.Handler())
		loginGuest(t, g, sender, strangerAddr)
		if id := sessionOf(t, srv, g); id.Kind != session.KindGuest || !strings.HasPrefix(id.Groups, authz.RoleGuest) {
			t.Errorf("stranger session = kind %q groups %q, want a guest", id.Kind, id.Groups)
		}

		if allowList {
			return
		}
		if err := srv.store.RemoveRoleAssignment(context.Background(), "caffeine", "user", store.AssignDomainGroup, "staff"); err != nil {
			t.Fatal(err)
		}
		srv.forgetRoles()
		rec := c.get("/verify", anyGuard(t, srv))
		if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/login") {
			t.Errorf("after the domain group's last role is removed: %d to %q, want sign-in", rec.Code, rec.Header().Get("Location"))
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
	partnerRole(t, srv, true)
	if err := srv.store.RemoveGroupDomain(ctx, "staff", "example.com"); err != nil {
		t.Fatal(err)
	}
	srv.forgetRoles()
	m.get("/verify", anyGuard(t, srv))
	if id := sessionOf(t, srv, m); id.Kind != "" || !strings.HasPrefix(id.Groups, authz.RoleUser) {
		t.Errorf("after its domain joined a domain group: kind %q groups %q, want an ordinary session", id.Kind, id.Groups)
	}
	s.get("/verify", anyGuard(t, srv))
	if id := sessionOf(t, srv, s); id.Kind != session.KindMember || !strings.HasPrefix(id.Groups, authz.RoleGuest) {
		t.Errorf("after its domain left every domain group: kind %q groups %q, want a member", id.Kind, id.Groups)
	}
}

// A guest session stays a stranger's: when the guest's domain later becomes
// a staff domain, the session still loses the lists closed to outsiders until its person
// signs in again.
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
			partnerRole(t, srv, true)
		}
		if !srv.known(ctx, addr) {
			t.Fatal("the address should now be staff")
		}
		wantDenied(t, "a guest on a list closed to outsiders", c.get("/verify", groupGuard(t, srv, "prototypes")))
		if rec := c.get("/verify", groupGuard(t, srv, "planka-users")); rec.Code != http.StatusOK {
			t.Errorf("a guest on an ordinary list it is in = %d, want 200", rec.Code)
		}
		if id := sessionOf(t, srv, c); id.Kind != session.KindGuest {
			t.Errorf("session kind = %q, want guest", id.Kind)
		}
	})
}

// A feed list closed to outsiders is dropped from a person's session once
// their domain stops being a staff domain, before the next sync takes them
// off it, and from any session on the guest tier.
func TestFeedListStrippedAfterItsDomainGoes(t *testing.T) {
	var body atomic.Value
	var hits atomic.Int32
	body.Store(`["amy@example.com","bob@example.com"]`)
	ts := feedEndpoint(t, &body, &hits)
	srv, _ := staffServer(t, false, ts.URL)
	ctx := context.Background()
	if st, err := srv.syncFeed(ctx, "rch-consultants", "group feed", ""); err != nil || st.Status != store.GroupSyncOK {
		t.Fatalf("sync = %+v, %v", st, err)
	}
	if got := srv.computeGroups(ctx, "amy@example.com", authz.RoleUser); got != "user,rch-consultants" {
		t.Fatalf("staff groups = %q", got)
	}
	if got := srv.computeGroups(ctx, "amy@example.com", authz.RoleGuest); got != "guest" {
		t.Errorf("guest-tier groups = %q, want guest only", got)
	}
	if err := srv.store.RemoveRoleAssignment(ctx, "caffeine", "user", store.AssignDomainGroup, "staff"); err != nil {
		t.Fatal(err)
	}
	srv.forgetRoles()
	if got := srv.computeGroups(ctx, "amy@example.com", authz.RoleUser); got != "user" {
		t.Errorf("after the domain stopped being staff: groups = %q, want the feed list dropped", got)
	}
}

// The staff domains are those of the domain groups that hold a role, in
// the order the groups were made, oldest first, and within a group in the
// group's own order; a group with no role is never hinted.
func TestStaffFromGroupsOrder(t *testing.T) {
	at := func(sec int64) time.Time { return time.Unix(sec, 0) }
	groups := []store.Group{
		{Name: "mcri-staff", Kind: store.GroupKindDomain, CreatedAt: at(200)},
		{Name: "rch-staff", Kind: store.GroupKindDomain, CreatedAt: at(100)},
		{Name: "idle", Kind: store.GroupKindDomain, CreatedAt: at(50)},
		{Name: "exec", Kind: store.GroupKindList, CreatedAt: at(10)},
	}
	domains := map[string][]string{"mcri-staff": {"mcri.edu.au"}, "rch-staff": {"rch.org.au", "rch.vic.gov.au"}, "idle": {"idle.org"}}
	as := []store.RoleAssignment{
		{App: "a", Role: "user", Kind: store.AssignDomainGroup, Ref: "mcri-staff"},
		{App: "b", Role: "admin", Kind: store.AssignDomainGroup, Ref: "rch-staff"},
		{App: "a", Role: "user", Kind: store.AssignList, Ref: "exec"},
		{App: "gone", Role: "user", Kind: store.AssignDomainGroup, Ref: "idle"},
	}
	declared := func(app, role string) bool { return app == "a" || app == "b" }
	staff, order, rank := staffFromGroups(groups, domains, as, declared)
	if want := []string{"rch.org.au", "rch.vic.gov.au", "mcri.edu.au"}; !reflect.DeepEqual(order, want) {
		t.Errorf("order = %v, want %v", order, want)
	}
	if staff["idle.org"] {
		t.Error("a domain group with no role makes its domain staff")
	}
	if rank["idle.org"] != 0 || rank["mcri.edu.au"] != 3 {
		t.Errorf("rank = %v", rank)
	}
}

// Creating a domain group, giving it a role, taking the role away and
// deleting the group each apply at once, without waiting for the role
// cache, and the other administrators are emailed about the group.
func TestDomainGroupChangesApplyAtOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app-roles.tsv")
	if err := os.WriteFile(path, []byte(testAppRolesWithPaths), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, sender := testServerWith(t, func(c *config.Config) {
		c.AllowedDomains = nil
		c.AppRolesFile = path
		c.AdminEmails = []string{"admin@example.com", "boss@example.com"}
	})
	ctx := context.Background()
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	tok := csrfOf(t, c, "/admin/groups/new")
	prime := func() { srv.roleData(ctx) }

	prime()
	sender.reset()
	rec := c.postForm("/admin/groups", url.Values{"csrf": {tok}, "from": {"new"}, "kind": {"domain"}, "label": {"Monash staff"}, "domains": {"monash.edu"}})
	if rec.Code != http.StatusFound {
		t.Fatalf("create = %d", rec.Code)
	}
	if st := srv.roleData(ctx); len(st.domains["monash-staff"]) != 1 {
		t.Errorf("the new group is not in the role data at once: %v", st.domains)
	}
	mail := noticesAfter(sender, 1)
	if len(mail) != 1 || mail[0].To != "boss@example.com" || !strings.Contains(mail[0].Text, "Added the domain @monash.edu") {
		t.Errorf("create emails = %+v", mail)
	}
	if srv.known(ctx, "x@monash.edu") {
		t.Error("a domain group with no role makes its domain staff")
	}

	clearNotices(sender, 0)
	prime()
	rec = c.postForm("/admin/apps/enquiries/save", url.Values{"csrf": {csrfOf(t, c, "/admin/apps/enquiries")}, "c": {"give|user|domain_group|monash-staff|0"}})
	if rec.Code != http.StatusFound {
		t.Fatalf("give = %d", rec.Code)
	}
	if !srv.known(ctx, "x@monash.edu") {
		t.Error("giving the group a role did not make its domain staff at once")
	}
	prime()
	rec = c.postForm("/admin/apps/enquiries/save", url.Values{"csrf": {csrfOf(t, c, "/admin/apps/enquiries")}, "c": {"take|user|domain_group|monash-staff|0"}})
	if rec.Code != http.StatusFound {
		t.Fatalf("take = %d", rec.Code)
	}
	if srv.known(ctx, "x@monash.edu") {
		t.Error("taking the role away did not end staff status at once")
	}

	prime()
	clearNotices(sender, 2)
	rec = c.postForm("/admin/groups/monash-staff/delete", url.Values{"csrf": {tok}})
	if rec.Code != http.StatusFound {
		t.Fatalf("delete = %d", rec.Code)
	}
	if st := srv.roleData(ctx); st.domains["monash-staff"] != nil {
		t.Errorf("the deleted group is still in the role data: %v", st.domains)
	}
	mail = noticesAfter(sender, 1)
	if len(mail) != 1 || !strings.Contains(mail[0].Text, "Deleted the group, which included @monash.edu") {
		t.Errorf("delete emails = %+v", mail)
	}
}

// assignmentsReadFail fails every read of the role assignments.
type assignmentsReadFail struct{ store.Store }

func (assignmentsReadFail) ListRoleAssignments(context.Context, string) ([]store.RoleAssignment, error) {
	return nil, errors.New("disk read error")
}

// Without the allow-list, while the role data has never been read the
// gateway keeps every session, answers 503, sends no code, returns 503 from
// the members endpoint, fails a feed sync and says so at start; once the
// data can be read, the same session works.
func TestRoleDataNeverLoaded(t *testing.T) {
	var body atomic.Value
	var hits atomic.Int32
	body.Store(`["amy@example.com"]`)
	ts := feedEndpoint(t, &body, &hits)
	srv, sender := staffServer(t, false, ts.URL)
	ctx := context.Background()
	srv.members = newMembersAPI([]config.MemberReader{{App: "digest", Token: digestToken, Groups: []string{"coordinators"}}})
	if err := srv.store.CreateGroup(ctx, "coordinators", ""); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.AddGroupMember(ctx, "coordinators", "amy@example.com"); err != nil {
		t.Fatal(err)
	}
	if st, err := srv.syncFeed(ctx, "rch-consultants", "group feed", ""); err != nil || st.Status != store.GroupSyncOK {
		t.Fatalf("sync = %+v, %v", st, err)
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "amy@example.com", nil)

	good := srv.store
	srv.store = assignmentsReadFail{good}
	srv.roleCache.mu.Lock()
	srv.roleCache.ok, srv.roleCache.have, srv.roleCache.state = false, false, roleState{}
	srv.roleCache.mu.Unlock()

	rec := c.get("/verify", anyGuard(t, srv))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Set-Cookie") != "" {
		t.Errorf("verify = %d, cookie %q; want 503 and the session kept", rec.Code, rec.Header().Get("Set-Cookie"))
	}
	// The page is served on the app's host, so its link names the gateway.
	if !strings.Contains(rec.Body.String(), `href="https://auth.example.com/login?rd=`) {
		t.Errorf("the 503 page's link is not absolute:\n%s", rec.Body.String())
	}
	if rec := membersGet(srv.MembersHandler(), "/v1/groups/coordinators/members", digestToken, nil); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("members = %d %s, want 503", rec.Code, rec.Body)
	}
	sender.reset()
	o := newClient(t, srv.Handler())
	if rec := o.postForm("/request", url.Values{"email": {"amy@example.com"}, "rd": {openHostRD}}); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("request = %d, want 503", rec.Code)
	}
	sender.mu.Lock()
	sent := sender.last
	sender.mu.Unlock()
	if sent != nil {
		t.Error("a code was sent while the gateway could not tell who is staff")
	}
	if st, _ := srv.syncFeed(ctx, "rch-consultants", "group feed", ""); st.Status == store.GroupSyncOK {
		t.Errorf("feed sync = %+v, want a failure", st)
	}
	if got := members(t, srv); !reflect.DeepEqual(got, []string{"amy@example.com"}) {
		t.Errorf("feed members = %v, want them kept", got)
	}
	var buf bytes.Buffer
	log.SetOutput(&buf)
	srv.logWhoSignsIn(ctx)
	log.SetOutput(os.Stderr)
	if !strings.Contains(buf.String(), "could not be read") || strings.Contains(buf.String(), "no domain group") {
		t.Errorf("start log = %q", buf.String())
	}

	srv.store = good
	srv.forgetRoles()
	if rec := c.get("/verify", anyGuard(t, srv)); rec.Code != http.StatusOK {
		t.Errorf("verify once the data can be read = %d, want 200", rec.Code)
	}
}

// clearNotices waits for want notices (the asynchronous emails to the other
// administrators), then forgets every notice so far.
func clearNotices(s *captureSender, want int) {
	noticesAfter(s, want)
	s.mu.Lock()
	s.notices = nil
	s.mu.Unlock()
}

// A domain-group assignment for an app or role the manifest no longer
// declares makes nobody staff.
func TestUndeclaredAssignmentMakesNobodyStaff(t *testing.T) {
	srv, _ := staffServer(t, false, "")
	ctx := context.Background()
	mustAssign(t, srv, store.RoleAssignment{App: "removed", Role: "user", Kind: store.AssignDomainGroup, Ref: "partner"})
	mustAssign(t, srv, store.RoleAssignment{App: "caffeine", Role: "editor", Kind: store.AssignDomainGroup, Ref: "partner"})
	if srv.known(ctx, "x@partner.org") {
		t.Error("an assignment the manifest does not declare makes its domain staff")
	}
	if got := srv.staffDomains(ctx); slices.Contains(got, "partner.org") {
		t.Errorf("staff domains = %v", got)
	}
	partnerRole(t, srv, true)
	if !srv.known(ctx, "x@partner.org") {
		t.Error("a declared role does not make the domain staff")
	}
}
