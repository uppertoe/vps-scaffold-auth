package server

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// The lists BREAKGLASS_REFUSED_GROUPS names on RCH and MCH in November 2026,
// with the roles each holds as the servers' snippets and design documents
// describe them (rch-server-image apps/air-db, apps/fellows; mch-server-image
// design-docs/the-login-wall.md). Every list the setting names stays closed,
// because the setting is still read; the role rule alone closes every RCH
// list, and on MCH every list but planka-users and cms-editors, which hold
// only User.
var serverLists = []struct {
	server  string
	setting []string
	holds   []store.RoleAssignment
	// byRoles are the lists the role rule closes without the setting.
	byRoles []string
}{
	{
		server:  "RCH",
		setting: []string{"airdb_admin", "prototypes", "fellowship_admin", "planka-admins", "insights-admins"},
		holds: []store.RoleAssignment{
			{App: "air-db", Role: "admin", Ref: "airdb_admin"},
			{App: "air-db", Role: "admin", Ref: "prototypes"},
			{App: "narrator", Role: "user", Ref: "prototypes"},
			{App: "enquiries", Role: "admin", Ref: "fellowship_admin"},
			{App: "planka", Role: "admin", Ref: "planka-admins"},
			{App: "roster-insights", Role: "admin", Ref: "insights-admins"},
		},
		byRoles: []string{"airdb_admin", "fellowship_admin", "insights-admins", "planka-admins", "prototypes"},
	},
	{
		server:  "MCH",
		setting: []string{"planka-admins", "planka-owners", "planka-users", "cms-editors"},
		holds: []store.RoleAssignment{
			{App: "planka", Role: "admin", Ref: "planka-admins"},
			{App: "planka", Role: "owner", Ref: "planka-owners"},
			{App: "planka", Role: "user", Ref: "planka-users"},
			{App: "cms", Role: "user", Ref: "cms-editors"},
		},
		byRoles: []string{"planka-admins", "planka-owners"},
	},
}

// serverListsServer is a server with one server's lists and roles, and the
// setting when withSetting is true.
func serverListsServer(t *testing.T, i int, withSetting bool) *Server {
	t.Helper()
	sl := serverLists[i]
	srv, _ := testServerWith(t, func(c *config.Config) {
		if withSetting {
			c.BreakGlassRefusedGroups = sl.setting
		}
	})
	ctx := context.Background()
	for _, g := range sl.setting {
		if err := srv.store.CreateGroupOfKind(ctx, g, "", store.GroupKindList); err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range sl.holds {
		a.Kind = store.AssignList
		mustAssign(t, srv, a)
	}
	return srv
}

// Every list the setting names on RCH and MCH today is closed under the new
// rule with the setting still read, and the role rule alone closes the lists
// listed in byRoles.
func TestRefusedGroupsSettingStillClosedOnRCHAndMCH(t *testing.T) {
	for i, sl := range serverLists {
		t.Run(sl.server, func(t *testing.T) {
			ctx := context.Background()
			srv := serverListsServer(t, i, true)
			closed, loaded := srv.closedLists(ctx)
			if !loaded {
				t.Fatal("the role data was not read")
			}
			for _, g := range sl.setting {
				if !closed[g] {
					t.Errorf("%s is open with the setting read", g)
				}
				if reason, _ := srv.targetRefusal(ctx, g); reason != refusedAppRole {
					t.Errorf("%s is a card target: reason %q", g, reason)
				}
			}
			alone := serverListsServer(t, i, false)
			closed, _ = alone.closedLists(ctx)
			var got []string
			for g := range closed {
				got = append(got, g)
			}
			sort.Strings(got)
			if !reflect.DeepEqual(got, sl.byRoles) {
				t.Errorf("the role rule alone closes %v, want %v", got, sl.byRoles)
			}
		})
	}
}

// The start log says the setting is deprecated and names each list it closes
// that the role rule does not: on MCH, cms-editors and planka-users.
func TestRefusedGroupsSettingLogsDeprecation(t *testing.T) {
	srv := serverListsServer(t, 1, true)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	srv.logRefusedGroupsDeprecated(context.Background())
	log.SetOutput(os.Stderr)
	out := buf.String()
	for _, want := range []string{"BREAKGLASS_REFUSED_GROUPS is deprecated", "alone closes cms-editors, planka-users,"} {
		if !strings.Contains(out, want) {
			t.Errorf("start log lacks %q:\n%s", want, out)
		}
	}
	rch := serverListsServer(t, 0, true)
	buf.Reset()
	log.SetOutput(&buf)
	rch.logRefusedGroupsDeprecated(context.Background())
	log.SetOutput(os.Stderr)
	if strings.Contains(buf.String(), "alone closes") {
		t.Errorf("RCH's start log names a list the role rule leaves open:\n%s", buf.String())
	}
	none, _ := testServer(t)
	buf.Reset()
	log.SetOutput(&buf)
	none.logRefusedGroupsDeprecated(context.Background())
	log.SetOutput(os.Stderr)
	if buf.Len() != 0 {
		t.Errorf("a server without the setting logs %q", buf.String())
	}
}

// An outsider on a closed list is never counted as its member: not in a
// session, whether a guest's, a member's or a card's, and not by the members
// endpoint. A member of staff on the same list is counted. The Groups page
// marks the outsider as not staff.
func TestOutsiderIsNeverAMemberOfAClosedList(t *testing.T) {
	srv, sender := closedListServer(t, func(c *config.Config) {
		c.OpenRegistrationHosts = []string{"apply.example.com"}
		c.MemberReaders = []config.MemberReader{{App: "digest", Token: digestToken, Groups: []string{"planka-admins", "planka-users"}}}
	})
	srv.members = newMembersAPI(srv.cfg.MemberReaders)
	ctx := context.Background()
	for _, g := range []string{"planka-admins", "planka-users"} {
		// The store takes an outsider directly; the admin pages refuse one.
		if _, err := srv.store.AddGroupMembers(ctx, g, []string{strangerAddr, "staff@example.com"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tier := range []string{authz.RoleGuest, authz.RoleMember} {
		if got := srv.computeGroups(ctx, strangerAddr, tier); got != tier+",planka-users" {
			t.Errorf("an outsider's groups on the %s tier = %q, want %s,planka-users", tier, got, tier)
		}
	}
	if got := srv.computeGroups(ctx, "staff@example.com", authz.RoleUser); got != "user,planka-admins,planka-users" {
		t.Errorf("staff groups = %q", got)
	}
	// The outsider holds Planka's User role through planka-users, so signs
	// in as a member, and never holds Administrator through planka-admins.
	c := newClient(t, srv.Handler())
	loginGuest(t, c, sender, strangerAddr)
	if id := sessionOf(t, srv, c); strings.Contains(","+id.Groups+",", ",planka-admins,") {
		t.Errorf("the outsider's session carries planka-admins: %q", id.Groups)
	}
	testGuardApp(t, srv, "planka")
	if rec := c.get("/verify", roleGuard("planka", "admin")); rec.Code == http.StatusOK {
		t.Error("the outsider holds Planka's Administrator role")
	}
	if rec := membersGet(srv.MembersHandler(), "/v1/groups/planka-admins/members", digestToken, nil); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), strangerAddr) || !strings.Contains(rec.Body.String(), "staff@example.com") {
		t.Errorf("members of planka-admins = %d %s, want staff only", rec.Code, rec.Body)
	}
	admin := newClient(t, srv.Handler())
	loginAs(t, admin, sender, "admin@example.com", nil)
	body := admin.get("/admin/groups/planka-admins", nil).Body.String()
	i := strings.Index(body, "<span>"+strangerAddr)
	if i < 0 || !strings.Contains(body[i:i+400], "not staff") {
		t.Error("the Groups page does not mark the outsider as not staff")
	}
}

// A member who stays signed in loses a list at the next request once the
// list closes, and keeps the roles held another way.
func TestMemberLosesAListAtTheNextRequestOnceItCloses(t *testing.T) {
	srv, sender := closedListServer(t, func(c *config.Config) {
		c.OpenRegistrationHosts = []string{"apply.example.com"}
	})
	ctx := context.Background()
	if _, err := srv.store.AddGroupMembers(ctx, "planka-users", []string{strangerAddr}); err != nil {
		t.Fatal(err)
	}
	testGuardApp(t, srv, "planka")
	testGuardApp(t, srv, "caffeine")
	mustAssign(t, srv, store.RoleAssignment{App: "caffeine", Role: "user", Kind: store.AssignPerson, Ref: strangerAddr, How: store.AssignedByAdmin})
	c := newClient(t, srv.Handler())
	loginGuest(t, c, sender, strangerAddr)
	if rec := c.get("/verify", roleGuard("planka", "")); rec.Code != http.StatusOK {
		t.Fatalf("member on planka-users = %d, want 200", rec.Code)
	}
	mustAssign(t, srv, store.RoleAssignment{App: "planka", Role: "owner", Kind: store.AssignList, Ref: "planka-users"})
	if rec := c.get("/verify", roleGuard("planka", "")); rec.Code == http.StatusOK {
		t.Error("the member still reaches Planka through planka-users once it is closed")
	}
	if rec := c.get("/verify", roleGuard("caffeine", "")); rec.Code != http.StatusOK {
		t.Errorf("the member's role held another way = %d %q, want 200", rec.Code, rec.Header().Get("Location"))
	}
}

// An outsider whose only role comes through a closed list holds no role: the
// sign-in sends no code and shows the same page as for any address that may
// not sign in, rather than signing the person in and ending the session at
// once. An outsider on a list that holds only User still signs in as a member.
func TestOutsiderWithOnlyAClosedListIsSentNoCode(t *testing.T) {
	srv, sender := closedListServer(t, nil)
	ctx := context.Background()
	const closedOnly, openToo = "contractor@partner.org", "visitor@partner.org"
	if _, err := srv.store.AddGroupMembers(ctx, "planka-admins", []string{closedOnly, openToo}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.store.AddGroupMembers(ctx, "planka-users", []string{openToo}); err != nil {
		t.Fatal(err)
	}
	testGuardApp(t, srv, "planka")
	if got := srv.loginRole(ctx, closedOnly, false); got != authz.RoleDeny {
		t.Errorf("loginRole(%s) = %q, want no role", closedOnly, got)
	}
	if got := srv.loginRole(ctx, openToo, false); got != authz.RoleMember {
		t.Errorf("loginRole(%s) = %q, want a member", openToo, got)
	}
	// A session that still carries the closed list gives no reason to stay.
	if srv.mayHoldRoleSnapshot(ctx, &session.Identity{Email: closedOnly, Groups: "guest,planka-admins", Kind: session.KindMember}) {
		t.Error("a closed list in a member's session counts as a reason to sign in")
	}
	sender.reset()
	c := newClient(t, srv.Handler())
	page := c.postForm("/request", url.Values{"email": {closedOnly}})
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), closedOnly) || sentCount(sender) != 0 {
		t.Errorf("request for %s = %d with %d codes sent; want the ordinary page and no code", closedOnly, page.Code, sentCount(sender))
	}
	newClient(t, srv.Handler()).postForm("/request", url.Values{"email": {openToo}})
	if sentCount(sender) != 1 {
		t.Errorf("request for %s sent %d codes, want 1", openToo, sentCount(sender))
	}
}

// An outsider is not added to an open list that a closed list includes,
// directly or through another group, since the closed list would then admit
// them; nor can a card target such a list. Staff are added as usual.
func TestOutsiderRefusedOnAListAClosedListIncludes(t *testing.T) {
	srv, sender := closedListServer(t, nil)
	ctx := context.Background()
	for _, g := range []string{"middle", "inner"} {
		if err := srv.store.CreateGroup(ctx, g, ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := srv.store.AddGroupInclude(ctx, "planka-admins", "middle"); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.AddGroupInclude(ctx, "middle", "inner"); err != nil {
		t.Fatal(err)
	}
	for _, g := range []string{"middle", "inner"} {
		if r, refused := srv.targetRefusal(ctx, g); !refused || r != refusedIncluded {
			t.Errorf("%s: refusal %q %v, want %q", g, r, refused, refusedIncluded)
		}
	}
	if _, refused := srv.targetRefusal(ctx, "bg_ward"); refused {
		t.Error("a list no closed list includes is refused")
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	tok := extractCSRF(t, c.get("/admin/groups/new", nil).Body.String())
	body := c.postForm("/admin/groups/inner/members", url.Values{"csrf": {tok}, "emails": {strangerAddr + "\nstaff@example.com"}}).Body.String()
	if !strings.Contains(body, "Cannot be added (1)") || !strings.Contains(body, refusedIncluded) {
		t.Errorf("the confirmation page does not refuse the outsider:\n%s", body)
	}
	c.postForm("/admin/groups/inner/members/confirm", url.Values{"csrf": {tok}, "add": {strangerAddr, "staff@example.com"}})
	if m, _ := srv.store.ListGroupMembers(ctx, "inner"); len(m) != 1 || m[0] != "staff@example.com" {
		t.Errorf("inner members = %v, want only the staff member", m)
	}
	rec := c.postForm("/admin/break", url.Values{"csrf": {tok}, "label": {"Inner"}, "group": {"inner"}})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("card targeting inner = %d, want 400", rec.Code)
	}
}

// neverLoaded makes every read of the role assignments fail and forgets the
// copy in memory, so the role data has never been read.
func neverLoaded(srv *Server) {
	srv.store = assignmentsReadFail{srv.store}
	srv.roleCache.mu.Lock()
	srv.roleCache.ok, srv.roleCache.have, srv.roleCache.state = false, false, roleState{}
	srv.roleCache.mu.Unlock()
}

// While the role data has never been read, the gateway cannot tell which
// lists are closed, so it fails closed: every group is refused as a card's
// target and for a hand-added outsider, and an include is not kept, while
// staff are still added.
func TestNeverLoadedRefusesTargetsOutsidersAndIncludes(t *testing.T) {
	srv, sender := closedListServer(t, nil)
	ctx := context.Background()
	for _, g := range []string{"collaborators", "staff-list"} {
		if err := srv.store.CreateGroup(ctx, g, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := srv.store.AddGroupMembers(ctx, "collaborators", []string{strangerAddr}); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	tok := extractCSRF(t, c.get("/admin/groups/new", nil).Body.String())
	neverLoaded(srv)

	for _, g := range []string{"bg_ward", "planka-users"} {
		if r, refused := srv.targetRefusal(ctx, g); !refused || r != refusedUnreadable {
			t.Errorf("%s: refusal %q %v, want %q", g, r, refused, refusedUnreadable)
		}
	}
	if rec := c.postForm("/admin/break", url.Values{"csrf": {tok}, "label": {"Ward"}, "group": {"bg_ward"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("card targeting bg_ward = %d, want 400", rec.Code)
	}
	c.postForm("/admin/groups/bg_ward/members/confirm", url.Values{"csrf": {tok}, "add": {strangerAddr, "staff@example.com"}})
	if m, _ := srv.store.ListGroupMembers(ctx, "bg_ward"); len(m) != 1 || m[0] != "staff@example.com" {
		t.Errorf("bg_ward members = %v, want only the staff member", m)
	}
	c.postForm("/admin/groups/staff-list/includes", url.Values{"csrf": {tok}, "included": {"collaborators"}})
	if inc, _ := srv.store.ListGroupIncludes(ctx); len(inc["staff-list"]) != 0 {
		t.Errorf("an include was kept while the role data could not be read: %v", inc["staff-list"])
	}
}
