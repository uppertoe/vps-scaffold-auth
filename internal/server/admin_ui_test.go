package server

import (
	"context"
	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

func TestAdminHomeOverview(t *testing.T) {
	srv, sender := routeGroupsServer(t, testRouteGroups)
	ctx := context.Background()
	if err := srv.store.CreateGroup(ctx, "old-group", ""); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.AddGroupMember(ctx, "old-group", "a@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.store.CreateBreakGlassCode(ctx, store.BreakGlassCode{Label: "Ward", TargetGroup: "bg_ward", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	rec := c.get("/admin/", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("overview = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"planka-users", "prototypes", "old-group", `aria-current="page">Overview`, "admin@example.com"} {
		if !strings.Contains(body, want) {
			t.Errorf("overview missing %q", want)
		}
	}
	// A break-glass target needs no group, so it is not reported as missing.
	if strings.Contains(body, "bg_ward") {
		t.Error("card-only group reported as missing")
	}
}

func TestAdminNoticeComesFromTheActionNotTheURL(t *testing.T) {
	srv, sender := testServer(t)
	ctx := context.Background()
	if err := srv.store.CreateGroup(ctx, "team", ""); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)

	// A crafted link cannot show a confirmation.
	if body := c.get("/admin/groups?done=member-added", nil).Body.String(); strings.Contains(body, `class="notice`) {
		t.Error("?done= in the URL produced a notice")
	}
	// A real action does, once.
	tok := extractCSRF(t, c.get("/admin/groups/new", nil).Body.String())
	rec := c.postForm("/admin/groups/team/members", url.Values{"csrf": {tok}, "email": {"a@example.com"}})
	if loc := rec.Header().Get("Location"); rec.Code != http.StatusFound || loc != "/admin/groups/team" {
		t.Fatalf("add member = %d %q", rec.Code, loc)
	}
	body := c.get("/admin/groups/team", nil).Body.String()
	if !strings.Contains(body, "The member has been added.") || !strings.Contains(body, `action="/admin/groups/team/label"`) {
		t.Error("notice or group page missing after the action")
	}
	if body := c.get("/admin/groups", nil).Body.String(); strings.Contains(body, `class="notice`) {
		t.Error("notice shown a second time")
	}
}

func TestAdminAddMemberRefusesBadEmailWithWarning(t *testing.T) {
	srv, sender := testServer(t)
	ctx := context.Background()
	if err := srv.store.CreateGroup(ctx, "team", ""); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	tok := extractCSRF(t, c.get("/admin/groups/new", nil).Body.String())

	rec := c.postForm("/admin/groups/team/members", url.Values{"csrf": {tok}, "email": {"not an email"}})
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/admin/groups/team" {
		t.Fatalf("bad email = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if members, _ := srv.store.ListGroupMembers(ctx, "team"); len(members) != 0 {
		t.Errorf("bad email stored: %v", members)
	}
	if page := c.get("/admin/groups/team", nil).Body.String(); !strings.Contains(page, `class="notice warn"`) {
		t.Error("warning missing")
	}
}

func TestAdminOpenGroupMustExist(t *testing.T) {
	srv, sender := testServer(t)
	if err := srv.store.CreateGroup(context.Background(), "team", ""); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	if rec := c.get("/admin/groups/nope", nil); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/admin/groups" {
		t.Errorf("a group that does not exist = %d %q, want a redirect to the list", rec.Code, rec.Header().Get("Location"))
	}
	if rec := c.get("/admin/groups?open=nope", nil); rec.Code != http.StatusOK {
		t.Errorf("an old link to a missing group = %d, want the list", rec.Code)
	}
	// An old link (?open=) goes to the group's own page, name normalised.
	if rec := c.get("/admin/groups?open=TEAM", nil); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/admin/groups/team" {
		t.Errorf("old link to an existing group = %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestRedirectDoneDropsMalformedGroup(t *testing.T) {
	srv, _ := testServer(t)
	rec := httptestRecorder()
	srv.redirectDone(rec, httptestRequest(), "/admin/groups", "member-added", "bad name\r\nX: y")
	if loc := rec.Header().Get("Location"); loc != "/admin/groups" {
		t.Errorf("malformed group carried into Location: %q", loc)
	}
}

func TestCreateGroupCapsLabel(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	tok := extractCSRF(t, c.get("/admin/groups/new", nil).Body.String())
	c.postForm("/admin/groups", url.Values{"csrf": {tok}, "name": {"team"}, "label": {"  " + strings.Repeat("x", 500) + "  "}})
	groups, _ := srv.store.ListGroups(context.Background())
	if len(groups) != 1 {
		t.Fatalf("groups = %+v, want one", groups)
	}
	if n := len([]rune(groups[0].Label)); n != 200 {
		t.Errorf("label not trimmed and capped: %d runes", n)
	}
}

func TestAuditShowsReadableActions(t *testing.T) {
	srv, sender := testServer(t)
	if err := srv.store.RecordAdminEvent(context.Background(), store.AdminEvent{Actor: "admin@example.com", Action: store.AdminActionGroupAddMember, Target: "team"}); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	if body := c.get("/admin/audit", nil).Body.String(); !strings.Contains(body, "Member added") {
		t.Error("readable action label missing")
	}
}

func httptestRecorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }
func httptestRequest() *http.Request {
	return httptest.NewRequest(http.MethodPost, "/admin/groups/x/members", nil)
}

func TestNoticeCookieAttributesWithTLS(t *testing.T) {
	srv, _ := testServerWith(t, func(c *config.Config) { c.CookieInsecure = false })
	rec := httptestRecorder()
	srv.redirectDone(rec, httptestRequest(), "/admin/groups", "member-added", "team")
	ck := rec.Result().Cookies()
	if len(ck) != 1 {
		t.Fatalf("cookies = %d, want 1", len(ck))
	}
	c := ck[0]
	if c.Name != "__Host-admin_notice" || !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" || c.SameSite != http.SameSiteStrictMode {
		t.Errorf("notice cookie = %+v", c)
	}
}

func TestLogoutClearsNotice(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	rec := c.postForm("/logout", url.Values{})
	if !strings.Contains(strings.Join(rec.Header().Values("Set-Cookie"), "\n"), "admin_notice=;") {
		t.Errorf("logout did not clear the notice cookie: %q", rec.Header().Values("Set-Cookie"))
	}
}

func TestMembershipChangesClearGroupRecheck(t *testing.T) {
	srv, sender := testServer(t)
	ctx := context.Background()
	for _, g := range []string{"a", "b"} {
		if err := srv.store.CreateGroup(ctx, g, ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := srv.store.AddGroupMember(ctx, "a", "x@example.com"); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	tok := extractCSRF(t, c.get("/admin/groups/new", nil).Body.String())
	for _, step := range []struct {
		path string
		form url.Values
	}{
		{"/admin/groups/a/members/delete", url.Values{"csrf": {tok}, "email": {"x@example.com"}}},
		{"/admin/groups/b/delete", url.Values{"csrf": {tok}}},
	} {
		now := srv.now()
		srv.groupRecheck.confirm("y@example.com", "user", now, srv.groupRecheck.generation())
		c.postForm(step.path, step.form)
		if srv.groupRecheck.fresh("y@example.com", "user", now) {
			t.Errorf("%s did not clear the remembered refusal", step.path)
		}
	}
}

func TestGroupRecheckIgnoresStaleRead(t *testing.T) {
	g := newGroupRecheck()
	now := time.Now()
	gen := g.generation()
	g.forgetAll() // an admin changed a membership mid-read
	g.confirm("y@example.com", "user", now, gen)
	if g.fresh("y@example.com", "user", now) {
		t.Error("a read that raced a membership change was cached")
	}
}

func TestPlainAddress(t *testing.T) {
	for _, ok := range []string{"a@example.com", "jane.citizen+x@rch.org.au"} {
		if !plainAddress(ok) {
			t.Errorf("refused %q", ok)
		}
	}
	for _, bad := range []string{"a‮@x.org", "a@x.org​", "а@rch.org.au", "a@ｘ.org", "a@[127.0.0.1]", "a@localhost"} {
		if plainAddress(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}
