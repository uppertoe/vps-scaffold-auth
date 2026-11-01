package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

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
	tok := extractCSRF(t, c.get("/admin/groups", nil).Body.String())
	rec := c.postForm("/admin/groups/team/members", url.Values{"csrf": {tok}, "email": {"a@example.com"}})
	if loc := rec.Header().Get("Location"); rec.Code != http.StatusFound || !strings.Contains(loc, "open=team") || strings.Contains(loc, "done=") {
		t.Fatalf("add member = %d %q", rec.Code, loc)
	}
	body := c.get("/admin/groups?open=team", nil).Body.String()
	if !strings.Contains(body, "The member has been added.") || !strings.Contains(body, `id="g-team" open`) {
		t.Error("notice or open group missing after the action")
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
	tok := extractCSRF(t, c.get("/admin/groups", nil).Body.String())

	rec := c.postForm("/admin/groups/team/members", url.Values{"csrf": {tok}, "email": {"not an email"}})
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "open=team") {
		t.Fatalf("bad email = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if members, _ := srv.store.ListGroupMembers(ctx, "team"); len(members) != 0 {
		t.Errorf("bad email stored: %v", members)
	}
	if page := c.get("/admin/groups?open=team", nil).Body.String(); !strings.Contains(page, `class="notice warn"`) {
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
	if body := c.get("/admin/groups?open=nope", nil).Body.String(); strings.Contains(body, " open>") {
		t.Error("a group that does not exist caused a group to open")
	}
	if body := c.get("/admin/groups?open=TEAM", nil).Body.String(); !strings.Contains(body, `id="g-team" open`) {
		t.Error("existing group (normalised) not opened")
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
	tok := extractCSRF(t, c.get("/admin/groups", nil).Body.String())
	c.postForm("/admin/groups", url.Values{"csrf": {tok}, "name": {"team"}, "label": {"  " + strings.Repeat("x", 500) + "  "}})
	groups, _ := srv.store.ListGroups(context.Background())
	if len(groups) != 1 || len([]rune(groups[0].Label)) != 200 {
		t.Errorf("label not trimmed and capped: %d runes", len([]rune(groups[0].Label)))
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
