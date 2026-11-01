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

func TestAdminNoticesAreFixedStrings(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)

	if body := c.get("/admin/groups?done=member-added", nil).Body.String(); !strings.Contains(body, "The member has been added.") {
		t.Error("known notice not shown")
	}
	body := c.get("/admin/groups?done=%3Cscript%3Ealert(1)%3C%2Fscript%3E", nil).Body.String()
	if strings.Contains(body, "<script>") || strings.Contains(body, `class="notice`) {
		t.Error("unknown done code rendered something")
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
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.Contains(loc, "done=member-invalid") || !strings.Contains(loc, "open=team") {
		t.Fatalf("bad email = %d %q", rec.Code, loc)
	}
	if members, _ := srv.store.ListGroupMembers(ctx, "team"); len(members) != 0 {
		t.Errorf("bad email stored: %v", members)
	}
	page := c.get("/admin/groups?done=member-invalid&open=team", nil).Body.String()
	if !strings.Contains(page, `class="notice warn"`) || !strings.Contains(page, `id="g-team" open`) {
		t.Error("warning or open group missing")
	}
}

func TestAdminOpenGroupMustExist(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	body := c.get("/admin/groups?open=%22%3E%3Cb%3E", nil).Body.String()
	if strings.Contains(body, "<b>") {
		t.Error("open parameter reflected into the page")
	}
}

func TestRedirectDoneDropsMalformedGroup(t *testing.T) {
	rec := httptestRecorder()
	redirectDone(rec, httptestRequest(), "/admin/groups", "member-added", "bad name\r\nX: y")
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "open=") || strings.Contains(loc, "#") {
		t.Errorf("malformed group carried into Location: %q", loc)
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
