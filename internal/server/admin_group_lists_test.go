package server

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

func adminWithGroups(t *testing.T, groups ...string) (*Server, *client, string) {
	t.Helper()
	srv, sender := testServer(t)
	for _, g := range groups {
		if err := srv.store.CreateGroup(context.Background(), g, ""); err != nil {
			t.Fatal(err)
		}
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	return srv, c, extractCSRF(t, c.get("/admin/groups/new", nil).Body.String())
}

func TestBulkAddShowsConfirmationThenAddsTicked(t *testing.T) {
	srv, c, tok := adminWithGroups(t, "team")
	ctx := context.Background()
	if err := srv.store.AddGroupMember(ctx, "team", "old@example.com"); err != nil {
		t.Fatal(err)
	}
	paste := "Jane Citizen <Jane@Example.com>, old@example.com; bad@\nstranger@other.org\n jane@example.com"
	rec := c.postForm("/admin/groups/team/members", url.Values{"csrf": {tok}, "emails": {paste}})
	if rec.Code != http.StatusOK {
		t.Fatalf("paste = %d, want the confirmation page", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `value="stranger@other.org">`) {
		t.Error("an address not on the allow-list should start unticked")
	}
	for _, want := range []string{"To be added (2)", `value="jane@example.com"`, `value="stranger@other.org"`, "not on the allow-list", "Already members (1)", "Not email addresses (1)", "bad@"} {
		if !strings.Contains(body, want) {
			t.Errorf("confirmation page missing %q", want)
		}
	}
	if strings.Contains(body, "Citizen") {
		t.Error("a display-name word was treated as an address")
	}
	if m, _ := srv.store.ListGroupMembers(ctx, "team"); len(m) != 1 {
		t.Fatalf("members changed before confirmation: %v", m)
	}
	// Confirm with only one address ticked.
	rec = c.postForm("/admin/groups/team/members/confirm", url.Values{"csrf": {tok}, "add": {"jane@example.com"}})
	if rec.Code != http.StatusFound {
		t.Fatalf("confirm = %d", rec.Code)
	}
	m, _ := srv.store.ListGroupMembers(ctx, "team")
	if want := []string{"jane@example.com", "old@example.com"}; !reflect.DeepEqual(m, want) {
		t.Errorf("members = %v, want %v", m, want)
	}
	events, _ := srv.store.ListAdminEvents(ctx, 10, 0)
	if len(events) == 0 || events[0].Action != store.AdminActionGroupAddMember || events[0].Detail != "jane@example.com" {
		t.Errorf("bulk add not audited per address: %+v", events)
	}
}

func TestSingleValidAddressIsAddedDirectly(t *testing.T) {
	srv, c, tok := adminWithGroups(t, "team")
	rec := c.postForm("/admin/groups/team/members", url.Values{"csrf": {tok}, "emails": {"a@example.com"}})
	if rec.Code != http.StatusFound {
		t.Fatalf("single add = %d, want a redirect", rec.Code)
	}
	if m, _ := srv.store.ListGroupMembers(context.Background(), "team"); len(m) != 1 {
		t.Errorf("members = %v", m)
	}
}

func TestGroupListRoutesNeedCSRFAndRealGroups(t *testing.T) {
	_, c, tok := adminWithGroups(t, "team", "other")
	for _, p := range []string{"/admin/groups/team/members", "/admin/groups/team/members/confirm", "/admin/groups/team/includes", "/admin/groups/team/includes/delete"} {
		if rec := c.postForm(p, url.Values{"emails": {"a@example.com"}, "add": {"a@example.com"}, "included": {"other"}}); rec.Code != http.StatusForbidden {
			t.Errorf("%s without CSRF = %d, want 403", p, rec.Code)
		}
	}
	if rec := c.postForm("/admin/groups/nope/members", url.Values{"csrf": {tok}, "emails": {"a@example.com"}}); rec.Code != http.StatusNotFound {
		t.Errorf("add to missing group = %d, want 404", rec.Code)
	}
	if rec := c.postForm("/admin/groups/team/includes", url.Values{"csrf": {tok}, "included": {"nope"}}); rec.Code != http.StatusNotFound {
		t.Errorf("include of missing group = %d, want 404", rec.Code)
	}
}

func TestIncludedGroupAdmitsThroughGate(t *testing.T) {
	srv, admin, tok := adminWithGroups(t, "planka-users", "rch-consultants")
	ctx := context.Background()
	if err := srv.store.AddGroupMember(ctx, "rch-consultants", "user@example.com"); err != nil {
		t.Fatal(err)
	}
	if rec := admin.postForm("/admin/groups/planka-users/includes", url.Values{"csrf": {tok}, "included": {"rch-consultants"}}); rec.Code != http.StatusFound {
		t.Fatalf("include = %d", rec.Code)
	}
	// The user signs in afterwards and reaches a route that needs planka-users.
	u := newClient(t, srv.Handler())
	loginAs(t, u, srv.sender.(*captureSender), "user@example.com", nil)
	rec := u.get("/verify", requireGroups("planka-users"))
	if rec.Code != http.StatusOK {
		t.Fatalf("member of an included group = %d, want 200", rec.Code)
	}
	if g := rec.Header().Get("Remote-Groups"); !strings.Contains(g, "planka-users") || !strings.Contains(g, "rch-consultants") {
		t.Errorf("Remote-Groups = %q", g)
	}
	// A cycle is refused with a warning.
	if rec := admin.postForm("/admin/groups/rch-consultants/includes", url.Values{"csrf": {tok}, "included": {"planka-users"}}); rec.Code != http.StatusFound {
		t.Fatalf("cycle include = %d", rec.Code)
	}
	if body := admin.get("/admin/groups", nil).Body.String(); !strings.Contains(body, "would make a group include itself") {
		t.Error("cycle warning not shown")
	}
}
