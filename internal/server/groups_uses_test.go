package server

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// The Groups pages name every use of a group other than its roles: the
// groups that include it and the apps that read its members. A group with no
// use at all is marked as not used by any app.
func TestGroupsShowEveryUse(t *testing.T) {
	srv, _, c := appsAdmin(t)
	ctx := context.Background()
	for _, g := range []struct{ name, label string }{{"enquiry-admins", ""}, {"enquiry-users", "Enquiry users"}, {"fellows", "Fellows"}, {"spare", "Spare"}} {
		if err := srv.store.CreateGroup(ctx, g.name, g.label); err != nil {
			t.Fatal(err)
		}
	}
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "user", Kind: store.AssignList, Ref: "enquiry-users"})
	if err := srv.store.AddGroupInclude(ctx, "enquiry-users", "fellows"); err != nil {
		t.Fatal(err)
	}
	srv.cfg.MemberReadersFilePairs = map[string][]string{"enquiries": {"fellows"}}
	page := html.UnescapeString(c.get("/admin/groups", nil).Body.String())
	for _, want := range []string{
		`<a href="/admin/groups/enquiry-users">` + fmt.Sprintf(msgUseIncluded, "Enquiry users") + `</a>`,
		`<a href="` + appFeedsPath + `">` + fmt.Sprintf(msgUseFeed, "Fellowship enquiries") + `</a>`,
		`<a class="noname" href="/admin/groups/enquiry-admins#label-enquiry-admins">` + msgNoNameSet + `</a>`,
		`<code class="slug">enquiry-users</code>`,
		"No domain groups yet.",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the Groups page lacks %q", want)
		}
	}
	// enquiry-admins and spare are unused; the others are not.
	if n := strings.Count(page, "Not used by any app"); n != 2 {
		t.Errorf("%d groups are marked as not used by any app, want 2", n)
	}
	group := html.UnescapeString(c.get("/admin/groups/fellows", nil).Body.String())
	if !strings.Contains(group, "<h2>"+msgOtherUsesHead+"</h2>") || !strings.Contains(group, fmt.Sprintf(msgUseFeed, "Fellowship enquiries")) || !strings.Contains(group, fmt.Sprintf(msgUseIncluded, "Enquiry users")) {
		t.Error("the group page does not list the other uses")
	}
	if strings.Contains(group, "Not used by any app") || strings.Contains(group, `<dd class="none">No roles</dd>`) {
		t.Error("the group page of a used group says it is unused or has no roles")
	}
	if spare := c.get("/admin/groups/spare", nil).Body.String(); !strings.Contains(spare, "Not used by any app") {
		t.Error("the page of an unused group does not say so")
	}
}

func TestGroupLabelEdit(t *testing.T) {
	srv, sender := testServer(t)
	ctx := context.Background()
	if err := srv.store.CreateGroup(ctx, "planka-users", ""); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	tok := extractCSRF(t, c.get("/admin/groups/new", nil).Body.String())

	rec := c.postForm("/admin/groups/planka-users/label", url.Values{"csrf": {tok}, "label": {"  Planka board users  "}})
	if rec.Code != http.StatusFound {
		t.Fatalf("label update = %d, want 302", rec.Code)
	}
	groups, _ := srv.store.ListGroups(ctx)
	if len(groups) != 1 || groups[0].Label != "Planka board users" {
		t.Errorf("groups = %+v", groups)
	}
	events, _ := srv.store.ListAdminEvents(ctx, 10, 0)
	if len(events) == 0 || events[0].Action != store.AdminActionGroupLabel || events[0].Target != "planka-users" {
		t.Errorf("label change not audited: %+v", events)
	}
	if rec := c.postForm("/admin/groups/nope/label", url.Values{"csrf": {tok}, "label": {"x"}}); rec.Code != http.StatusNotFound {
		t.Errorf("label on missing group = %d, want 404", rec.Code)
	}
	if rec := c.postForm("/admin/groups/planka-users/label", url.Values{"label": {"no csrf"}}); rec.Code != http.StatusForbidden {
		t.Errorf("label update without CSRF token = %d, want 403", rec.Code)
	}
	if groups, _ := srv.store.ListGroups(ctx); groups[0].Label != "Planka board users" {
		t.Errorf("label changed without CSRF: %q", groups[0].Label)
	}
}
