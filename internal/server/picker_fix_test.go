package server

import (
	"context"
	"fmt"
	"html"
	"strings"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// pickerOf returns one role's picker from the app page, unescaped.
func pickerOf(t *testing.T, page, role string) string {
	t.Helper()
	i := strings.Index(page, `id="pick-`+role+`"`)
	if i < 0 {
		t.Fatalf("the page has no picker for %s", role)
	}
	rest := page[i:]
	if j := strings.Index(rest, `class="pfoot"`); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// With no group, a picker says that none can be chosen and links to the
// Groups page's new-group form; with a group to offer, it has a quiet link
// to the same form instead.
func TestPickerGroupsLine(t *testing.T) {
	srv, _, c := appsAdmin(t)
	noGroups := fmt.Sprintf(msgPickerNoGroups, `<a href="`+newGroupHref+`">`+msgPickerGroupsPage+`</a>`)
	newGroup := `<a href="` + newGroupHref + `">` + msgPickerNewGroup + `</a>`

	page := html.UnescapeString(c.get("/admin/apps/enquiries", nil).Body.String())
	for _, role := range []string{"user", "admin"} {
		p := pickerOf(t, page, role)
		if !strings.Contains(p, noGroups) {
			t.Errorf("with no group, the %s picker lacks %q", role, noGroups)
		}
		if strings.Contains(p, newGroup) {
			t.Errorf("with no group, the %s picker has the New group link", role)
		}
	}

	ctx := context.Background()
	if err := srv.store.CreateGroupOfKind(ctx, "rch-staff", "RCH staff", store.GroupKindDomain); err != nil {
		t.Fatal(err)
	}
	page = html.UnescapeString(c.get("/admin/apps/enquiries", nil).Body.String())
	for _, role := range []string{"user", "admin"} {
		p := pickerOf(t, page, role)
		if !strings.Contains(p, newGroup) {
			t.Errorf("with a group, the %s picker lacks %q", role, newGroup)
		}
		if strings.Contains(p, "No group can be chosen yet") {
			t.Errorf("with a group, the %s picker still says none can be chosen", role)
		}
		if strings.Index(p, newGroup) < strings.Index(p, "RCH staff") {
			t.Errorf("the %s picker's New group link is not at the foot of its groups", role)
		}
	}

	// Once the only group holds the role, the picker has no group to offer.
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "admin", Kind: store.AssignDomainGroup, Ref: "rch-staff"})
	page = html.UnescapeString(c.get("/admin/apps/enquiries", nil).Body.String())
	if !strings.Contains(pickerOf(t, page, "admin"), noGroups) {
		t.Error("a picker whose only group already holds the role does not say that none can be chosen")
	}
}

// The changes bar names the controls by the words on them.
func TestChangesBarNamesTheControls(t *testing.T) {
	srv, _, c := appsAdmin(t)
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "user", Kind: store.AssignGuests})
	page := html.UnescapeString(c.get("/admin/apps/enquiries", nil).Body.String())
	if !strings.Contains(page, ">"+msgChangesNone+"<") {
		t.Errorf("the changes bar lacks %q", msgChangesNone)
	}
	if strings.Contains(page, "plus token") {
		t.Error("the page still mentions the plus token")
	}
	for _, label := range []string{msgGiveToken, msgAddToken} {
		if !strings.Contains(msgChangesNone, label) || !strings.Contains(page, `<span class="l">`+label+`</span>`) {
			t.Errorf("the changes bar and the role rows do not both use %q", label)
		}
	}
}
