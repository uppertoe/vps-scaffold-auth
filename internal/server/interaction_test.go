package server

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// postApp posts the app page's form to one of its actions and returns the
// status and the page, unescaped.
func postApp(t *testing.T, c *client, action string, form url.Values) (int, string) {
	t.Helper()
	form.Set("csrf", csrfOf(t, c, "/admin/apps/enquiries"))
	rec := c.postForm("/admin/apps/enquiries/"+action, form)
	return rec.Code, html.UnescapeString(rec.Body.String())
}

// A person added in a role's picker, as a token on the row ("p.<role>") or
// as typed ("pa.<role>", "pu.<role>"), goes through the same review and
// save as the groups, once each.
func TestPickerPeopleAreReviewedAndSaved(t *testing.T) {
	srv, _, c := appsAdmin(t)
	day := srv.now().AddDate(0, 2, 0).In(srv.tzloc()).Format("2006-01-02")
	code, page := postApp(t, c, "review", url.Values{
		"roles":   {"user", "admin"},
		"r.user":  {"guests:"},
		"p.admin": {"Chair@Example.org|" + day, "chair@example.org|"},
		"pa.user": {"visitor@other.org"},
		"pu.user": {""},
	})
	if code != http.StatusOK {
		t.Fatalf("review = %d", code)
	}
	vals := changeValues(page)
	if len(vals) != 3 {
		t.Fatalf("changes = %q, want guests and two people, each once", vals)
	}
	for _, want := range []string{"chair@example.org, until ", "visitor@other.org"} {
		if !strings.Contains(page, want) {
			t.Errorf("the review lacks %q", want)
		}
	}
	rec := c.postForm("/admin/apps/enquiries/save", url.Values{"csrf": {csrfOf(t, c, "/admin/apps/enquiries")}, "c": vals})
	if rec.Code != http.StatusFound {
		t.Fatalf("save = %d", rec.Code)
	}
	as, _ := srv.store.ListRoleAssignments(context.Background(), "enquiries")
	got := map[string]store.RoleAssignment{}
	for _, a := range as {
		got[a.Role+" "+a.Kind+" "+a.Ref] = a
	}
	chair, ok := got["admin person chair@example.org"]
	if !ok || chair.Until.IsZero() || srv.lastDay(chair.Until) != day {
		t.Errorf("the chair = %+v, want the Administrator role until %s", chair, day)
	}
	if v, ok := got["user person visitor@other.org"]; !ok || !v.Until.IsZero() {
		t.Errorf("the visitor = %+v, want the User role with no end date", v)
	}
}

// A person who cannot be added is refused with the page's own wording, and
// the other changes stay on the page, unsaved, rather than being lost.
func TestPickerPersonRefusalKeepsTheOtherChanges(t *testing.T) {
	srv, _, c := appsAdmin(t)
	past := srv.now().AddDate(0, 0, -2).In(srv.tzloc()).Format("2006-01-02")
	for _, tc := range []struct {
		form url.Values
		want string
	}{
		{url.Values{"pa.admin": {"not-an-address"}}, msgPersonNotAddress},
		{url.Values{"pa.admin": {"x@example.org"}, "pu.admin": {"31/12/2027"}}, msgPersonBadDate},
		{url.Values{"p.admin": {"x@example.org|" + past}}, msgPersonPastDate},
	} {
		form := tc.form
		form["roles"] = []string{"user", "admin"}
		form["r.user"] = []string{"guests:"}
		for _, action := range []string{"review", "edit"} {
			code, page := postApp(t, c, action, url.Values(form))
			if code != http.StatusBadRequest || !strings.Contains(page, tc.want) {
				t.Errorf("%s with %v = %d, without %q", action, tc.form, code, tc.want)
			}
			if strings.Contains(page, `name="c"`) {
				t.Errorf("%s with %v opened the review", action, tc.form)
			}
			if !strings.Contains(page, `padd" title="Give the role to Guests"`) {
				t.Errorf("%s with %v lost the ticked guests", action, tc.form)
			}
		}
	}
	if as, _ := srv.store.ListRoleAssignments(context.Background(), "enquiries"); len(as) != 0 {
		t.Errorf("a refused form stored %+v", as)
	}
}

// "Keep editing" keeps people: one about to be given a role is a pending
// token on the role's row with its end date, and one about to have it taken
// away is a pending removal, so neither change is lost.
func TestKeepEditingKeepsPeople(t *testing.T) {
	srv, _, c := appsAdmin(t)
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "user", Kind: store.AssignPerson, Ref: "old@example.org", How: store.AssignedByAdmin})
	srv.forgetRoles()
	day := srv.now().AddDate(0, 1, 0).In(srv.tzloc())
	until := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, srv.tzloc()).AddDate(0, 0, 1)
	code, page := postApp(t, c, "edit", url.Values{"c": {
		fmt.Sprintf("give|admin|person|new@example.org|%d", until.Unix()),
		"take|user|person|old@example.org|0",
	}})
	if code != http.StatusOK {
		t.Fatalf("keep editing = %d", code)
	}
	for _, want := range []string{
		`name="p.admin" value="new@example.org|` + day.Format("2006-01-02") + `" checked data-held="0"`,
		fmt.Sprintf(msgPersonUntil, srv.longDate(day)),
		`pdel" title="Take the role from old@example.org"`,
		`name="take" value="user|person|old@example.org" checked data-held="0"`,
		`class="changes some"`,
		"Two changes have not been saved.",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	// The kept changes go to the review again as they were.
	code, page = postApp(t, c, "review", url.Values{
		"roles":   {"user", "admin"},
		"p.admin": {"new@example.org|" + day.Format("2006-01-02")},
		"take":    {"user|person|old@example.org"},
	})
	vals := changeValues(page)
	if code != http.StatusOK || len(vals) != 2 {
		t.Fatalf("review = %d with %q", code, vals)
	}
}

// Without the page's script, a picker's Add sends the whole form to the edit
// action, which shows the person on the row, with the ticks kept.
func TestPickerAddWithoutScript(t *testing.T) {
	_, _, c := appsAdmin(t)
	page := html.UnescapeString(c.get("/admin/apps/enquiries", nil).Body.String())
	if !strings.Contains(page, `formaction="/admin/apps/enquiries/edit#roles"`) || !strings.Contains(page, `href="/admin/invitations/new?role=enquiries%3Aadmin"`) {
		t.Error("the picker has no Add that works without the script, or no invitation link for its role")
	}
	if strings.Contains(page, "Add or invite a person") {
		t.Error("the picker still jumps to the people table")
	}
	code, page := postApp(t, c, "edit", url.Values{"roles": {"user", "admin"}, "r.user": {"guests:"}, "pa.admin": {"Someone@Example.org"}})
	if code != http.StatusOK {
		t.Fatalf("edit = %d", code)
	}
	for _, want := range []string{`name="p.admin" value="someone@example.org|"`, `padd" title="Give the role to Guests"`, `class="changes some"`} {
		if !strings.Contains(page, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
}

// A network or guests still cannot be given a role other than User, from
// the review, the edit action or a forged save; the refusal keeps the
// page's other changes without the refused one.
func TestNetworkRefusalHoldsWithPeople(t *testing.T) {
	srv, _, c := appsAdmin(t)
	for _, action := range []string{"review", "edit"} {
		code, page := postApp(t, c, action, url.Values{"roles": {"user", "admin"}, "r.admin": {"network:rch", "guests:"}, "pa.admin": {"a@example.org"}})
		if code != http.StatusBadRequest || !strings.Contains(page, msgNetworkUserOnly) {
			t.Errorf("%s = %d, without the refusal", action, code)
		}
		if strings.Contains(page, `value="network:rch" checked`) || strings.Contains(page, `name="c"`) {
			t.Errorf("%s kept the network on the Administrator role", action)
		}
		if !strings.Contains(page, `name="p.admin" value="a@example.org|"`) {
			t.Errorf("%s lost the person", action)
		}
	}
	c.postForm("/admin/apps/enquiries/save", url.Values{"csrf": {csrfOf(t, c, "/admin/apps/enquiries")}, "c": {"give|admin|network|rch|0", "give|admin|guests||0", "give|admin|person|not-an-address|0"}})
	if as, _ := srv.store.ListRoleAssignments(context.Background(), "enquiries"); len(as) != 0 {
		t.Errorf("the save stored %+v", as)
	}
}
