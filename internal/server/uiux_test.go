package server

import (
	"html"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// Tests for the UI/UX fixes of 13 November 2026.

// A person whose end date has passed holds nothing: the overview counts
// nobody, the app is closed, and the app page names the row as ended.
func TestEndedPersonHoldsNothing(t *testing.T) {
	srv, _, c := appsAdmin(t)
	mustAssign(t, srv, store.RoleAssignment{App: "caffeine", Role: "user", Kind: store.AssignPerson, Ref: "ended@example.com",
		How: store.AssignedByAdmin, Until: srv.now().Add(-time.Hour)})
	body := html.UnescapeString(c.get("/admin/apps", nil).Body.String())
	if !strings.Contains(body, ">caffeine</a>, so nobody can reach it.") {
		t.Error("an app held only by an ended person is not reported as closed")
	}
	page := html.UnescapeString(c.get("/admin/apps/caffeine", nil).Body.String())
	roles := page[strings.Index(page, `id="roles"`):strings.Index(page, `id="people"`)]
	if strings.Contains(roles, "One person") || !strings.Contains(roles, "Closed") {
		t.Error("the role row counts the ended person")
	}
	if !strings.Contains(page, "Ended "+srv.longDate(srv.now().Add(-time.Hour-time.Second))) {
		t.Error("the ended row's Until cell does not say that the role has ended")
	}
}
