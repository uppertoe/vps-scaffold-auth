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

// An overview row with more than three holders shows three and "+N more"
// without the script, and checking an address marks the tokens through
// which it holds the role, which are the last to be hidden.
func TestOverviewTokensCappedAndMatched(t *testing.T) {
	srv, _, c := appsAdmin(t)
	for _, g := range []string{"a-staff", "b-staff", "c-staff", "d-staff", "e-staff"} {
		mustDomainGroup(t, srv, g, g+".example.org")
		mustAssign(t, srv, store.RoleAssignment{App: "caffeine", Role: "user", Kind: store.AssignDomainGroup, Ref: g})
	}
	body := html.UnescapeString(c.get("/admin/apps", nil).Body.String())
	if n := strings.Count(body, " capped"); n != 2 || !strings.Contains(body, ">+2 more</button>") {
		t.Errorf("capped tokens = %d, or no +2 more", n)
	}
	body = c.get("/admin/apps?address=sam%40e-staff.example.org", nil).Body.String()
	i := strings.Index(body, ">e-staff<")
	if i < 0 {
		t.Fatal("no e-staff token")
	}
	tok := body[strings.LastIndex(body[:i], "<a "):i]
	if !strings.Contains(tok, " on") || strings.Contains(tok, "capped") {
		t.Errorf("the matched token is not marked, or is hidden: %s", tok)
	}
}
