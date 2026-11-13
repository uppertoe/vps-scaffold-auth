package server

import (
	"context"
	"fmt"
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

// openInvitation stores an invitation to enquiries, sent at sent.
func openInvitation(t *testing.T, srv *Server, addr string, sent time.Time) {
	t.Helper()
	if _, err := srv.store.CreateInvitations(context.Background(), []store.Invitation{{
		Email: addr, App: "enquiries", Role: "admin", TokenHash: "h-" + addr, CreatedBy: "admin@example.com",
		CreatedAt: sent, SentAt: sent, ExpiresAt: sent.Add(inviteTTL),
	}}, nil); err != nil {
		t.Fatal(err)
	}
	srv.forgetRoles()
}

// An app page's Withdraw opens a confirmation in the row, which names the
// address; the page keeps its add line and its pickers' close control.
func TestAppPageWithdrawIsConfirmed(t *testing.T) {
	srv, _, c := appsAdmin(t)
	openInvitation(t, srv, "k.lee@monash.org", srv.now())
	page := html.UnescapeString(c.get("/admin/apps/enquiries", nil).Body.String())
	for _, want := range []string{`href="/admin/apps/enquiries?withdraw=1#invite-1"`, `name="person"`, ">" + msgPickerDone + "<", `aria-modal="true"`} {
		if !strings.Contains(page, want) {
			t.Errorf("app page lacks %q", want)
		}
	}
	if strings.Contains(page, `action="/admin/invitations/1/withdraw"`) {
		t.Error("Withdraw acts without a confirmation")
	}
	page = html.UnescapeString(c.get("/admin/apps/enquiries?withdraw=1", nil).Body.String())
	if !strings.Contains(page, fmt.Sprintf(msgWithdrawConfirm, "k.lee@monash.org")) || !strings.Contains(page, `action="/admin/invitations/1/withdraw"`) {
		t.Error("the confirmation does not name the address, or has no button")
	}
}

// The Invitations page shows the same invitation lines as the Apps page,
// and Resend and Withdraw are confirmed first.
func TestInvitationsLinesAndConfirmations(t *testing.T) {
	srv, _, c := appsAdmin(t)
	openInvitation(t, srv, "k.lee@monash.org", srv.now().Add(-8*24*time.Hour))
	week := "The invitation to k.lee@monash.org for Fellowship enquiries has not been accepted after a week."
	for _, page := range []string{"/admin/apps", "/admin/invitations"} {
		if !strings.Contains(html.UnescapeString(c.get(page, nil).Body.String()), week) {
			t.Errorf("%s lacks the week-old invitation", page)
		}
	}
	list := html.UnescapeString(c.get("/admin/invitations", nil).Body.String())
	if strings.Contains(list, `action="/admin/invitations/1/resend"`) || strings.Contains(list, `action="/admin/invitations/1/withdraw"`) {
		t.Error("Resend or Withdraw acts without a confirmation")
	}
	for action, want := range map[string]string{
		"resend":   fmt.Sprintf(msgResendConfirm, "k.lee@monash.org"),
		"withdraw": fmt.Sprintf(msgWithdrawConfirm, "k.lee@monash.org"),
	} {
		page := html.UnescapeString(c.get("/admin/invitations?"+action+"=1", nil).Body.String())
		if !strings.Contains(page, want) || !strings.Contains(page, `action="/admin/invitations/1/`+action+`"`) {
			t.Errorf("the %s confirmation is missing", action)
		}
	}
}

// The Overview lists what the Apps, Invitations and Cards pages list, and
// leaves out the ROUTE_GROUPS_FILE note once app roles are on.
func TestOverviewAgreesWithTheOtherPages(t *testing.T) {
	srv, _, c := appsAdmin(t)
	openInvitation(t, srv, "k.lee@monash.org", srv.now().Add(-8*24*time.Hour))
	body := html.UnescapeString(c.get("/admin/", nil).Body.String())
	for _, want := range []string{
		"Nobody holds the User role in ", ">caffeine</a>, so nobody can reach it.",
		"The invitation to k.lee@monash.org for Fellowship enquiries has not been accepted after a week.",
		msgActiveCardsTile,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("overview lacks %q", want)
		}
	}
	if strings.Contains(body, "Nothing needs attention.") || strings.Contains(body, "ROUTE_GROUPS_FILE") {
		t.Error("overview says nothing needs attention, or names ROUTE_GROUPS_FILE with app roles on")
	}
}

// Removing a domain is confirmed first, naming the roles and apps the group
// holds; a group that holds roles says so in place of a Delete button.
func TestDomainRemovalAndDeleteConfirmations(t *testing.T) {
	srv, _, c := appsAdmin(t)
	ctx := context.Background()
	if err := srv.store.CreateGroupOfKind(ctx, "rch-staff", "RCH staff", store.GroupKindDomain); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.AddGroupDomain(ctx, "rch-staff", "rch.org.au"); err != nil {
		t.Fatal(err)
	}
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "user", Kind: store.AssignDomainGroup, Ref: "rch-staff"})
	mustAssign(t, srv, store.RoleAssignment{App: "caffeine", Role: "user", Kind: store.AssignDomainGroup, Ref: "rch-staff"})
	page := html.UnescapeString(c.get("/admin/groups/rch-staff", nil).Body.String())
	if strings.Contains(page, `action="/admin/groups/rch-staff/domains/delete"`) {
		t.Error("Remove acts without a confirmation")
	}
	if !strings.Contains(page, fmt.Sprintf(msgGroupHolds, "RCH staff", "two roles")) || strings.Contains(page, `action="/admin/groups/rch-staff/delete"`) {
		t.Error("the delete confirmation does not say the group holds roles, or still offers to delete it")
	}
	page = html.UnescapeString(c.get("/admin/groups/rch-staff?remove=rch.org.au", nil).Body.String())
	want := fmt.Sprintf(msgDomainRemoveHolds, "RCH staff", "two roles", "caffeine and Fellowship enquiries") + " " +
		fmt.Sprintf(msgDomainRemoveLast, "rch.org.au", "rch.org.au", "RCH staff")
	if !strings.Contains(page, want) || !strings.Contains(page, `action="/admin/groups/rch-staff/domains/delete"`) {
		t.Errorf("the removal confirmation lacks %q, or its button", want)
	}
}

// A list member outside the allow-list who holds an app role signs in as a
// member, so carries no "not on the allow-list" pill; the list's facts say
// which roles it holds.
func TestListMemberWithRoleIsNotMarkedGuest(t *testing.T) {
	srv, _, c := appsAdmin(t)
	ctx := context.Background()
	if err := srv.store.CreateGroupOfKind(ctx, "registrars", "Registrars", store.GroupKindList); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"jo@outside.example.org"} {
		if err := srv.store.AddGroupMember(ctx, "registrars", m); err != nil {
			t.Fatal(err)
		}
	}
	page := c.get("/admin/groups/registrars", nil).Body.String()
	if !strings.Contains(page, "not on the allow-list") {
		t.Error("a member of a list with no role is not marked")
	}
	mustAssign(t, srv, store.RoleAssignment{App: "caffeine", Role: "user", Kind: store.AssignList, Ref: "registrars"})
	page = c.get("/admin/groups/registrars", nil).Body.String()
	if strings.Contains(page, "not on the allow-list") {
		t.Error("a member who holds a role is marked as signing in only as a guest")
	}
	if !strings.Contains(page, "One role in one app") {
		t.Error("the facts' Used by does not name the list's roles")
	}
}

// A network or guests are offered and accepted for the User role only; an
// older assignment to another role is listed apart and gives nothing.
func TestNetworkAndGuestsOnlyForUser(t *testing.T) {
	srv, _, c := appsAdmin(t)
	page := c.get("/admin/apps/enquiries", nil).Body.String()
	admin := page[strings.Index(page, `id="pick-admin"`):]
	admin = admin[:strings.Index(admin, "</form>")]
	if strings.Contains(admin, `value="network:rch"`) || strings.Contains(admin, `value="guests:"`) {
		t.Error("the Administrator picker offers the network or guests")
	}
	form := map[string][]string{"roles": {"user", "admin"}, "r.admin": {"network:rch"}, "csrf": {csrfOf(t, c, "/admin/apps/enquiries")}}
	rec := c.postForm("/admin/apps/enquiries/review", form)
	if body := html.UnescapeString(rec.Body.String()); rec.Code != 400 || !strings.Contains(body, msgNetworkUserOnly) {
		t.Errorf("giving the admin role to a network = %d, without the refusal", rec.Code)
	}
	rec = c.postForm("/admin/apps/enquiries/save", map[string][]string{"c": {"give|admin|network|rch|0"}, "csrf": {csrfOf(t, c, "/admin/apps/enquiries")}})
	if as, _ := srv.store.ListRoleAssignments(context.Background(), "enquiries"); len(as) != 0 {
		t.Errorf("the save stored %+v", as)
	}

	// An assignment stored before the rule is listed apart, with Remove,
	// and does not count as a holder.
	w, err := srv.loadRolesWorld(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	w.as = append(w.as, store.RoleAssignment{App: "enquiries", Role: "admin", Kind: store.AssignNetwork, Ref: "rch"})
	v := srv.appPage(w, srv.appRoles.Apps["enquiries"], nil)
	if len(v.Ignored) != 1 || len(v.Groups) != 0 {
		t.Errorf("ignored = %+v, groups = %+v", v.Ignored, v.Groups)
	}
	for _, row := range v.Block.Rows {
		if len(row.Tokens) != 0 || !row.Reach.Closed {
			t.Errorf("row %s counts the ignored assignment", row.Role)
		}
	}
}
