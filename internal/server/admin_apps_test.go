package server

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// A manifest with paths, so the warnings can name them.
const testAppRolesWithPaths = "enquiries\tuser\tUser\tenquiries.{$DOMAIN}\n" +
	"enquiries\tadmin\tAdministrator\tenquiries.{$DOMAIN}\n" +
	"@label\tenquiries\tFellowship enquiries\n" +
	"@open\tenquiries\t/ /faq\tRead before signing in\n" +
	"@path\tenquiries\t/admin/*\tadmin\n" +
	"@path\tenquiries\t*\tuser\n" +
	"caffeine\tuser\tUser\tcaffeine.{$DOMAIN}\n" +
	"@path\tcaffeine\t*\tuser\n"

// appsAdmin is a server with the manifest above, a network "rch", two
// administrators, and a client signed in as the first.
func appsAdmin(t *testing.T) (*Server, *captureSender, *client) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app-roles.tsv")
	if err := os.WriteFile(path, []byte(testAppRolesWithPaths), 0o600); err != nil {
		t.Fatal(err)
	}
	ranges, err := config.ParseNetworkRanges("rch=10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	srv, sender := testServerWith(t, func(c *config.Config) {
		c.AppRolesFile = path
		c.NetworkRanges = ranges
		c.AdminEmails = []string{"admin@example.com", "boss@example.com"}
	})
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	return srv, sender, c
}

func csrfOf(t *testing.T, c *client, page string) string {
	t.Helper()
	return extractCSRF(t, c.get(page, nil).Body.String())
}

// reviewOf posts the app page's form and returns the review page.
func reviewOf(t *testing.T, c *client, app string, form url.Values) string {
	t.Helper()
	form.Set("csrf", csrfOf(t, c, "/admin/apps/"+app))
	rec := c.postForm("/admin/apps/"+app+"/review", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("review = %d", rec.Code)
	}
	return html.UnescapeString(rec.Body.String())
}

// changeValues are the changes a review page carries to the save.
func changeValues(page string) []string {
	var out []string
	for _, m := range regexp.MustCompile(`name="c" value="([^"]*)"`).FindAllStringSubmatch(page, -1) {
		out = append(out, html.UnescapeString(m[1]))
	}
	return out
}

func TestAppsOverview(t *testing.T) {
	srv, _, c := appsAdmin(t)
	mustDomainGroup(t, srv, "staff", "example.com")
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "user", Kind: store.AssignDomainGroup, Ref: "staff"})
	rec := c.get("/admin/apps", nil)
	body := html.UnescapeString(rec.Body.String())
	for _, want := range []string{
		"Each app's roles, and who holds them.",
		"Nobody holds the User role in ", ">caffeine</a>, so nobody can reach it.",
		"Nobody holds this role.", "Closed", "Everything else", "/admin/*", "One open by design",
		"Amber tokens admit strangers, or people who have not signed in.",
		"Widest access, from the widest step to the narrowest", "Anyone on the RCH network",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("overview lacks %q", want)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src "+scriptHash(string(rolesScript))) || strings.Contains(csp, "unsafe-inline'; script") {
		t.Errorf("CSP does not allow exactly the page's script: %s", csp)
	}
	// Checking an address marks the roles it holds.
	body = html.UnescapeString(c.get("/admin/apps?address=someone%40example.com", nil).Body.String())
	if !strings.Contains(body, "someone@example.com holds one role in one app, through staff.") {
		t.Errorf("address check sentence missing:\n%s", body[strings.Index(body, "focus"):][:300])
	}
	if !strings.Contains(body, `class="rrow hit"`) || !strings.Contains(body, `class="rrow dim"`) {
		t.Error("address check did not mark the rows")
	}
	// The filter keeps matching apps only.
	body = c.get("/admin/apps?q=caff", nil).Body.String()
	if strings.Contains(body, "Fellowship enquiries</b>") || !strings.Contains(body, "caffeine</b>") {
		t.Error("filter did not keep caffeine alone")
	}
}

func TestAppsPagesNeedTheModel(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	if rec := c.get("/admin/apps", nil); rec.Code != http.StatusFound {
		t.Errorf("apps page with the model off = %d, want a redirect", rec.Code)
	}
	if strings.Contains(c.get("/admin/", nil).Body.String(), `href="/admin/apps"`) {
		t.Error("menu offers Apps with the model off")
	}
}

func TestReviewWarnings(t *testing.T) {
	srv, _, c := appsAdmin(t)
	mustDomainGroup(t, srv, "staff", "example.com")
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "admin", Kind: store.AssignDomainGroup, Ref: "staff"})

	// Taking the last holder of the administrator role closes /admin/*;
	// giving the user role to a network and to guests opens every other path.
	page := reviewOf(t, c, "enquiries", url.Values{
		"roles":  {"user", "admin"},
		"r.user": {"network:rch", "guests:"},
	})
	for _, want := range []string{
		"Save these changes?",
		"Nobody will hold Administrator once this is saved, so /admin/* will be closed to everyone.",
		"Anyone on the RCH network will reach every other path without signing in.",
		"Anyone who confirms an email address will reach every other path.",
		msgSaveNote, "Keep editing", "Save the changes", "Give to", "Take from",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("review lacks %q", want)
		}
	}
	// The user role stays reachable while another role is held, so taking
	// nothing from it raises no closing warning for it.
	if strings.Contains(page, "Nobody will hold User") {
		t.Error("closing warning for a role nobody held before")
	}
	if got := changeValues(page); len(got) != 3 {
		t.Errorf("changes = %q, want three", got)
	}
	// An unknown network or a group of the wrong kind is not offered.
	page = reviewOf(t, c, "enquiries", url.Values{"roles": {"admin"}, "r.admin": {"domain_group:staff", "network:nowhere", "list:staff"}})
	if !strings.Contains(page, "Nothing has been changed") {
		t.Error("unknown holders were turned into changes")
	}
	// Nothing is saved by a review.
	if as, _ := srv.store.ListRoleAssignments(context.Background(), "enquiries"); len(as) != 1 {
		t.Errorf("assignments after review = %+v", as)
	}
	// The user role closes only when no role in the app is held.
	page = reviewOf(t, c, "enquiries", url.Values{"roles": {"admin"}})
	if !strings.Contains(page, "Nobody will hold User once this is saved, so every other path will be closed to everyone.") {
		t.Error("no closing warning for the user role once nothing is held")
	}
}

func TestSaveIsAtomicAuditedAndEmailedOnce(t *testing.T) {
	srv, sender, c := appsAdmin(t)
	mustDomainGroup(t, srv, "staff", "example.com")
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "admin", Kind: store.AssignDomainGroup, Ref: "staff"})
	// Prime the role cache, so the save must drop it.
	srv.roleData(context.Background())

	page := reviewOf(t, c, "enquiries", url.Values{"roles": {"user", "admin"}, "r.user": {"guests:"}, "r.admin": {"domain_group:staff"}})
	vals := changeValues(page)
	if len(vals) != 1 {
		t.Fatalf("changes = %q", vals)
	}
	page = reviewOf(t, c, "enquiries", url.Values{"person": {"Visitor@Other.org"}, "person_role": {"admin"}, "until": {time.Now().AddDate(0, 1, 0).Format("2006-01-02")}})
	vals = append(vals, changeValues(page)...)
	vals = append(vals, "take|admin|domain_group|staff|0")
	sender.reset()
	rec := c.postForm("/admin/apps/enquiries/save", url.Values{"csrf": {csrfOf(t, c, "/admin/apps/enquiries")}, "c": vals})
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/admin/apps/enquiries" {
		t.Fatalf("save = %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	as, _ := srv.store.ListRoleAssignments(context.Background(), "enquiries")
	got := map[string]bool{}
	for _, a := range as {
		got[a.Role+" "+a.Kind+" "+a.Ref] = true
		if a.Kind == store.AssignPerson && (a.CreatedBy != "admin@example.com" || a.How != store.AssignedByAdmin || a.Until.IsZero()) {
			t.Errorf("person assignment = %+v", a)
		}
	}
	if len(got) != 2 || !got["user guests "] || !got["admin person visitor@other.org"] {
		t.Errorf("assignments after save = %v", got)
	}
	// The cache was dropped: the new holder is seen at once.
	if st := srv.roleData(context.Background()); len(st.assignments) != 2 {
		t.Errorf("cached assignments = %d, want 2", len(st.assignments))
	}
	events, _ := srv.store.ListAdminEvents(context.Background(), 20, 0)
	n := 0
	for _, e := range events {
		if e.Action == store.AdminActionRoleGive || e.Action == store.AdminActionRoleTake {
			n++
			if e.Actor != "admin@example.com" || !strings.HasPrefix(e.Target, "enquiries:") {
				t.Errorf("event = %+v", e)
			}
		}
	}
	if n != 3 {
		t.Errorf("role events = %d, want one per change", n)
	}
	mail := noticesAfter(sender, 1)
	if len(mail) != 1 || mail[0].To != "boss@example.com" || mail[0].Subject != "Access to Fellowship enquiries has changed." {
		t.Fatalf("emails = %+v, want one, to the other administrator", mail)
	}
	for _, want := range []string{"admin@example.com made these changes on ", "User · Give to · Guests", "Administrator · Take from · staff", "Administrator · Give to · visitor@other.org, until ", "Each change is recorded in the admin log."} {
		if !strings.Contains(mail[0].Text, want) {
			t.Errorf("email lacks %q:\n%s", want, mail[0].Text)
		}
	}
}

// One failing change leaves every change and record unsaved.
func TestApplyRoleChangesIsAllOrNothing(t *testing.T) {
	srv, _, _ := appsAdmin(t)
	ctx := context.Background()
	give := []store.RoleAssignment{
		{App: "enquiries", Role: "user", Kind: store.AssignGuests},
		{App: "enquiries", Role: "admin", Kind: store.AssignList, Ref: "missing"},
	}
	events := []store.AdminEvent{{Actor: "a@example.com", Action: store.AdminActionRoleGive, CreatedAt: time.Now()}}
	if err := srv.store.ApplyRoleChanges(ctx, give, nil, events); !errors.Is(err, store.ErrNoSuchGroup) {
		t.Fatalf("err = %v, want ErrNoSuchGroup", err)
	}
	if as, _ := srv.store.ListRoleAssignments(ctx, ""); len(as) != 0 {
		t.Errorf("assignments after a failed save = %+v", as)
	}
	if es, _ := srv.store.ListAdminEvents(ctx, 10, 0); len(es) != 0 {
		t.Errorf("events after a failed save = %+v", es)
	}
}

func TestSaveRefusesForgedChanges(t *testing.T) {
	srv, sender, c := appsAdmin(t)
	sender.reset()
	tok := csrfOf(t, c, "/admin/apps/enquiries")
	// A role the snippet does not declare, an unknown network and a past end.
	past := fmt.Sprint(time.Now().Add(-time.Hour).Unix())
	rec := c.postForm("/admin/apps/enquiries/save", url.Values{"csrf": {tok}, "c": {
		"give|editor|guests||0", "give|user|network|nowhere|0", "give|user|person|x@example.org|" + past,
	}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Nothing has been changed") {
		t.Errorf("forged save = %d", rec.Code)
	}
	if as, _ := srv.store.ListRoleAssignments(context.Background(), ""); len(as) != 0 {
		t.Errorf("assignments = %+v", as)
	}
	// Without the form token nothing happens.
	if rec := c.postForm("/admin/apps/enquiries/save", url.Values{"c": {"give|user|guests||0"}}); rec.Code != http.StatusForbidden {
		t.Errorf("save without CSRF = %d", rec.Code)
	}
	if got := noticesAfter(sender, 0); len(got) != 0 {
		t.Errorf("emails = %+v", got)
	}
}

func TestAppPageListsPeopleGroupsPathsAndOrphans(t *testing.T) {
	srv, _, c := appsAdmin(t)
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "admin", Kind: store.AssignPerson, Ref: "p@example.org", How: store.AssignedByAdmin, CreatedBy: "upperteam@example.com"})
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "editor", Kind: store.AssignGuests})
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "user", Kind: store.AssignNetwork, Ref: "rch"})
	body := html.UnescapeString(c.get("/admin/apps/enquiries", nil).Body.String())
	for _, want := range []string{
		"User and Administrator", "One path, listed below",
		"People given a role directly", "p@example.org", "By upperteam, ", "No end date",
		"Groups and settings", "Anyone on the RCH network, without signing in",
		msgOrphanRole, "editor",
		"Nothing, open by design", "Read before signing in", "The Administrator role", "The User role, or any other",
		`name="r.user" value="network:rch" checked data-held="1"`,
		`href="#pick-admin"`, "Give this role",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("app page lacks %q", want)
		}
	}
	// The orphaned assignment can be taken away through the review.
	page := reviewOf(t, c, "enquiries", url.Values{"take": {"editor|guests|"}})
	if got := changeValues(page); len(got) != 1 || got[0] != "take|editor|guests||0" {
		t.Errorf("orphan take = %q", got)
	}
}

func TestDeleteGroupThatHoldsRolesIsRefused(t *testing.T) {
	srv, _, c := appsAdmin(t)
	ctx := context.Background()
	if err := srv.store.CreateGroupOfKind(ctx, "exec", "Department executive", store.GroupKindList); err != nil {
		t.Fatal(err)
	}
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "admin", Kind: store.AssignList, Ref: "exec"})
	mustAssign(t, srv, store.RoleAssignment{App: "caffeine", Role: "user", Kind: store.AssignList, Ref: "exec"})
	page := c.get("/admin/groups/exec", nil).Body.String()
	for _, want := range []string{"Roles this group holds", "Fellowship enquiries: Administrator", "caffeine: User", "A change to this group affects every role listed here."} {
		if !strings.Contains(html.UnescapeString(page), want) {
			t.Errorf("group page lacks %q", want)
		}
	}
	rec := c.postForm("/admin/groups/exec/delete", url.Values{"csrf": {extractCSRF(t, page)}})
	if rec.Code != http.StatusConflict || !strings.Contains(html.UnescapeString(rec.Body.String()), "Department executive holds two roles. Remove the group from those roles on each app's page, then delete it.") {
		t.Errorf("delete in use = %d", rec.Code)
	}
	if gs, _ := srv.store.ListGroups(ctx); len(gs) != 1 {
		t.Error("the group was deleted")
	}
}

func TestDomainGroupPages(t *testing.T) {
	srv, sender, c := appsAdmin(t)
	ctx := context.Background()
	tok := csrfOf(t, c, "/admin/groups/new")
	page := c.get("/admin/groups/new", nil).Body.String()
	for _, want := range []string{"Choose the kind of group first. The kind cannot be changed later.", "Domain group", "By hand", "From a feed", "Create the group"} {
		if !strings.Contains(page, want) {
			t.Errorf("new group page lacks %q", want)
		}
	}
	// A webmail domain is refused before the group is made.
	rec := c.postForm("/admin/groups", url.Values{"csrf": {tok}, "from": {"new"}, "kind": {"domain"}, "label": {"Monash staff"}, "domains": {"monashhealth.org, gmail.com"}})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "gmail.com is a public email service, so anyone could sign in with it. A domain group cannot include it.") {
		t.Errorf("webmail on create = %d", rec.Code)
	}
	if gs, _ := srv.store.ListGroups(ctx); len(gs) != 0 {
		t.Fatalf("groups after a refused create = %+v", gs)
	}
	rec = c.postForm("/admin/groups", url.Values{"csrf": {tok}, "from": {"new"}, "kind": {"domain"}, "label": {"Monash staff"}, "domains": {"@MonashHealth.org"}})
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/admin/groups/monash-staff" {
		t.Fatalf("create = %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	gs, _ := srv.store.ListGroups(ctx)
	if len(gs) != 1 || gs[0].Kind != store.GroupKindDomain || gs[0].Label != "Monash staff" {
		t.Fatalf("groups = %+v", gs)
	}
	// The same name again is refused.
	rec = c.postForm("/admin/groups", url.Values{"csrf": {tok}, "from": {"new"}, "kind": {"list"}, "label": {"Monash staff"}})
	if rec.Code != http.StatusConflict {
		t.Errorf("duplicate create = %d", rec.Code)
	}

	// Adding a domain: webmail refused, then a real one, which drops the
	// role cache and emails the other administrator.
	rec = c.postForm("/admin/groups/monash-staff/domains", url.Values{"csrf": {tok}, "domain": {"hotmail.com"}})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "hotmail.com is a public email service") {
		t.Errorf("webmail domain = %d", rec.Code)
	}
	mustAssign(t, srv, store.RoleAssignment{App: "caffeine", Role: "user", Kind: store.AssignDomainGroup, Ref: "monash-staff"})
	srv.roleData(ctx)
	sender.reset()
	rec = c.postForm("/admin/groups/monash-staff/domains", url.Values{"csrf": {tok}, "domain": {"monash.edu"}})
	if rec.Code != http.StatusFound {
		t.Fatalf("add domain = %d", rec.Code)
	}
	if st := srv.roleData(ctx); len(st.domains["monash-staff"]) != 2 {
		t.Errorf("cached domains = %v", st.domains)
	}
	mail := noticesAfter(sender, 1)
	if len(mail) != 1 || mail[0].To != "boss@example.com" || mail[0].Subject != "Access through Monash staff has changed." || !strings.Contains(mail[0].Text, "Added the domain @monash.edu") {
		t.Errorf("emails = %+v", mail)
	}
	page = html.UnescapeString(c.get("/admin/groups/monash-staff", nil).Body.String())
	for _, want := range []string{"Domain group", "@monash.edu", "@monashhealth.org", "Add the domain", "caffeine: User"} {
		if !strings.Contains(page, want) {
			t.Errorf("domain group page lacks %q", want)
		}
	}
	if strings.Contains(page, "Add members") {
		t.Error("a domain group offers to add members")
	}
	rec = c.postForm("/admin/groups/monash-staff/domains/delete", url.Values{"csrf": {tok}, "domain": {"monash.edu"}})
	if d, _ := srv.store.ListGroupDomains(ctx); rec.Code != http.StatusFound || len(d["monash-staff"]) != 1 {
		t.Errorf("remove domain = %d, domains %v", rec.Code, d)
	}

	// A list takes no domain, and the groups page lists the two kinds apart.
	if err := srv.store.CreateGroupOfKind(ctx, "exec", "", store.GroupKindList); err != nil {
		t.Fatal(err)
	}
	rec = c.postForm("/admin/groups/exec/domains", url.Values{"csrf": {tok}, "domain": {"example.org"}})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("domain on a list = %d", rec.Code)
	}
	page = c.get("/admin/groups", nil).Body.String()
	dom, lists := strings.Index(page, "<h2>Domain groups</h2>"), strings.Index(page, "<h2>Lists</h2>")
	if dom < 0 || lists < dom || !strings.Contains(page[dom:lists], "Monash staff") || !strings.Contains(page[lists:], ">exec<") {
		t.Error("groups page does not list domain groups and lists apart")
	}
}

// A user role with no holders of its own is still reached by the holders of
// the app's other roles, so its row is not shown as closed.
func TestUserRowCountsOtherRoles(t *testing.T) {
	srv, _, c := appsAdmin(t)
	mustDomainGroup(t, srv, "staff", "example.com")
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "admin", Kind: store.AssignDomainGroup, Ref: "staff"})
	body := html.UnescapeString(c.get("/admin/apps?q=enquiries", nil).Body.String())
	if !strings.Contains(body, "Only the holders of Administrator reach these paths.") {
		t.Error("the user row does not name the other role")
	}
	if strings.Contains(body, "Fellowship enquiries</a>, so nobody can reach it.") {
		t.Error("the attention line calls the app unreachable")
	}
	if strings.Contains(body, ">Closed<") {
		t.Error("the user row is shown as closed")
	}
}

// A domain group's organisation name is set on the new-group form or on the
// group's page. Setting it is audited and emails nobody; a list has none.
func TestDomainGroupOrganisationName(t *testing.T) {
	srv, sender, c := appsAdmin(t)
	ctx := context.Background()
	tok := csrfOf(t, c, "/admin/groups/new")
	page := html.UnescapeString(c.get("/admin/groups/new", nil).Body.String())
	for _, want := range []string{msgOrgLabel, msgOrgHint, `name="org"`} {
		if !strings.Contains(page, want) {
			t.Errorf("new group page lacks %q", want)
		}
	}
	rec := c.postForm("/admin/groups", url.Values{"csrf": {tok}, "from": {"new"}, "kind": {"domain"}, "label": {"Monash staff"}, "domains": {"monashhealth.org"}, "org": {"  Monash Health "}})
	if rec.Code != http.StatusFound {
		t.Fatalf("create = %d", rec.Code)
	}
	// A list ignores the field.
	c.postForm("/admin/groups", url.Values{"csrf": {tok}, "from": {"new"}, "kind": {"list"}, "label": {"Exec"}, "org": {"Exec"}})
	orgs := map[string]string{}
	gs, _ := srv.store.ListGroups(ctx)
	for _, g := range gs {
		orgs[g.Name] = g.Org
	}
	if orgs["monash-staff"] != "Monash Health" || orgs["exec"] != "" {
		t.Fatalf("organisation names = %v", orgs)
	}

	page = html.UnescapeString(c.get("/admin/groups/monash-staff", nil).Body.String())
	for _, want := range []string{msgOrgLabel, msgOrgHint, msgOrgButton, `value="Monash Health"`} {
		if !strings.Contains(page, want) {
			t.Errorf("domain group page lacks %q", want)
		}
	}
	if list := c.get("/admin/groups/exec", nil).Body.String(); strings.Contains(list, msgOrgLabel) {
		t.Error("a list offers an organisation name")
	}

	sender.reset()
	rec = c.postForm("/admin/groups/monash-staff/org", url.Values{"csrf": {tok}, "org": {"MHS"}})
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/admin/groups/monash-staff" {
		t.Fatalf("save = %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	if page := html.UnescapeString(c.get("/admin/groups/monash-staff", nil).Body.String()); !strings.Contains(page, msgOrgSaved) || !strings.Contains(page, `value="MHS"`) {
		t.Error("the saved name or the notice is missing")
	}
	if mail := noticesAfter(sender, 0); len(mail) != 0 {
		t.Errorf("saving the name emailed %+v", mail)
	}
	// Emptying it stores no name; a list cannot be given one.
	c.postForm("/admin/groups/monash-staff/org", url.Values{"csrf": {tok}, "org": {"  "}})
	if rec := c.postForm("/admin/groups/exec/org", url.Values{"csrf": {tok}, "org": {"Exec"}}); rec.Code != http.StatusNotFound {
		t.Errorf("a list's name = %d", rec.Code)
	}
	gs, _ = srv.store.ListGroups(ctx)
	for _, g := range gs {
		if g.Org != "" {
			t.Errorf("%s keeps %q", g.Name, g.Org)
		}
	}
	events, _ := srv.store.ListAdminEvents(ctx, 50, 0)
	var details []string
	for _, e := range events {
		if e.Action == store.AdminActionGroupOrg {
			details = append(details, e.Target+"="+e.Detail)
		}
	}
	if strings.Join(details, ",") != "monash-staff=,monash-staff=MHS,monash-staff=Monash Health" {
		t.Errorf("audited = %v", details)
	}
	if audit := html.UnescapeString(c.get("/admin/audit", nil).Body.String()); !strings.Contains(audit, msgOrgAudit) {
		t.Error("the audit page does not label the change")
	}
}
