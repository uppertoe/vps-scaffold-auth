package server

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// A pending app (the site is still on an older guard) and a live one.
const testPendingRoles = "planka\tuser\tUser\tplanka.{$DOMAIN}\n" +
	"planka\towner\tOwner\tplanka.{$DOMAIN}\n" +
	"@label\tplanka\tPlanka\n" +
	"@source\tplanka\tapps/planka/planka.caddy\n" +
	"@pending\tplanka\n" +
	"enquiries\tuser\tUser\tenquiries.{$DOMAIN}\n" +
	"@label\tenquiries\tFellowship enquiries\n" +
	"@path\tenquiries\t*\tuser\n"

// The older rules of the sites, as the scaffold renders route-access.tsv and
// route-groups.tsv.
const testPendingAccess = "planka.{$DOMAIN}\tgroups\tplanka-admins planka-users\n" +
	"enquiries.{$DOMAIN}\troles\tenquiries user\n" +
	"caffeine.{$DOMAIN}\tdomains\texample.com example.net\n" +
	"caffeine.{$DOMAIN}\tnetwork\trch\n" +
	"caffeine.{$DOMAIN}\tpublic\t/j/* /static/*: join links for a shared order\n" +
	"dept.{$DOMAIN}\tpublic\ta redirect to SharePoint, which signs people in itself\n" +
	"admin.{$DOMAIN}\tgroups\tadmin\n"

const testPendingGroups = "planka-admins\tplanka.{$DOMAIN}\n" +
	"planka-users\tplanka.{$DOMAIN}\n" +
	"admin\tadmin.{$DOMAIN}\n"

func pendingServer(t *testing.T) (*Server, *captureSender) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	roles, access, groups := write("app-roles.tsv", testPendingRoles), write("route-access.tsv", testPendingAccess), write("route-groups.tsv", testPendingGroups)
	ranges, err := config.ParseNetworkRanges("RCH=10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	return testServerWith(t, func(c *config.Config) {
		c.AppRolesFile, c.RouteAccessFile, c.RouteGroupsFile = roles, access, groups
		c.NetworkRanges = ranges
		c.NetworkNames = config.NetworkNamesAsWritten("RCH=10.0.0.0/8")
		c.AdminEmails = []string{"admin@example.com", "boss@example.com"}
	})
}

// A pending app's roles can be given, but no guard names the app yet, so the
// assignment admits nobody through the site's older guard. Once a guard
// names the app, the assignment already made admits the person.
func TestPendingAppAdmitsNobodyUntilAGuardNamesIt(t *testing.T) {
	srv, sender := pendingServer(t)
	mustAssign(t, srv, store.RoleAssignment{App: "planka", Role: "owner", Kind: store.AssignPerson, Ref: "user@example.com", How: store.AssignedByAdmin})
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)

	older := map[string]string{"X-Auth-Policy": "groups=planka-admins planka-users", "X-Forwarded-Host": "planka.example.com"}
	wantDenied(t, "the older guard, with the pending role held", c.get("/verify", older))

	rec := c.get("/verify", roleGuard("planka", "owner"))
	if rec.Code != http.StatusOK {
		t.Fatalf("a guard naming the pending app = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Remote-Roles"); got == "" {
		t.Error("no Remote-Roles for the role held")
	}
}

func pendingAdmin(t *testing.T) (*Server, *client) {
	t.Helper()
	srv, sender := pendingServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	return srv, c
}

func TestAppsOverviewListsPendingAppsAndOlderSites(t *testing.T) {
	srv, c := pendingAdmin(t)
	ctx := context.Background()
	if err := srv.store.CreateGroup(ctx, "planka-admins", "Planka admins"); err != nil {
		t.Fatal(err)
	}
	page := html.UnescapeString(c.get("/admin/apps", nil).Body.String())
	for _, want := range []string{
		`<span class="pendtag" title="` + fmt.Sprintf(msgPendingNote, "Planka") + `">` + msgPendingTag + `</span>`,
		`<b>` + msgOlderRow + `</b>`,
		`<h2 class="sec" id="older">` + msgOlderHead + `</h2>`,
		`<b>Caffeine</b><span class="p">caffeine.example.com</span>`,
		`<span class="l">@example.net</span>`,
		`<span class="l">RCH network</span>`,
		`<span class="l">One open by design</span>`,
		`<b>Dept</b>`,
		`<span class="l">` + msgOlderAdmins + `</span>`,
		`href="/admin/groups/planka-admins"`,
		`title="` + msgReaderNoGroup + `"`, // planka-users does not exist
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the Apps page lacks %q", want)
		}
	}
	// A live app's site and a pending app's site are not listed as older.
	for _, not := range []string{`<b>Enquiries</b>`, `<b>Planka</b><span class="p">`} {
		if strings.Contains(page, not) {
			t.Errorf("the older sites list %q", not)
		}
	}
	// Live apps come before pending ones, and older sites after both.
	live, pend, older := strings.Index(page, "<b>Fellowship enquiries</b>"), strings.Index(page, "<b>Planka</b>"), strings.Index(page, msgOlderHead)
	if !(live >= 0 && live < pend && pend < older) {
		t.Errorf("order: live %d, pending %d, older %d", live, pend, older)
	}
	// A pending app with nobody holding a role is not said to be closed.
	if strings.Contains(page, "Nobody holds the User role in <a href=\"/admin/apps/planka\">") {
		t.Error("a pending app is reported as closed")
	}
	// The filter finds an older site by its rule.
	page = html.UnescapeString(c.get("/admin/apps?q=example.net", nil).Body.String())
	if !strings.Contains(page, "<b>Caffeine</b>") || strings.Contains(page, "<b>Dept</b>") {
		t.Error("the filter does not reach the older sites")
	}
}

func TestPendingAppPage(t *testing.T) {
	_, c := pendingAdmin(t)
	page := html.UnescapeString(c.get("/admin/apps/planka", nil).Body.String())
	for _, want := range []string{
		fmt.Sprintf(msgPendingNote, "Planka"),
		"<dt>" + msgPendingState + "</dt>",
		fmt.Sprintf(msgOlderDeclared, "apps/planka/planka.caddy"),
		`<b>Planka</b><span class="p">planka.example.com</span>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the pending app's page lacks %q", want)
		}
	}
	if strings.Contains(page, "<h2 class=\"sec\">Paths</h2>") {
		t.Error("a pending app's page lists paths")
	}
	// The review names the app and says when a change will matter.
	review := reviewOf(t, c, "planka", url.Values{"roles": {"user", "owner"}, "r.user": {"network:rch"}})
	if !strings.Contains(review, fmt.Sprintf(msgPendingNetworkOpens, "RCH network", "Planka")) {
		t.Errorf("the review lacks the pending network warning:\n%s", review)
	}
	// A live app's page is unchanged.
	if live := c.get("/admin/apps/enquiries", nil).Body.String(); strings.Contains(live, msgPendingState) || !strings.Contains(live, "Open by design") {
		t.Error("a live app's page changed")
	}
}

func TestGroupsShowEveryUse(t *testing.T) {
	srv, c := pendingAdmin(t)
	ctx := context.Background()
	for _, g := range []struct{ name, label string }{{"planka-admins", ""}, {"planka-users", "Planka users"}, {"fellows", "Fellows"}, {"spare", "Spare"}} {
		if err := srv.store.CreateGroup(ctx, g.name, g.label); err != nil {
			t.Fatal(err)
		}
	}
	if err := srv.store.AddGroupInclude(ctx, "planka-users", "fellows"); err != nil {
		t.Fatal(err)
	}
	srv.cfg.MemberReadersFilePairs = map[string][]string{"planka": {"fellows"}}
	page := html.UnescapeString(c.get("/admin/groups", nil).Body.String())
	for _, want := range []string{
		`<a href="/admin/apps/planka">` + fmt.Sprintf(msgUseOlder, "Planka") + `</a>`,
		`<a href="/admin/groups/planka-users">` + fmt.Sprintf(msgUseIncluded, "Planka users") + `</a>`,
		`<a href="` + appFeedsPath + `">` + fmt.Sprintf(msgUseFeed, "Planka") + `</a>`,
		`<a class="noname" href="/admin/groups/planka-admins#label-planka-admins">` + msgNoNameSet + `</a>`,
		`<code class="slug">planka-users</code>`,
		"No domain groups yet. " + msgDomainGroupsBy,
		"Not used by any app", // spare
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the Groups page lacks %q", want)
		}
	}
	for _, not := range []string{"Not applicable", "<th>Feed</th>"} {
		if strings.Contains(page, not) {
			t.Errorf("the Groups page shows %q", not)
		}
	}
	group := html.UnescapeString(c.get("/admin/groups/fellows", nil).Body.String())
	if !strings.Contains(group, "<h2>"+msgOtherUsesHead+"</h2>") || !strings.Contains(group, fmt.Sprintf(msgUseFeed, "Planka")) {
		t.Error("the group page does not list the other uses")
	}
	if strings.Contains(group, `<dd class="none">No roles</dd>`) {
		t.Error("the group page says No roles beside its other uses")
	}
}
