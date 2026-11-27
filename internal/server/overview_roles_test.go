package server

import (
	"context"
	"html"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// The RCH shape: every gated site is behind a role guard.
const testRCHRoles = "insights\tuser\tUser\tinsights.{$DOMAIN}\n" +
	"insights\tadmin\tAdministrator\tinsights.{$DOMAIN}\n" +
	"@label\tinsights\tRoster insights\n" +
	"@path\tinsights\t*\tuser\n"

const testRCHAccess = "insights.{$DOMAIN}\troles\tinsights user admin\n" +
	"dept.{$DOMAIN}\tpublic\ta redirect to SharePoint, which signs people in itself\n"

func rchServer(t *testing.T) (*Server, *client) {
	t.Helper()
	return rchServerWith(t, nil)
}

func rchServerWith(t *testing.T, adjust func(*config.Config)) (*Server, *client) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	roles, access := write("app-roles.tsv", testRCHRoles), write("route-access.tsv", testRCHAccess)
	srv, sender := testServerWith(t, func(c *config.Config) {
		c.AppRolesFile, c.RouteAccessFile = roles, access
		c.AdminEmails = []string{"admin@example.com"}
		c.BreakGlassRefusedGroups = []string{"insights-admins"}
		if adjust != nil {
			adjust(c)
		}
	})
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	return srv, c
}

// unusedOnOverview returns the groups the Overview offers for deletion as
// unused, and whether it offered any.
func unusedOnOverview(t *testing.T, c *client) string {
	t.Helper()
	body := c.get("/admin/", nil).Body.String()
	_, after, ok := strings.Cut(body, "No app uses")
	if !ok {
		return ""
	}
	line, _, _ := strings.Cut(after, "</li>")
	return line
}

func mustGroup(t *testing.T, srv *Server, name string) {
	t.Helper()
	if err := srv.store.CreateGroupOfKind(context.Background(), name, "", store.GroupKindList); err != nil {
		t.Fatal(err)
	}
}

// RCH, with every site on roles: the groups that hold roles, are fed, are
// included, are read by an app, are a break-glass card's target or are named
// by a setting run the site. Only a group nothing uses is offered for
// deletion, and the Groups pages agree.
func TestOverviewUnusedGroupsCountEveryUse(t *testing.T) {
	srv, c := rchServerWith(t, func(c *config.Config) {
		c.GroupFeeds = []config.GroupFeed{{Group: "rch-fellows", URL: "https://feed.example.org/fellows", Token: testFeedToken}}
		c.MemberReadersFilePairs = map[string][]string{"insights": {"rch-registrars"}}
	})
	ctx := context.Background()
	for _, g := range []string{"rch-staff", "rch-fellows", "rch-trainees", "insights-admins", "rch-registrars", "bg_ward", "leftover"} {
		mustGroup(t, srv, g)
	}
	// rch-staff holds a role; rch-trainees is included in rch-staff;
	// rch-fellows is a feed; insights-admins is in BREAKGLASS_REFUSED_GROUPS;
	// rch-registrars is read by an app; bg_ward is a card's target.
	mustAssign(t, srv, store.RoleAssignment{App: "insights", Role: "user", Kind: store.AssignList, Ref: "rch-staff"})
	if err := srv.store.AddGroupInclude(ctx, "rch-staff", "rch-trainees"); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.store.CreateBreakGlassCode(ctx, store.BreakGlassCode{Label: "Ward", TargetGroup: "bg_ward", Status: "active"}); err != nil {
		t.Fatal(err)
	}

	line := unusedOnOverview(t, c)
	if !strings.Contains(line, "/admin/groups/leftover") {
		t.Errorf("the Overview does not offer the unused group leftover: %q", line)
	}
	for _, g := range []string{"rch-staff", "rch-fellows", "rch-trainees", "insights-admins", "rch-registrars", "bg_ward"} {
		if strings.Contains(line, "/admin/groups/"+g+"\"") {
			t.Errorf("the Overview offers %s for deletion as unused: %q", g, line)
		}
		page := c.get("/admin/groups/"+g, nil).Body.String()
		if strings.Contains(page, "Not used by any app") {
			t.Errorf("the page of %s says it is not used by any app", g)
		}
	}
	if page := c.get("/admin/groups/leftover", nil).Body.String(); !strings.Contains(page, "Not used by any app") {
		t.Error("the page of leftover does not say it is not used by any app")
	}

	// The role goes, and rch-staff is unused; rch-trainees is still
	// included in it, so it stays in use.
	if err := srv.store.RemoveGroupInclude(ctx, "rch-staff", "rch-trainees"); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.AddGroupInclude(ctx, "leftover", "rch-trainees"); err != nil {
		t.Fatal(err)
	}
	if line := unusedOnOverview(t, c); strings.Contains(line, "/admin/groups/rch-trainees\"") {
		t.Errorf("the Overview offers an included group for deletion: %q", line)
	}
}

// Every site behind a role guard is listed in "Who can reach what", pointing
// to its app's page, beside the sites open by design.
func TestOverviewReachListsRoleGuardedSites(t *testing.T) {
	_, c := rchServer(t)
	body := c.get("/admin/", nil).Body.String()
	_, table, ok := strings.Cut(body, "Who can reach what")
	if !ok {
		t.Fatal("the Overview has no table of who can reach what")
	}
	for _, want := range []string{
		"insights.example.com",
		`App roles: see <a href="/admin/apps/insights">Roster insights</a>`,
		"dept.example.com",
		"Open to everyone",
		html.EscapeString(msgReachIntro),
	} {
		if !strings.Contains(table, want) {
			t.Errorf("the table lacks %q", want)
		}
	}
	if n := strings.Count(table, "App roles: see"); n != 1 {
		t.Errorf("insights is listed %d times, want once (two roles, one app)", n)
	}
}
