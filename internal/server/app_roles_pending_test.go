package server

import (
	"net/http"
	"os"
	"path/filepath"
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
