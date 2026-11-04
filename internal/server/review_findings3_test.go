// Regression tests from the security review of 2026-11-04: each failed
// while its finding stood.
package server

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
)

// P8: a guest keeps a group that becomes an app role after sign-in, until
// the next scheduled renewal; a routes change is not a membership change.
func TestReviewGuestKeepsGroupThatBecomesAppRole(t *testing.T) {
	srv, sender := appRoleServer(t, func(c *config.Config) {
		c.OpenRegistrationHosts = []string{"apply.example.com"}
	})
	ctx := context.Background()
	_ = srv.store.CreateGroup(ctx, "reviewers", "")
	_, _ = srv.store.AddGroupMembers(ctx, "reviewers", []string{strangerAddr})
	g := newClient(t, srv.Handler())
	loginGuest(t, g, sender, strangerAddr)
	t.Logf("guest groups at sign-in: %q", sessionOf(t, srv, g).Groups)
	b, _ := os.ReadFile(srv.cfg.RouteAccessFile)
	_ = os.WriteFile(srv.cfg.RouteAccessFile, append(b, []byte("rev.{$DOMAIN}\tgroups\treviewers admin\n")...), 0o600)
	if !srv.appRoleGroups()["reviewers"] {
		t.Fatal("reviewers not an app role after the routes change")
	}
	rec := g.get("/verify", map[string]string{"X-Auth-Policy": "groups=reviewers admin"})
	t.Logf("after routes change: %d groups=%q", rec.Code, rec.Header().Get("Remote-Groups"))
	if rec.Code == http.StatusOK && strings.Contains(rec.Header().Get("Remote-Groups"), "reviewers") {
		t.Errorf("guest still carries 'reviewers' after it became an app role")
	}
}
