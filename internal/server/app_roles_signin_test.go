package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// rolesServerWith is rolesServer with further configuration.
func rolesServerWith(t *testing.T, adjust func(*config.Config)) (*Server, *captureSender) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app-roles.tsv")
	if err := os.WriteFile(path, []byte(testAppRoles), 0o600); err != nil {
		t.Fatal(err)
	}
	return testServerWith(t, func(c *config.Config) {
		c.AppRolesFile = path
		if adjust != nil {
			adjust(c)
		}
	})
}

// A person the allow-list refuses but who holds an app role may manage their
// passkeys, as they may sign in; without the role they still may not.
func TestPasskeyPageIsRoleAware(t *testing.T) {
	srv, sender := rolesServerWith(t, func(c *config.Config) { c.PasskeysEnabled = true })
	mustAssign(t, srv, store.RoleAssignment{App: "caffeine", Role: "user", Kind: store.AssignPerson, Ref: "visitor@other.org", How: store.AssignedByAdmin})
	c := newClient(t, srv.Handler())
	phoneSignIn(t, c, sender, "visitor@other.org")
	if rec := c.get("/passkeys", phone); rec.Code != http.StatusOK {
		t.Fatalf("passkeys page for a role holder = %d, want 200", rec.Code)
	}
	// Once the role is taken away, the page sends them to sign in.
	if err := srv.store.RemoveRoleAssignment(t.Context(), "caffeine", "user", store.AssignPerson, "visitor@other.org"); err != nil {
		t.Fatal(err)
	}
	srv.forgetRoles()
	if rec := c.get("/passkeys", phone); rec.Code != http.StatusFound {
		t.Errorf("passkeys page after the role was taken = %d, want a redirect", rec.Code)
	}
}

// Code alerts are sent for an address that may sign in through an app role,
// and still not for one that may not.
func TestCodeAlertsAreRoleAware(t *testing.T) {
	srv, sender := rolesServerWith(t, func(c *config.Config) {
		c.RateLimitPerEmailCeiling = config.RateLimit{Count: 100, Window: time.Hour}
		c.RateLimitPerEmailDaily = config.RateLimit{Count: 1, Window: 24 * time.Hour}
		c.OTPResendCooldown = 0
	})
	srv.cfg.AdminEmails = []string{"admin@example.com"}
	mustAssign(t, srv, store.RoleAssignment{App: "caffeine", Role: "user", Kind: store.AssignPerson, Ref: "visitor@other.org", How: store.AssignedByAdmin})
	for i := 1; i <= 3; i++ {
		requestFrom(newClient(t, srv.Handler()), fmt.Sprintf("198.51.100.%d", i), "visitor@other.org")
		requestFrom(newClient(t, srv.Handler()), fmt.Sprintf("198.51.101.%d", i), "stranger@other.org")
	}
	got := noticesAfter(sender, 1)
	if len(got) != 1 || got[0].Subject != "Sign-in codes for visitor@other.org have reached the daily limit" {
		t.Fatalf("alerts = %+v, want one, for the role holder only", got)
	}
}
