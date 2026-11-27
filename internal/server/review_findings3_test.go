// Regression tests from the security review of 2026-11-04: each failed
// while its finding stood.
package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// P8: a guest keeps a list that closes after sign-in, until the next
// scheduled renewal; a role change is not a membership change. The list is
// dropped at the guest's next request instead.
func TestReviewOutsiderLosesAListThatCloses(t *testing.T) {
	srv, sender := testServerWith(t, func(c *config.Config) {
		c.OpenRegistrationHosts = []string{"apply.example.com"}
	})
	ctx := context.Background()
	_ = srv.store.CreateGroup(ctx, "reviewers", "")
	_, _ = srv.store.AddGroupMembers(ctx, "reviewers", []string{strangerAddr})
	guard := groupGuard(t, srv, "reviewers")
	g := newClient(t, srv.Handler())
	loginGuest(t, g, sender, strangerAddr)
	if rec := g.get("/verify", guard); rec.Code != http.StatusOK {
		t.Fatalf("guest on an open list = %d, want 200", rec.Code)
	}
	mustAssign(t, srv, store.RoleAssignment{App: appForGroup("reviewers"), Role: "admin", Kind: store.AssignList, Ref: "reviewers"})
	if closed, _ := srv.closedLists(ctx); !closed["reviewers"] {
		t.Fatal("reviewers is not closed once it holds Administrator")
	}
	// The member's only role came through reviewers, so the refusal ends
	// the session as well.
	if rec := g.get("/verify", guard); rec.Code == http.StatusOK {
		t.Errorf("guest still reaches the app through reviewers after it closed")
	}
}
