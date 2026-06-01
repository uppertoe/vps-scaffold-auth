package server

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
)

// F1: a principal who is no longer permitted (domain de-listed, admin removed)
// must lose access at the next renewal, not have their session silently
// extended. Before the fix, handleVerify kept the stale groups and re-issued
// the cookie, so an actively-used session was renewed forever.
func TestRevokedPrincipalNotRenewed(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)

	if rec := c.get("/verify", nil); rec.Code != http.StatusOK {
		t.Fatalf("initial /verify = %d, want 200", rec.Code)
	}

	// Access is revoked for everyone (domain de-listed, no admin override).
	srv.policy = authz.NewPolicy(nil, nil)
	// Push the clock past the renew threshold so /verify hits the renew path.
	srv.now = func() time.Time { return time.Now().Add(45 * time.Minute) }

	rec := c.get("/verify", nil)
	if rec.Code == http.StatusOK {
		t.Fatal("revoked principal still granted at renewal (access-revocation bypass)")
	}
	if ck := c.cookies[session.SessionCookie]; ck != nil {
		t.Errorf("stale session cookie not cleared after revocation: %v", ck)
	}
}

// A demotion (admin -> user) should still work: the user keeps access but loses
// the admin group at renewal.
func TestDemotedAdminLosesAdminGroupAtRenewal(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	if g := c.get("/verify", nil).Header().Get("Remote-Groups"); g != "admin" {
		t.Fatalf("initial groups = %q, want admin", g)
	}

	// admin@example.com is demoted to a plain user (still in an allowed domain).
	srv.policy = authz.NewPolicy([]string{"example.com"}, nil)
	srv.now = func() time.Time { return time.Now().Add(45 * time.Minute) }

	rec := c.get("/verify", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("demoted-but-allowed user = %d, want 200", rec.Code)
	}
	if g := rec.Header().Get("Remote-Groups"); g != "user" {
		t.Errorf("groups after demotion = %q, want user", g)
	}
}

// F2: an admin must not be able to mint a break-glass code whose target group
// is a reserved role. Such a code would grant the admin UI to anyone who scans
// the QR, with no second factor.
func TestBreakGlassCannotTargetReservedGroup(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	tok := extractCSRF(t, c.get("/admin/break", nil).Body.String())

	rec := c.postForm("/admin/break", url.Values{"csrf": {tok}, "label": {"Evil"}, "group": {"admin"}})
	if rec.Code == http.StatusFound {
		t.Fatal("break-glass code targeting group 'admin' was created (privilege-escalation footgun)")
	}
	if codes, _ := srv.store.ListBreakGlassCodes(context.Background()); len(codes) != 0 {
		t.Errorf("reserved-group code should not have been stored, got %+v", codes)
	}
}

// F2: a DB group must not be named after a reserved role either; a member of a
// group literally named "admin" would otherwise get admin via Remote-Groups.
func TestReservedGroupNameRejected(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	tok := extractCSRF(t, c.get("/admin/groups", nil).Body.String())

	c.postForm("/admin/groups", url.Values{"csrf": {tok}, "name": {"admin"}, "label": {"x"}})
	groups, _ := srv.store.ListGroups(context.Background())
	for _, g := range groups {
		if g.Name == authz.RoleAdmin {
			t.Fatal("a DB group named 'admin' was created (would confer admin via Remote-Groups)")
		}
	}
}

// F2 (defense in depth): even a pre-existing code whose target group is "admin"
// (e.g. created before the guard, or written directly to the DB) must not let a
// break-glass session reach the admin UI.
func TestBreakGlassSessionRejectedFromAdminUI(t *testing.T) {
	srv, _ := testServer(t)
	token := mintCode(t, srv, "Sneaky", authz.RoleAdmin)
	c := newClient(t, srv.Handler())
	if rec := c.get("/break/"+token, nil); rec.Code != http.StatusFound {
		t.Fatalf("scan = %d, want 302", rec.Code)
	}
	if rec := c.get("/admin/break", nil); rec.Code == http.StatusOK {
		t.Fatal("break-glass session granted admin UI access (second-factor bypass)")
	}
}
