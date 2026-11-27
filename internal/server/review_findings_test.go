// Regression tests from the security review of 2026-11-04: each failed
// while its finding stood.
package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/passkey/passkeytest"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
)

// P2: TOTP off; a staff member promoted to admin opens /admin directly.
func TestReviewPromotedAdminWithTOTPOffAtAdminPages(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)
	srv.cfg.AdminEmails = []string{"admin@example.com", "user@example.com"}
	srv.policy = newPolicyFor(srv.cfg)
	rec := c.get("/admin/", nil)
	t.Logf("/admin/ = %d loc=%q", rec.Code, rec.Header().Get("Location"))
	door := c.get("/totp?rd="+url.QueryEscape("https://auth.example.com/admin/"), nil)
	t.Logf("/totp = %d loc=%q body-has-setup=%v", door.Code, door.Header().Get("Location"),
		strings.Contains(door.Body.String(), "authenticator app, which has not been set up"))
	if rec.Code != http.StatusOK && door.Code == http.StatusForbidden {
		t.Errorf("with TOTP off a promoted admin is asked for an authenticator they cannot have")
	}
	// A /verify request repairs it.
	c.get("/verify", anyGuard(t, srv))
	t.Logf("/admin/ after a /verify = %d", c.get("/admin/", nil).Code)
}

// P3: a passkey for the victim's account held by an attacker, and a session
// cookie overwritten by a sibling app: the victim's code at the door upgrades
// the attacker's passkey for good.
func TestReviewDoorUpgradesPasskeyOfPlantedSession(t *testing.T) {
	srv, sender := pkServer(t, nil)
	// While victim is staff, the attacker (with the inbox) adds a passkey.
	att := newClient(t, srv.Handler())
	a := passkeytest.New()
	register(t, att, a, phoneSignIn(t, att, sender, "user@example.com").Body.String(), nil)
	// Victim later becomes an administrator with TOTP.
	srv.cfg.TOTPEnabled = true
	srv.cfg.AdminEmails = []string{"admin@example.com", "user@example.com"}
	srv.policy = newPolicyFor(srv.cfg)
	secret := provisionTOTP(t, srv, "user@example.com")

	// Attacker signs in with the passkey and plants that cookie in the victim's browser.
	atk := newClient(t, srv.Handler())
	signInWith(t, atk, a)
	victim := newClient(t, srv.Handler())
	victim.cookies[session.SessionCookie] = atk.cookies[session.SessionCookie]

	door := victim.get("/totp", phone)
	if door.Code != http.StatusOK {
		t.Fatalf("door = %d", door.Code)
	}
	rec := victim.postWith("/totp", url.Values{"code": {totpNow(t, secret, time.Now())}, "csrf": {extractCSRF(t, door.Body.String())}}, phone)
	t.Logf("victim's code at door = %d", rec.Code)

	later := newClient(t, srv.Handler())
	srv.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	signInWith(t, later, a)
	if got := later.get("/admin/", nil); got.Code == http.StatusOK {
		t.Errorf("the attacker's passkey now opens /admin alone, days later")
	}
}

// P4: the guest filter fails closed while the role data cannot be read: an
// outsider keeps none of the lists, and keeps the leading guest role.
func TestReviewGuestFilterFailsClosedWhileRolesUnread(t *testing.T) {
	srv, _ := staffOnlyListServer(t, nil)
	openToGuestsForTest(t, srv, "apply")
	ctx := context.Background()
	_ = srv.store.CreateGroup(ctx, "collaborators", "")
	_, _ = srv.store.AddGroupMembers(ctx, "collaborators", []string{strangerAddr})
	_, _ = srv.store.AddGroupMembers(ctx, "planka-users", []string{strangerAddr})
	_ = srv.store.AddGroupInclude(ctx, "prototypes", "collaborators")
	good := srv.store
	srv.store = assignmentsReadFail{good}
	srv.roleCache.mu.Lock()
	srv.roleCache.ok, srv.roleCache.have, srv.roleCache.state = false, false, roleState{}
	srv.roleCache.mu.Unlock()
	if _, loaded := srv.staffOnlyLists(ctx); loaded {
		t.Fatal("the role data reads as loaded")
	}
	got := srv.computeGroups(ctx, strangerAddr, "guest")
	t.Logf("guest groups with the role data unreadable: %q", got)
	if got != "guest" {
		t.Errorf("guest groups = %q, want the leading guest role alone", got)
	}
	srv.store = good
	srv.forgetRoles()
	if got := srv.computeGroups(ctx, strangerAddr, "guest"); got != "guest,collaborators,planka-users" {
		t.Errorf("guest groups once the data can be read = %q", got)
	}
}

// P5: a card use costs two break-glass limiter tokens (scan + post).
func TestReviewBreakGlassChargesTwice(t *testing.T) {
	srv, _ := testServerWith(t, func(c *config.Config) {
		c.RateLimitBreakGlassPerIP = config.RateLimit{Count: 2, Window: time.Hour}
	})
	token := mintCode(t, srv, "Lab 1", "g")
	c := newClient(t, srv.Handler())
	if rec := c.get("/break/"+token, nil); rec.Code != http.StatusOK {
		t.Fatalf("scan = %d", rec.Code)
	}
	rec := c.postForm("/break", url.Values{"token": {token}})
	t.Logf("first use: post = %d", rec.Code)
	c2 := newClient(t, srv.Handler())
	rec = c2.get("/break/"+token, nil)
	t.Logf("second person, same IP, limit 2: scan = %d", rec.Code)
	if rec.Code == http.StatusTooManyRequests {
		t.Errorf("one use spends two limiter tokens")
	}
}
