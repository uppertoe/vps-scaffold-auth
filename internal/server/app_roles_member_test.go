package server

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// wantMemberOnOlderGuards checks that a session is no more than a guest on
// the older guards: refused by "any" and by a domain policy (even one naming
// its own domain), admitted where guests are, and by a group it is in.
func wantMemberOnOlderGuards(t *testing.T, who string, c *client, domain, group string) {
	t.Helper()
	wantDenied(t, who+` on X-Auth-Policy "any"`, c.get("/verify", protectedAny()))
	wantDenied(t, who+" on a domain policy", c.get("/verify", requireDomains(domain)))
	wantDenied(t, who+" on a group policy it is not in", c.get("/verify", requireGroups("nobody-here")))
	rec := c.get("/verify", map[string]string{"X-Auth-Policy": "any;guests=allow"})
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Remote-Groups"), authz.RoleGuest) {
		t.Errorf("%s where guests are allowed = %d, groups %q; want 200 and the guest tier", who, rec.Code, rec.Header().Get("Remote-Groups"))
	}
	if group != "" {
		if rec := c.get("/verify", requireGroups(group)); rec.Code != http.StatusOK {
			t.Errorf("%s on a policy naming its group = %d, want 200", who, rec.Code)
		}
	}
}

// A person who may sign in only because of an app role is a member: their
// role guard decides by their roles, and every older guard treats them as it
// would a guest. An allow-listed person is unaffected.
func TestRoleOnlyPersonIsAMember(t *testing.T) {
	srv, sender := rolesServer(t, "")
	ctx := context.Background()
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "admin", Kind: store.AssignPerson, Ref: "p@partner.org", How: store.AssignedByAdmin})
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "user", Kind: store.AssignPerson, Ref: "user@example.com", How: store.AssignedByAdmin})
	if err := srv.store.CreateGroup(ctx, "fellows", ""); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.AddGroupMember(ctx, "fellows", "p@partner.org"); err != nil {
		t.Fatal(err)
	}

	p := newClient(t, srv.Handler())
	loginAs(t, p, sender, "p@partner.org", nil)
	if id := sessionOf(t, srv, p); id.Kind != session.KindMember || !strings.HasPrefix(id.Groups, authz.RoleGuest+",") {
		t.Fatalf("role-only session: kind %q, groups %q; want member, guest tier", id.Kind, id.Groups)
	}
	rec := p.get("/verify", withHost(roleGuard("enquiries", "admin"), "enquiries.example.com"))
	if rec.Code != http.StatusOK || rec.Header().Get("Remote-Roles") != "admin" {
		t.Fatalf("role guard = %d, roles %q; want 200, admin", rec.Code, rec.Header().Get("Remote-Roles"))
	}
	if g := rec.Header().Get("Remote-Groups"); g == authz.RoleUser || authz.HasGroup(g, authz.RoleUser) {
		t.Errorf("role guard sent Remote-Groups %q to a member", g)
	}
	wantMemberOnOlderGuards(t, "a role-only person", p, "partner.org", "fellows")

	// The allow-listed person is exactly as before.
	u := newClient(t, srv.Handler())
	loginAs(t, u, sender, "user@example.com", nil)
	if id := sessionOf(t, srv, u); id.Kind != "" || id.Groups != authz.RoleUser {
		t.Errorf("allow-listed session: kind %q, groups %q", id.Kind, id.Groups)
	}
	for _, h := range []map[string]string{protectedAny(), requireDomains("example.com"), withHost(roleGuard("enquiries", ""), "enquiries.example.com")} {
		if rec := u.get("/verify", h); rec.Code != http.StatusOK || rec.Header().Get("Remote-Groups") != authz.RoleUser {
			t.Errorf("allow-listed person on %v = %d, groups %q", h, rec.Code, rec.Header().Get("Remote-Groups"))
		}
	}
}

// An invitee who accepts through the invitation's code step is a member too.
func TestInviteeIsAMember(t *testing.T) {
	srv, sender, ml, c := inviteAdmin(t)
	invite(t, c, adminInviteForm("k.lee@monash.org"))
	link := inviteLinkIn(t, ml.waitFor(1, invitationsTo("k.lee@monash.org"))[0])
	p := newClient(t, srv.Handler())
	sender.reset()
	p.postForm("/invite/send", url.Values{"token": {strings.TrimPrefix(link, "/invite/")}})
	rec := p.postForm("/verify-code", url.Values{"code": {sender.code()}})
	if rec.Code != http.StatusFound {
		t.Fatalf("verify-code = %d", rec.Code)
	}
	if id := sessionOf(t, srv, p); id.Kind != session.KindMember {
		t.Fatalf("invitee session kind = %q, want member", id.Kind)
	}
	if done := html.UnescapeString(p.get(rec.Header().Get("Location"), nil).Body.String()); !strings.Contains(done, "Your invitation has been accepted") {
		t.Errorf("done page:\n%s", done)
	}
	if rec := p.get("/verify", withHost(roleGuard("enquiries", "admin"), "enquiries.example.com")); rec.Code != http.StatusOK {
		t.Errorf("invitee on the role guard = %d, want 200", rec.Code)
	}
	wantMemberOnOlderGuards(t, "an invitee", p, "monash.org", "")
}

// Renewal keeps a member a member, turns a member whom the allow-list now
// admits into an ordinary session at once, and turns a normal session whose
// address has left the allow-list but holds a role into a member at once.
func TestMemberTierAtRenewal(t *testing.T) {
	srv, sender := rolesServer(t, "")
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "user", Kind: store.AssignPerson, Ref: "p@partner.org", How: store.AssignedByAdmin})
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "user", Kind: store.AssignPerson, Ref: "amy@example.com", How: store.AssignedByAdmin})
	start := time.Now()
	srv.now = func() time.Time { return start }
	p := newClient(t, srv.Handler())
	loginAs(t, p, sender, "p@partner.org", nil)
	a := newClient(t, srv.Handler())
	loginAs(t, a, sender, "amy@example.com", nil)

	// A scheduled renewal keeps the member's kind and tier.
	later := start.Add(srv.cfg.SessionRenew + time.Minute)
	srv.now = func() time.Time { return later }
	before := sessionOf(t, srv, p).Iat
	if rec := p.get("/verify", roleGuard("enquiries", "")); rec.Code != http.StatusOK {
		t.Fatalf("member after renewal = %d", rec.Code)
	}
	if id := sessionOf(t, srv, p); id.Iat == before || id.Kind != session.KindMember || !strings.HasPrefix(id.Groups, authz.RoleGuest) {
		t.Errorf("renewed member: iat %d (was %d), kind %q, groups %q", id.Iat, before, id.Kind, id.Groups)
	}
	wantDenied(t, "a renewed member on any", p.get("/verify", protectedAny()))

	// The allow-list changes: partner.org joins, example.com leaves.
	srv.cfg.AllowedDomains = []string{"partner.org"}
	srv.policy = newPolicyFor(srv.cfg)
	if rec := p.get("/verify", protectedAny()); rec.Code != http.StatusOK || rec.Header().Get("Remote-Groups") != authz.RoleUser {
		t.Errorf("member now on the allow-list = %d, groups %q; want 200, user", rec.Code, rec.Header().Get("Remote-Groups"))
	}
	if id := sessionOf(t, srv, p); id.Kind != "" {
		t.Errorf("kind after joining the allow-list = %q, want ordinary", id.Kind)
	}
	wantDenied(t, "a person who left the allow-list but holds a role", a.get("/verify", protectedAny()))
	if id := sessionOf(t, srv, a); id.Kind != session.KindMember {
		t.Errorf("kind after leaving the allow-list = %q, want member", id.Kind)
	}
	if rec := a.get("/verify", roleGuard("enquiries", "")); rec.Code != http.StatusOK {
		t.Errorf("former staff member with a role on the role guard = %d, want 200", rec.Code)
	}
}
