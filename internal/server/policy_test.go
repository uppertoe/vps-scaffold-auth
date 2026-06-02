package server

import (
	"context"
	"net/http"
	"testing"
)

func TestParsePolicy(t *testing.T) {
	tests := []struct {
		in              string
		domains, groups string
	}{
		{"", "", ""},
		{"any", "", ""}, // sentinel / unknown field → no requirement
		{"domains=rch.org.au", "rch.org.au", ""},
		{"groups=dashboard", "", "dashboard"},
		{"domains=a.com b.com;groups=g1 g2", "a.com b.com", "g1 g2"},
		{"groups=g;domains=a.com", "a.com", "g"}, // order-independent
		{"  domains = a.com ; groups = g ", "a.com", "g"},
		{"mode=any;domains=a.com", "a.com", ""}, // unknown field ignored
	}
	for _, tc := range tests {
		d, g := parsePolicy(tc.in)
		if d != tc.domains || g != tc.groups {
			t.Errorf("parsePolicy(%q) = (%q,%q), want (%q,%q)", tc.in, d, g, tc.domains, tc.groups)
		}
	}
}

// protected_access semantics: domain OR group. A user who fails the domain but
// is in a listed group is allowed, carried in the single combined policy header.
func TestPerAppAccessCombined(t *testing.T) {
	srv, sender := testServer(t)
	ctx := context.Background()
	if err := srv.store.CreateGroup(ctx, "dashboard", ""); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.AddGroupMember(ctx, "dashboard", "user@example.com"); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)

	// Domain mismatch (partner.com) but group match (dashboard) -> allowed.
	rec := c.get("/verify", map[string]string{"X-Auth-Policy": "domains=partner.com;groups=dashboard"})
	if rec.Code != http.StatusOK {
		t.Fatalf("combined domain-OR-group = %d, want 200", rec.Code)
	}
	// Neither domain nor group matches -> denied.
	rec = c.get("/verify", map[string]string{"X-Auth-Policy": "domains=partner.com;groups=finance"})
	if rec.Code != http.StatusFound {
		t.Fatalf("no match = %d, want 302 (denied)", rec.Code)
	}
}

// The "any" sentinel behaves exactly like a bare `protected` (absent policy):
// any signed-in user is allowed, and a client-injected policy can't widen it
// because the guard's header_up replaces whatever the client sent.
func TestPolicyAnyAllowsSignedIn(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)
	if rec := c.get("/verify", map[string]string{"X-Auth-Policy": "any"}); rec.Code != http.StatusOK {
		t.Fatalf(`policy "any" = %d, want 200`, rec.Code)
	}
}
