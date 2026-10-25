package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestParsePolicy(t *testing.T) {
	tests := []struct {
		in              string
		domains, groups string
	}{
		{"any", "", ""}, // the plain-protected sentinel
		{"domains=rch.org.au", "rch.org.au", ""},
		{"groups=dashboard", "", "dashboard"},
		{"domains=a.com b.com;groups=g1 g2", "a.com b.com", "g1 g2"},
		{"groups=g;domains=a.com", "a.com", "g"}, // order-independent
		{"  domains = a.com ; groups = g ", "a.com", "g"},
		{"any;", "", ""}, // a trailing separator is tolerated
	}
	for _, tc := range tests {
		d, g, _, ok := parsePolicy(tc.in)
		if !ok || d != tc.domains || g != tc.groups {
			t.Errorf("parsePolicy(%q) = (%q,%q,ok=%v), want (%q,%q,ok=true)", tc.in, d, g, ok, tc.domains, tc.groups)
		}
	}

	guests := []struct {
		in   string
		want bool
	}{
		{"any", false},
		{"any;guests=allow", true},
		{" any ; guests = allow ", true},
		{"guests=allow;groups=g", true},
		{"domains=a.com", false},
	}
	for _, tc := range guests {
		if _, _, got, ok := parsePolicy(tc.in); !ok || got != tc.want {
			t.Errorf("parsePolicy(%q) allowGuests = %v (ok=%v), want %v", tc.in, got, ok, tc.want)
		}
	}

	// Everything outside the exact grammar is invalid, so the caller denies. A
	// lenient reading of any of these would collapse a guard into "any
	// signed-in user".
	invalid := []string{
		"",
		"   ",
		"domains=", // empty allow-list
		"groups=",  // empty allow-list
		"domains= ;groups=g",
		"gruops=admin",           // misspelled field
		"mode=any;domains=a.com", // unknown field
		"domain=a.com",
		"any;domains=a.com", // the sentinel does not combine with a list
		"guests=allow",      // a guest flag with nothing to attach it to
		"any;guests=yes",    // only the exact value opens guests
		"any;guests=Allow",
		"any;guests",
		"ANY",
		"domains",
	}
	for _, in := range invalid {
		if d, g, guests, ok := parsePolicy(in); ok {
			t.Errorf("parsePolicy(%q) accepted as (%q,%q,guests=%v); want invalid", in, d, g, guests)
		}
	}
}

// A malformed policy denies a signed-in ordinary user at /verify: an empty
// allow-list or a misspelled field must never read as "any signed-in user".
func TestMalformedPolicyDeniesSignedInUser(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)
	for _, p := range []string{"groups=", "domains=", "gruops=admin", "mode=any;domains=example.com", "any;domains=example.com", ""} {
		rec := c.get("/verify", map[string]string{"X-Auth-Policy": p})
		if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/denied") {
			t.Errorf("policy %q: user got %d %q, want 302 to /denied", p, rec.Code, rec.Header().Get("Location"))
		}
	}
	// The well-formed forms still admit.
	for _, p := range []string{"any", "domains=example.com", "any;guests=allow"} {
		if rec := c.get("/verify", map[string]string{"X-Auth-Policy": p}); rec.Code != http.StatusOK {
			t.Errorf("policy %q: user got %d, want 200", p, rec.Code)
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
