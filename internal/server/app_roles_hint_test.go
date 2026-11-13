package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// roleLoginURL asks /verify for a role guard's page with no session and
// returns the login URL's query.
func roleLoginURL(t *testing.T, srv *Server, app, role string) url.Values {
	t.Helper()
	h := roleGuard(app, role)
	h["X-Forwarded-Host"] = app + ".example.com"
	h["X-Forwarded-Uri"] = "/"
	rec := newClient(t, srv.Handler()).get("/verify", h)
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.HasPrefix(loc, "https://auth.example.com/login?") {
		t.Fatalf("/verify for %s %s: %d to %q, want the login page", app, role, rec.Code, loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

// A role guard hints the domains of the domain groups holding its role only
// when domain groups are its only assignments: as rqd, which declines early,
// when nothing else could admit anyone, and as rhd beside rqr=1 when a card
// or an open invitation could. Any other holder gives rqr=1 alone, so an
// anonymous visitor learns no more about it than that mark.
func TestRoleGuardLoginHint(t *testing.T) {
	type hint struct{ rqd, rqr, rhd string }
	cases := []struct {
		name   string
		setup  func(t *testing.T, srv *Server)
		app    string
		role   string
		want   hint
		reason string
	}{
		{
			name: "domain groups only", app: "enquiries", role: "admin",
			setup: func(t *testing.T, srv *Server) {
				assignDomains(t, srv, "enquiries", "admin", "rch", "rch.org.au", "rchvic.org")
				assignDomains(t, srv, "enquiries", "admin", "mch", "monashhealth.org", "rch.org.au")
			},
			want: hint{rqd: "monashhealth.org rch.org.au rchvic.org"},
		},
		{
			name: "a domain group and a list", app: "enquiries", role: "admin",
			setup: func(t *testing.T, srv *Server) {
				assignDomains(t, srv, "enquiries", "admin", "rch", "rch.org.au")
				mustListGroup(t, srv, "exec")
				mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "admin", Kind: store.AssignList, Ref: "exec"})
			},
			want: hint{rqr: "1"},
		},
		{
			name: "a domain group and a current person", app: "enquiries", role: "admin",
			setup: func(t *testing.T, srv *Server) {
				assignDomains(t, srv, "enquiries", "admin", "rch", "rch.org.au")
				mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "admin", Kind: store.AssignPerson, Ref: "p@partner.org", How: store.AssignedByAdmin})
			},
			want: hint{rqr: "1"},
		},
		{
			name: "a domain group and an ended person", app: "enquiries", role: "admin",
			setup: func(t *testing.T, srv *Server) {
				assignDomains(t, srv, "enquiries", "admin", "rch", "rch.org.au")
				mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "admin", Kind: store.AssignPerson, Ref: "old@partner.org", How: store.AssignedByAdmin, Until: time.Now().Add(-time.Hour)})
			},
			want: hint{rqd: "rch.org.au"},
		},
		{
			name: "a domain group and guests", app: "caffeine", role: "user",
			setup: func(t *testing.T, srv *Server) {
				assignDomains(t, srv, "caffeine", "user", "rch", "rch.org.au")
				mustAssign(t, srv, store.RoleAssignment{App: "caffeine", Role: "user", Kind: store.AssignGuests})
			},
			want: hint{rqr: "1"},
		},
		{
			name: "a domain group and a network", app: "caffeine", role: "user",
			setup: func(t *testing.T, srv *Server) {
				assignDomains(t, srv, "caffeine", "user", "rch", "rch.org.au")
				mustAssign(t, srv, store.RoleAssignment{App: "caffeine", Role: "user", Kind: store.AssignNetwork, Ref: "theatre"})
			},
			want: hint{rqr: "1"},
		},
		{
			name: "the user role counts every role in the app", app: "enquiries", role: "user",
			setup: func(t *testing.T, srv *Server) {
				assignDomains(t, srv, "enquiries", "admin", "rch", "rch.org.au")
				assignDomains(t, srv, "enquiries", "user", "mch", "monashhealth.org")
			},
			want: hint{rqd: "monashhealth.org rch.org.au"},
		},
		{
			name: "the user role is not declined when a list holds another role", app: "enquiries", role: "user",
			setup: func(t *testing.T, srv *Server) {
				assignDomains(t, srv, "enquiries", "user", "rch", "rch.org.au")
				mustListGroup(t, srv, "exec")
				mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "admin", Kind: store.AssignList, Ref: "exec"})
			},
			want: hint{rqr: "1"},
		},
		{
			name: "another role's holders do not count for a role other than user", app: "enquiries", role: "admin",
			setup: func(t *testing.T, srv *Server) {
				assignDomains(t, srv, "enquiries", "admin", "rch", "rch.org.au")
				mustListGroup(t, srv, "exec")
				mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "user", Kind: store.AssignList, Ref: "exec"})
				mustAssign(t, srv, store.RoleAssignment{App: "caffeine", Role: "admin", Kind: store.AssignList, Ref: "exec"})
			},
			want: hint{rqd: "rch.org.au"},
		},
		{
			name: "a card on the app's user role", app: "nd", role: "user",
			setup: func(t *testing.T, srv *Server) {
				assignDomains(t, srv, "nd", "user", "rch", "rch.org.au")
				cardFor(t, srv, "nd")
			},
			want: hint{rqr: "1", rhd: "rch.org.au"},
		},
		{
			name: "a card does not hold a role other than user", app: "enquiries", role: "admin",
			setup: func(t *testing.T, srv *Server) {
				assignDomains(t, srv, "enquiries", "admin", "rch", "rch.org.au")
				cardFor(t, srv, "enquiries")
			},
			want: hint{rqd: "rch.org.au"},
		},
		{
			name: "an open invitation for the role", app: "enquiries", role: "admin",
			setup: func(t *testing.T, srv *Server) {
				assignDomains(t, srv, "enquiries", "admin", "rch", "rch.org.au")
				inviteTo(t, srv, "enquiries", "admin")
			},
			want: hint{rqr: "1", rhd: "rch.org.au"},
		},
		{
			name: "an open invitation for any role, at the user role", app: "enquiries", role: "user",
			setup: func(t *testing.T, srv *Server) {
				assignDomains(t, srv, "enquiries", "user", "rch", "rch.org.au")
				inviteTo(t, srv, "enquiries", "admin")
			},
			want: hint{rqr: "1", rhd: "rch.org.au"},
		},
		{
			name: "no domain group", app: "enquiries", role: "admin",
			setup: func(t *testing.T, srv *Server) {
				mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "admin", Kind: store.AssignPerson, Ref: "p@partner.org", How: store.AssignedByAdmin})
			},
			want: hint{rqr: "1"},
		},
		{
			name: "nobody holds the role", app: "enquiries", role: "admin",
			setup: func(t *testing.T, srv *Server) {},
			want:  hint{rqr: "1"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, _ := rolesServer(t, "theatre=192.0.2.0/24")
			c.setup(t, srv)
			q := roleLoginURL(t, srv, c.app, c.role)
			got := hint{rqd: q.Get("rqd"), rqr: q.Get("rqr"), rhd: q.Get("rhd")}
			if got != c.want {
				t.Errorf("login URL hint = %+v, want %+v", got, c.want)
			}
			if q.Has("rqg") || q.Has("dlabel") {
				t.Errorf("login URL carries a legacy guard's hint: %v", q)
			}
		})
	}
}

// From a role guard held only by domain groups, the login page hints the
// domains and /request declines an address at none of them, sending nothing;
// an address at one of them is sent a code.
func TestRoleGuardDeclinesEarlyForDomainGroupsOnly(t *testing.T) {
	srv, sender := rolesServer(t, "")
	assignDomains(t, srv, "enquiries", "admin", "rch", "rch.org.au")
	q := roleLoginURL(t, srv, "enquiries", "admin")
	c := newClient(t, srv.Handler())

	page := c.get("/login?"+q.Encode(), nil).Body.String()
	if !strings.Contains(page, "This page is for <strong>rch.org.au</strong> email addresses.") {
		t.Errorf("the login page does not hint the role's domain:\n%s", page)
	}
	if !strings.Contains(page, `name="rqd" value="rch.org.au"`) || strings.Contains(page, `name="rqr"`) {
		t.Errorf("the login page does not carry the decline as rqd:\n%s", page)
	}

	rec := c.postForm("/request", url.Values{"email": {"someone@outside.org"}, "rqd": {q.Get("rqd")}})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "This app is only available to rch.org.au email addresses.") {
		t.Fatalf("an address outside the domain: %d:\n%s", rec.Code, rec.Body.String())
	}
	if sentCount(sender) != 0 {
		t.Error("a code was sent to an address the role guard declines")
	}

	rec = c.postForm("/request", url.Values{"email": {"j.smith@rch.org.au"}, "rqd": {q.Get("rqd")}})
	if rec.Code != http.StatusOK || sender.code() == "" {
		t.Errorf("an address at the role's domain: %d, code %q; want the code page and a code", rec.Code, sender.code())
	}
}

// From a role guard that a list also holds, the login page hints no domain
// and never declines: an address that holds no role is sent no code and sees
// the ordinary code page, the same page a holder sees, so the page does not
// reveal who holds the role.
func TestRoleGuardWithOtherHoldersDoesNotDecline(t *testing.T) {
	srv, sender := rolesServer(t, "")
	assignDomains(t, srv, "enquiries", "admin", "rch", "rch.org.au")
	mustListGroup(t, srv, "exec")
	if err := srv.store.AddGroupMember(context.Background(), "exec", "x@partner.org"); err != nil {
		t.Fatal(err)
	}
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "admin", Kind: store.AssignList, Ref: "exec"})
	q := roleLoginURL(t, srv, "enquiries", "admin")
	c := newClient(t, srv.Handler())

	page := c.get("/login?"+q.Encode(), nil).Body.String()
	if strings.Contains(page, "rch.org.au") {
		t.Errorf("the login page reveals the domain group's domain:\n%s", page)
	}
	if !strings.Contains(page, `name="rqr" value="1"`) || strings.Contains(page, `name="rhd"`) || strings.Contains(page, `name="rqd"`) {
		t.Errorf("the login page does not carry the role guard's mark alone:\n%s", page)
	}

	form := func(email string) url.Values {
		return url.Values{"email": {email}, "rqr": {q.Get("rqr")}, "rhd": {q.Get("rhd")}}
	}
	nobody := c.postForm("/request", form("nobody@outside.org"))
	if nobody.Code != http.StatusOK || !strings.Contains(nobody.Body.String(), "nobody@outside.org") {
		t.Fatalf("an address with no role: %d, want the ordinary code page:\n%s", nobody.Code, nobody.Body.String())
	}
	if sentCount(sender) != 0 {
		t.Error("a code was sent to an address that holds no role")
	}
	holder := newClient(t, srv.Handler()).postForm("/request", form("x@partner.org"))
	if holder.Code != http.StatusOK || sender.code() == "" {
		t.Fatalf("a list member: %d, code %q; want the code page and a code", holder.Code, sender.code())
	}
	// The two pages differ only in the address they name.
	if strings.ReplaceAll(nobody.Body.String(), "nobody@outside.org", "") != strings.ReplaceAll(holder.Body.String(), "x@partner.org", "") {
		t.Error("the code page differs between an address with no role and a holder")
	}
}

// A role guard with no domain group to hint suppresses the allow-list's
// domains, which say nothing about who holds the role, as a group door does.
func TestRoleGuardWithoutDomainsHintsNothing(t *testing.T) {
	srv, _ := rolesServer(t, "")
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "admin", Kind: store.AssignPerson, Ref: "p@partner.org", How: store.AssignedByAdmin})
	q := roleLoginURL(t, srv, "enquiries", "admin")
	page := newClient(t, srv.Handler()).get("/login?"+q.Encode(), nil).Body.String()
	// The generic placeholder is you@example.com, the same as the test
	// allow-list's, so only the hint line is checked.
	if strings.Contains(page, "This page is for") {
		t.Errorf("the login page hints the allow-list at a role guard:\n%s", page)
	}
	if !strings.Contains(page, `name="rqr" value="1"`) {
		t.Errorf("the login page does not carry the role guard's mark:\n%s", page)
	}
}

func assignDomains(t *testing.T, srv *Server, app, role, group string, domains ...string) {
	t.Helper()
	groups, err := srv.store.ListGroupDomains(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := groups[group]; !ok {
		mustDomainGroup(t, srv, group, domains...)
	}
	mustAssign(t, srv, store.RoleAssignment{App: app, Role: role, Kind: store.AssignDomainGroup, Ref: group})
}

func mustListGroup(t *testing.T, srv *Server, name string) {
	t.Helper()
	if err := srv.store.CreateGroup(context.Background(), name, ""); err != nil {
		t.Fatal(err)
	}
}

func cardFor(t *testing.T, srv *Server, app string) {
	t.Helper()
	ctx := context.Background()
	mintCode(t, srv, "Lab 1", "bg_lab")
	codes, err := srv.store.ListBreakGlassCodes(ctx)
	if err != nil || len(codes) != 1 {
		t.Fatalf("codes = %v, %v", codes, err)
	}
	if err := srv.store.SetBreakGlassRole(ctx, codes[0].ID, app, "user"); err != nil {
		t.Fatal(err)
	}
	srv.forgetRoles()
}

func inviteTo(t *testing.T, srv *Server, app, role string) {
	t.Helper()
	now := time.Now()
	if _, err := srv.store.CreateInvitations(context.Background(), []store.Invitation{{
		Email: "k.lee@monash.org", App: app, Role: role, TokenHash: "h", CreatedBy: "admin@example.com",
		CreatedAt: now, SentAt: now, ExpiresAt: now.Add(inviteTTL),
	}}, nil); err != nil {
		t.Fatal(err)
	}
	srv.forgetRoles()
}
