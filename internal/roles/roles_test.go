package roles

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

func TestParseManifest(t *testing.T) {
	in := strings.Join([]string{
		"# comment",
		"enquiries\tuser\tUser\tenquiries.{$DOMAIN}",
		"enquiries\tadmin\tAdministrator\tenquiries.{$DOMAIN}",
		"roster\tadmin\tAdministrator\troster.{$DOMAIN}", // no user role: left out
		"bad line",
		"Caps\tuser\tUser\tx.{$DOMAIN}",
		"caffeine\tuser\t\tcaffeine.{$DOMAIN}, CAFFEINE.{$DOMAIN}",
		"enquiries\tuser\tAgain\tenquiries.{$DOMAIN}",
		"",
	}, "\n")
	var logs []string
	m := ParseManifest(strings.NewReader(in), "rch-anaesthesia.org", func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) })
	if len(m.Apps) != 2 {
		t.Fatalf("apps = %v", m.Apps)
	}
	if !m.Has("enquiries", "admin") || !m.Has("enquiries", "user") || !m.Has("caffeine", "user") {
		t.Errorf("missing roles: %+v", m.Apps)
	}
	if m.Has("roster", "admin") || m.Has("caffeine", "admin") || m.Has("nope", "user") {
		t.Error("Has admits an undeclared app or role")
	}
	if m.Apps["enquiries"].Roles["user"] != "User" {
		t.Errorf("a duplicate line replaced the label: %q", m.Apps["enquiries"].Roles["user"])
	}
	if m.Apps["caffeine"].Roles["user"] != "user" {
		t.Errorf("empty label not defaulted: %q", m.Apps["caffeine"].Roles["user"])
	}
	if want := []string{"caffeine.rch-anaesthesia.org"}; !reflect.DeepEqual(m.Apps["caffeine"].Hosts, want) {
		t.Errorf("hosts = %v, want %v", m.Apps["caffeine"].Hosts, want)
	}
	if len(logs) != 4 {
		t.Errorf("logged %d problems, want 4: %q", len(logs), logs)
	}
}

func TestHeld(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	env := Env{
		Networks: map[string][]netip.Prefix{"rch": {netip.MustParsePrefix("10.40.0.0/16")}},
		Domains:  map[string][]string{"staff": {"rch.org.au", "mcri.edu.au"}},
		Now:      now,
	}
	as := []store.RoleAssignment{
		{App: "nd", Role: "user", Kind: store.AssignDomainGroup, Ref: "staff"},
		{App: "nd", Role: "user", Kind: store.AssignNetwork, Ref: "rch"},
		{App: "enq", Role: "user", Kind: store.AssignGuests},
		{App: "enq", Role: "admin", Kind: store.AssignList, Ref: "exec"},
		{App: "enq", Role: "admin", Kind: store.AssignPerson, Ref: "p@nsw.gov.au", Until: now.Add(time.Hour)},
		{App: "enq", Role: "admin", Kind: store.AssignPerson, Ref: "old@nsw.gov.au", Until: now.Add(-time.Second)},
		{App: "other", Role: "user", Kind: store.AssignDomainGroup, Ref: "staff"},
	}
	inside := netip.MustParseAddr("10.40.12.8")
	outside := netip.MustParseAddr("203.0.113.4")
	cases := []struct {
		name string
		app  string
		s    Subject
		want []string
	}{
		{"staff by domain", "nd", Subject{Session: true, Email: "A@RCH.org.au", Addr: outside}, []string{"user"}},
		{"other domain refused", "nd", Subject{Session: true, Email: "a@gmail.com", Addr: outside}, []string{}},
		{"no session inside the network", "nd", Subject{Addr: inside}, []string{"user"}},
		{"no session outside the network", "nd", Subject{Addr: outside}, []string{}},
		{"no session does not match a domain", "nd", Subject{Email: "a@rch.org.au", Addr: outside}, []string{}},
		{"mapped IPv4 inside the network", "nd", Subject{Addr: netip.MustParseAddr("::ffff:10.40.1.1")}, []string{"user"}},
		{"guest never matches a domain", "nd", Subject{Session: true, Guest: true, Email: "a@rch.org.au", Addr: outside}, []string{}},
		{"break-glass never matches a domain", "nd", Subject{Session: true, BreakGlass: true, Email: "breakglass:ops@rch.org.au", Addr: outside}, []string{}},
		{"card for this app", "nd", Subject{Session: true, BreakGlass: true, Email: "breakglass:Lab 1", CardApp: "nd", CardRole: "user", Addr: outside}, []string{"user"}},
		{"card for another app", "enq", Subject{Session: true, BreakGlass: true, Email: "breakglass:Lab 1", CardApp: "nd", CardRole: "user"}, []string{}},
		{"card naming a non-user role holds nothing", "enq", Subject{Session: true, BreakGlass: true, CardApp: "enq", CardRole: "admin"}, []string{}},
		{"card ignores guests and lists", "enq", Subject{Session: true, BreakGlass: true, Lists: map[string]bool{"exec": true}}, []string{}},
		{"card still admitted by a network", "nd", Subject{Session: true, BreakGlass: true, Addr: inside}, []string{"user"}},
		{"guest holds a guests role", "enq", Subject{Session: true, Guest: true, Email: "x@gmail.com"}, []string{"user"}},
		{"staff hold a guests role", "enq", Subject{Session: true, Email: "a@rch.org.au"}, []string{"user"}},
		{"guest on a list", "enq", Subject{Session: true, Guest: true, Email: "x@gmail.com", Lists: map[string]bool{"exec": true}}, []string{"admin", "user"}},
		{"current person", "enq", Subject{Session: true, Email: "P@nsw.gov.au"}, []string{"admin", "user"}},
		{"expired person", "enq", Subject{Session: true, Email: "old@nsw.gov.au"}, []string{"user"}},
		{"no session holds no guests role", "enq", Subject{}, []string{}},
	}
	for _, c := range cases {
		got := Held(c.app, c.s, as, env)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: Held = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAdmits(t *testing.T) {
	cases := []struct {
		held []string
		role string
		want bool
	}{
		{[]string{"admin"}, "user", true},
		{[]string{"admin"}, "admin", true},
		{[]string{"user"}, "admin", false},
		{nil, "user", false},
		{[]string{"editor"}, "admin", false},
	}
	for _, c := range cases {
		if got := Admits(c.held, c.role); got != c.want {
			t.Errorf("Admits(%v, %q) = %v, want %v", c.held, c.role, got, c.want)
		}
	}
}

func TestMaySignIn(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	env := Env{Domains: map[string][]string{"staff": {"rch.org.au"}}, Now: now}
	as := []store.RoleAssignment{
		{App: "a", Role: "user", Kind: store.AssignDomainGroup, Ref: "staff"},
		{App: "a", Role: "user", Kind: store.AssignList, Ref: "exec"},
		{App: "a", Role: "user", Kind: store.AssignPerson, Ref: "p@nsw.gov.au", Until: now.Add(time.Hour)},
		{App: "a", Role: "user", Kind: store.AssignPerson, Ref: "old@nsw.gov.au", Until: now.Add(-time.Hour)},
		{App: "a", Role: "user", Kind: store.AssignGuests},
		{App: "a", Role: "user", Kind: store.AssignNetwork, Ref: "rch"},
	}
	cases := []struct {
		email string
		lists map[string]bool
		want  bool
	}{
		{"a@rch.org.au", nil, true},
		{"x@gmail.com", map[string]bool{"exec": true}, true},
		{"P@NSW.gov.au", nil, true},
		{"old@nsw.gov.au", nil, false},
		{"x@gmail.com", nil, false}, // guests and networks do not let an address sign in
		{"not-an-address", nil, false},
	}
	for _, c := range cases {
		if got := MaySignIn(c.email, c.lists, as, env); got != c.want {
			t.Errorf("MaySignIn(%q) = %v, want %v", c.email, got, c.want)
		}
	}
}

// An older assignment of a network or guests to a role other than user
// gives nothing, and does not count against a sign-in hint's domains.
func TestNetworkAndGuestsIgnoredOnOtherRoles(t *testing.T) {
	env := Env{Networks: map[string][]netip.Prefix{"rch": {netip.MustParsePrefix("10.40.0.0/16")}},
		Domains: map[string][]string{"staff": {"rch.org.au"}}, Now: time.Unix(1_800_000_000, 0)}
	as := []store.RoleAssignment{
		{App: "enq", Role: "admin", Kind: store.AssignNetwork, Ref: "rch"},
		{App: "enq", Role: "admin", Kind: store.AssignGuests},
		{App: "enq", Role: "admin", Kind: store.AssignDomainGroup, Ref: "staff"},
	}
	inside := Subject{Addr: netip.MustParseAddr("10.40.1.1")}
	if got := Held("enq", inside, as, env); len(got) != 0 {
		t.Errorf("a network on the admin role gave %v", got)
	}
	guest := Subject{Session: true, Guest: true, Email: "x@gmail.com"}
	if got := Held("enq", guest, as, env); len(got) != 0 {
		t.Errorf("guests on the admin role gave %v", got)
	}
	if ds, only := SignInDomains("enq", "admin", as, env); !only || len(ds) != 1 {
		t.Errorf("SignInDomains = %v, %v; want the domain group alone", ds, only)
	}
}
