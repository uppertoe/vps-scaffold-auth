package store

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestGroupKindsAndDomainRules(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	mustGroups(t, s, "consultants")
	if err := s.CreateGroupOfKind(ctx, "staff", "RCH and MCRI staff", GroupKindDomain); err != nil {
		t.Fatal(err)
	}
	groups, err := s.ListGroups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, g := range groups {
		kinds[g.Name] = g.Kind
	}
	if kinds["consultants"] != GroupKindList || kinds["staff"] != GroupKindDomain {
		t.Fatalf("kinds = %v", kinds)
	}
	// The kind of an existing group cannot change.
	if err := s.CreateGroupOfKind(ctx, "consultants", "", GroupKindDomain); !errors.Is(err, ErrGroupKind) {
		t.Errorf("changing kind: err = %v, want ErrGroupKind", err)
	}
	for _, d := range []string{"@RCH.org.au", "mcri.edu.au", "rch.org.au"} {
		if err := s.AddGroupDomain(ctx, "staff", d); err != nil {
			t.Fatalf("AddGroupDomain(%q): %v", d, err)
		}
	}
	cases := []struct {
		group, domain string
		want          error
	}{
		{"staff", "gmail.com", ErrWebmailDomain},
		{"staff", "@Outlook.com", ErrWebmailDomain},
		{"staff", "localhost", ErrInvalidDomain},
		{"staff", "a..b", ErrInvalidDomain},
		{"staff", "x y.org", ErrInvalidDomain},
		{"consultants", "rch.org.au", ErrGroupKind},
		{"missing", "rch.org.au", ErrNoSuchGroup},
	}
	for _, c := range cases {
		if err := s.AddGroupDomain(ctx, c.group, c.domain); !errors.Is(err, c.want) {
			t.Errorf("AddGroupDomain(%q, %q) = %v, want %v", c.group, c.domain, err, c.want)
		}
	}
	got, err := s.ListGroupDomains(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string][]string{"staff": {"mcri.edu.au", "rch.org.au"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("domains = %v, want %v", got, want)
	}
	// A domain group has no members.
	if err := s.AddGroupMember(ctx, "staff", "a@rch.org.au"); !errors.Is(err, ErrGroupKind) {
		t.Errorf("AddGroupMember on a domain group = %v, want ErrGroupKind", err)
	}
	if _, err := s.AddGroupMembers(ctx, "staff", []string{"a@rch.org.au"}); !errors.Is(err, ErrGroupKind) {
		t.Errorf("AddGroupMembers on a domain group = %v, want ErrGroupKind", err)
	}
	if err := s.RemoveGroupDomain(ctx, "staff", "@MCRI.edu.au"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListGroupDomains(ctx); !reflect.DeepEqual(got["staff"], []string{"rch.org.au"}) {
		t.Errorf("after remove: %v", got)
	}
	// Deleting the group removes its rules.
	if err := s.DeleteGroup(ctx, "staff"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListGroupDomains(ctx); len(got) != 0 {
		t.Errorf("rules outlived their group: %v", got)
	}
}

func TestRoleAssignments(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	mustGroups(t, s, "consultants")
	if err := s.CreateGroupOfKind(ctx, "staff", "", GroupKindDomain); err != nil {
		t.Fatal(err)
	}
	until := time.Unix(1_900_000_000, 0)
	ok := []RoleAssignment{
		{App: "caffeine", Role: "user", Kind: AssignDomainGroup, Ref: "staff"},
		{App: "caffeine", Role: "user", Kind: AssignNetwork, Ref: "rch"},
		{App: "roster", Role: "user", Kind: AssignList, Ref: "consultants"},
		{App: "roster", Role: "admin", Kind: AssignPerson, Ref: "A.Nguyen@RCH.org.au", How: AssignedByAdmin, CreatedBy: "boss@x"},
		{App: "enquiries", Role: "user", Kind: AssignGuests},
		{App: "enquiries", Role: "admin", Kind: AssignPerson, Ref: "p@nsw.gov.au", How: AssignedByInvite, Until: until},
	}
	for _, a := range ok {
		if err := s.AddRoleAssignment(ctx, a); err != nil {
			t.Fatalf("AddRoleAssignment(%+v): %v", a, err)
		}
	}
	bad := []struct {
		a    RoleAssignment
		want error
	}{
		{RoleAssignment{App: "x", Role: "user", Kind: AssignList, Ref: "staff"}, ErrGroupKind},
		{RoleAssignment{App: "x", Role: "user", Kind: AssignDomainGroup, Ref: "consultants"}, ErrGroupKind},
		{RoleAssignment{App: "x", Role: "user", Kind: AssignList, Ref: "missing"}, ErrNoSuchGroup},
		{RoleAssignment{App: "x", Role: "user", Kind: AssignPerson, Ref: "not-an-address", How: AssignedByAdmin}, ErrInvalidAssignment},
		{RoleAssignment{App: "x", Role: "user", Kind: AssignPerson, Ref: "a@x.org"}, ErrInvalidAssignment},
		{RoleAssignment{App: "x", Role: "user", Kind: AssignGuests, Ref: "someone"}, ErrInvalidAssignment},
		{RoleAssignment{App: "x", Role: "user", Kind: AssignNetwork}, ErrInvalidAssignment},
		{RoleAssignment{App: "x", Role: "user", Kind: AssignList, Ref: "consultants", Until: until}, ErrInvalidAssignment},
		{RoleAssignment{App: "", Role: "user", Kind: AssignGuests}, ErrInvalidAssignment},
		{RoleAssignment{App: "x", Role: "user", Kind: "everyone"}, ErrInvalidAssignment},
	}
	for _, b := range bad {
		if err := s.AddRoleAssignment(ctx, b.a); !errors.Is(err, b.want) {
			t.Errorf("AddRoleAssignment(%+v) = %v, want %v", b.a, err, b.want)
		}
	}
	all, err := s.ListRoleAssignments(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != len(ok) {
		t.Fatalf("got %d assignments, want %d", len(all), len(ok))
	}
	enq, err := s.ListRoleAssignments(ctx, "enquiries")
	if err != nil {
		t.Fatal(err)
	}
	if len(enq) != 2 || enq[0].Role != "admin" || !enq[0].Until.Equal(until) || enq[0].How != AssignedByInvite {
		t.Errorf("enquiries = %+v", enq)
	}
	roster, _ := s.ListRoleAssignments(ctx, "roster")
	if roster[0].Ref != "a.nguyen@rch.org.au" || roster[0].CreatedBy != "boss@x" {
		t.Errorf("person ref not lowered or created_by lost: %+v", roster[0])
	}
	// Adding again replaces until and how.
	if err := s.AddRoleAssignment(ctx, RoleAssignment{App: "enquiries", Role: "admin", Kind: AssignPerson, Ref: "p@nsw.gov.au", How: AssignedByAdmin}); err != nil {
		t.Fatal(err)
	}
	enq, _ = s.ListRoleAssignments(ctx, "enquiries")
	if !enq[0].Until.IsZero() || enq[0].How != AssignedByAdmin {
		t.Errorf("replace did not take: %+v", enq[0])
	}
	if err := s.RemoveRoleAssignment(ctx, "roster", "admin", AssignPerson, "A.NGUYEN@rch.org.au"); err != nil {
		t.Fatal(err)
	}
	if roster, _ := s.ListRoleAssignments(ctx, "roster"); len(roster) != 1 {
		t.Errorf("after remove: %+v", roster)
	}
}

func TestBreakGlassRole(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id, err := s.CreateBreakGlassCode(ctx, BreakGlassCode{Label: "Lab 1", TargetGroup: "bg_lab", TokenEnc: "e", TokenHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := s.GetBreakGlassCode(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if c.App != "" || c.Role != "" {
		t.Errorf("a group card has app/role %q/%q", c.App, c.Role)
	}
	if err := s.SetBreakGlassRole(ctx, id, "neverdrugs", "admin"); !errors.Is(err, ErrCardRole) {
		t.Errorf("admin role on a card = %v, want ErrCardRole", err)
	}
	if err := s.SetBreakGlassRole(ctx, id, "neverdrugs", RoleUser); err != nil {
		t.Fatal(err)
	}
	c, _, _ = s.LookupBreakGlassByTokenHash(ctx, "h")
	if c.App != "neverdrugs" || c.Role != RoleUser || c.TargetGroup != "bg_lab" {
		t.Errorf("card = %+v", c)
	}
	id2, err := s.CreateBreakGlassCode(ctx, BreakGlassCode{Label: "Lab 2", App: "handbook", Role: RoleUser, TokenEnc: "e2", TokenHash: "h2"})
	if err != nil {
		t.Fatal(err)
	}
	if c, _, _ := s.GetBreakGlassCode(ctx, id2); c.App != "handbook" || c.Role != RoleUser {
		t.Errorf("created card = %+v", c)
	}
}

// A database made by an earlier build gains the new columns and tables, and
// its groups become lists.
func TestRoleSchemaMigratesOldDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	s, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mustGroups(t, s, "old")
	// Strip the new pieces to imitate the earlier schema.
	for _, q := range []string{
		`DROP TABLE role_assignments`, `DROP TABLE group_domains`,
		`ALTER TABLE groups DROP COLUMN kind`,
		`ALTER TABLE break_glass_codes DROP COLUMN app`, `ALTER TABLE break_glass_codes DROP COLUMN role`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	s.Close()
	s, err = OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	groups, err := s.ListGroups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].Kind != GroupKindList {
		t.Errorf("groups = %+v", groups)
	}
	if _, err := s.ListRoleAssignments(ctx, ""); err != nil {
		t.Errorf("role_assignments missing after migrate: %v", err)
	}
}

// A list or domain group stored under a reserved name (legacy data, manual
// SQL) cannot be given a role: a session's tier token would match it, not
// its members.
func TestAssignmentRefusesReservedGroupNames(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for _, name := range []string{"user", "admin", "guest"} {
		if err := s.CreateGroupOfKind(ctx, name, "", GroupKindList); err != nil {
			t.Fatalf("create %q: %v", name, err)
		}
		for _, kind := range []string{AssignList, AssignDomainGroup} {
			err := s.AddRoleAssignment(ctx, RoleAssignment{App: "enquiries", Role: "admin", Kind: kind, Ref: name})
			if !errors.Is(err, ErrInvalidAssignment) {
				t.Errorf("assign %s %q: err = %v, want ErrInvalidAssignment", kind, name, err)
			}
		}
	}
}

// A network or guests identify nobody, so, like a card, they may hold only
// an app's user role.
func TestNetworkAndGuestsHoldOnlyTheUserRole(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for _, a := range []RoleAssignment{
		{App: "enquiries", Role: "admin", Kind: AssignNetwork, Ref: "rch"},
		{App: "enquiries", Role: "admin", Kind: AssignGuests},
	} {
		if err := s.AddRoleAssignment(ctx, a); !errors.Is(err, ErrInvalidAssignment) {
			t.Errorf("assign %s to admin: err = %v, want ErrInvalidAssignment", a.Kind, err)
		}
		if err := s.ApplyRoleChanges(ctx, []RoleAssignment{a}, nil, nil); err == nil {
			t.Errorf("ApplyRoleChanges gave %s the admin role", a.Kind)
		}
		a.Role = RoleUser
		if err := s.AddRoleAssignment(ctx, a); err != nil {
			t.Errorf("assign %s to user: %v", a.Kind, err)
		}
	}
}

// Moving a group card onto an app keeps its token, label and note, clears
// its group and sets its page; a card already moved, made for an app or
// withdrawn is refused.
func TestMoveBreakGlassCard(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id, err := s.CreateBreakGlassCode(ctx, BreakGlassCode{Label: "Theatre 3", Note: "By the door", TargetGroup: "bg_nd", TokenEnc: "e", TokenHash: "h", Redirect: "https://old.example.com/"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MoveBreakGlassCard(ctx, id, "", "https://nd.example.com/"); !errors.Is(err, ErrCardRole) {
		t.Errorf("no app = %v", err)
	}
	if err := s.MoveBreakGlassCard(ctx, id, "neverdrugs", "https://nd.example.com/search"); err != nil {
		t.Fatal(err)
	}
	c, ok, _ := s.LookupBreakGlassByTokenHash(ctx, "h")
	if !ok || c.ID != id || c.App != "neverdrugs" || c.Role != RoleUser || c.TargetGroup != "" || c.Redirect != "https://nd.example.com/search" ||
		c.TokenEnc != "e" || c.Label != "Theatre 3" || c.Note != "By the door" || c.Status != BreakGlassActive {
		t.Errorf("moved card = %+v", c)
	}
	if err := s.MoveBreakGlassCard(ctx, id, "caffeine", "https://c.example.com/"); !errors.Is(err, ErrCardNotGroup) {
		t.Errorf("second move = %v, want ErrCardNotGroup", err)
	}
	id2, _ := s.CreateBreakGlassCode(ctx, BreakGlassCode{Label: "Theatre 4", TargetGroup: "bg_nd", TokenEnc: "e2", TokenHash: "h2"})
	if err := s.RevokeBreakGlassCode(ctx, id2); err != nil {
		t.Fatal(err)
	}
	if err := s.MoveBreakGlassCard(ctx, id2, "neverdrugs", "https://nd.example.com/"); !errors.Is(err, ErrCardNotGroup) {
		t.Errorf("withdrawn move = %v, want ErrCardNotGroup", err)
	}
}

// The webmail list refuses the big providers' regional variants and the
// Australian ISPs' mail, and not an institution's own domain.
func TestWebmailDomainsIncludeRegionalVariants(t *testing.T) {
	for _, d := range []string{
		"y7mail.com", "hotmail.co.uk", "yahoo.co.uk", "duck.com", "tutanota.com", "gmx.de",
		"internode.on.net", "outlook.co.nz", "Gmail.com", "live.com.au", "rocketmail.com",
		"mac.com", "web.de", "proton.me", "zohomail.com", "aol.com", "yandex.ru", "mail.ru",
		"fastmail.com", "bigpond.com", "optusnet.com.au", "iinet.net.au", "tpg.com.au", "dodo.com.au",
	} {
		if !IsWebmailDomain(d) {
			t.Errorf("%s is not refused", d)
		}
	}
	for _, d := range []string{"rch.org.au", "mcri.edu.au", "monashhealth.org", "telstra.com"} {
		if IsWebmailDomain(d) {
			t.Errorf("%s is refused", d)
		}
	}
}
