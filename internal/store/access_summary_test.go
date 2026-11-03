package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The access log folds hourly rows into one per person, site and kind, and
// its person filter matches part of an address literally.
func TestSummariseAppAccess(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 11, 2, 0, 30, 0, 0, time.UTC) // 11:30 in Melbourne (UTC+11)
	add := func(email, host, kind string, at time.Time) {
		t.Helper()
		if err := s.RecordAppAccess(ctx, AppAccess{Email: email, Host: host, Kind: kind, Bucket: at.Unix() / 3600, CreatedAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	for h := 0; h < 8; h++ { // a working day on Planka
		add("amy@x.org", "planka.x.org", "", base.Add(time.Duration(h)*time.Hour))
	}
	add("amy@x.org", "planka.x.org", "", base.Add(24*time.Hour)) // the next day
	add("amy@x.org", "planka.x.org", "guest", base)              // a different kind stays apart
	add("bob@x.org", "docs.x.org", "", base)
	add("a_b@x.org", "docs.x.org", "", base)
	add("old@x.org", "docs.x.org", "", base.Add(-30*24*time.Hour)) // before the period

	melbourne := 11 * 3600
	all, err := s.SummariseAppAccess(ctx, AccessFilter{Since: base.Add(-time.Hour)}, melbourne)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 4 {
		t.Fatalf("want 4 rows (amy twice, bob, a_b), got %+v", all)
	}
	if a := all[0]; a.Email != "amy@x.org" || a.Kind != "" || a.Hours != 9 || a.Days != 2 || !a.Last.Equal(base.Add(24*time.Hour)) || !a.First.Equal(base) {
		t.Errorf("amy's planka row: %+v", a)
	}
	// Day boundaries follow the offset: 23:30 UTC and 00:30 UTC are one
	// Melbourne day but two UTC days.
	late := time.Date(2026, 11, 5, 23, 30, 0, 0, time.UTC)
	add("cal@x.org", "docs.x.org", "", late)
	add("cal@x.org", "docs.x.org", "", late.Add(time.Hour))
	for _, tc := range []struct {
		offset, days int
	}{{0, 2}, {melbourne, 1}} {
		got, _ := s.SummariseAppAccess(ctx, AccessFilter{Email: "cal@", Since: late.Add(-time.Hour)}, tc.offset)
		if len(got) != 1 || got[0].Days != tc.days {
			t.Errorf("offset %d: %+v, want %d days", tc.offset, got, tc.days)
		}
	}
	// "_" is a literal underscore, not "any character".
	got, _ := s.SummariseAppAccess(ctx, AccessFilter{Email: "A_B", Since: base.Add(-time.Hour)}, 0)
	if len(got) != 1 || got[0].Email != "a_b@x.org" {
		t.Errorf("person filter a_b: %+v", got)
	}
	got, _ = s.SummariseAppAccess(ctx, AccessFilter{Host: "docs.x.org", Since: base.Add(-time.Hour)}, 0)
	if len(got) != 3 {
		t.Errorf("site filter: %+v", got)
	}
	people, err := s.SummarisePeople(ctx, AccessFilter{Since: base.Add(-time.Hour)}, melbourne)
	if err != nil {
		t.Fatal(err)
	}
	var amy *AccessSummary
	for i := range people {
		if people[i].Email == "amy@x.org" {
			amy = &people[i]
		}
	}
	// amy's guest visit shares an hour with her first ordinary one.
	if amy == nil || amy.Hours != 9 || amy.Days != 2 || len(amy.Sites) != 1 || amy.Sites[0] != "planka.x.org" || len(amy.Kinds) != 1 || amy.Kinds[0] != "guest" {
		t.Errorf("amy as a person: %+v", amy)
	}
	add("bob@x.org", "planka.x.org", "", base)
	people, _ = s.SummarisePeople(ctx, AccessFilter{Email: "bob", Since: base.Add(-time.Hour)}, 0)
	if len(people) != 1 || strings.Join(people[0].Sites, " ") != "docs.x.org planka.x.org" {
		t.Errorf("bob's sites: %+v", people)
	}
	// A whole address matches only itself, not every address containing it.
	add("joamy@x.org", "docs.x.org", "", base)
	got, _ = s.SummariseAppAccess(ctx, AccessFilter{Email: "amy@x.org", EmailExact: true, Since: base.Add(-time.Hour)}, 0)
	for _, g := range got {
		if g.Email != "amy@x.org" {
			t.Errorf("exact filter for amy@x.org matched %s", g.Email)
		}
	}
	hosts, _ := s.AppAccessHosts(ctx, base.Add(-60*24*time.Hour))
	if len(hosts) != 2 || hosts[0] != "docs.x.org" {
		t.Errorf("hosts: %v", hosts)
	}
}

// "Refused only" is applied when the events are read, so refusals older than
// any number of successful sign-ins are still found.
func TestRefusedOnlyReadsPastSuccesses(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	at := time.Unix(1_800_000_000, 0)
	if err := s.RecordAuthEvent(ctx, AuthEvent{Email: "a@x.org", EventType: "verify", Outcome: "wrong_code", CreatedAt: at}); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 50; i++ {
		s.RecordAuthEvent(ctx, AuthEvent{Email: "a@x.org", EventType: "login", Outcome: "ok", CreatedAt: at.Add(time.Duration(i) * time.Minute)})
	}
	got, err := s.ListAuthEventsFiltered(ctx, AccessFilter{Since: at.Add(-time.Hour), RefusedOnly: true}, 10)
	if err != nil || len(got) != 1 || got[0].Outcome != "wrong_code" {
		t.Fatalf("refused only = %+v, %v", got, err)
	}
}

// A group's resolved members are exactly the addresses whose sign-in groups
// include it, through includes at any depth, and a loop of includes ends.
func TestGroupMembersResolved(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for _, g := range []string{"top", "mid", "low", "aside"} {
		if err := s.CreateGroup(ctx, g, ""); err != nil {
			t.Fatal(err)
		}
	}
	s.AddGroupMember(ctx, "top", "t@x.org")
	s.AddGroupMember(ctx, "mid", "m@x.org")
	s.AddGroupMember(ctx, "low", "l@x.org")
	s.AddGroupMember(ctx, "low", "t@x.org")
	s.AddGroupMember(ctx, "aside", "a@x.org")
	s.AddGroupInclude(ctx, "top", "mid")
	s.AddGroupInclude(ctx, "mid", "low")
	// A loop slipped past the include check must still end.
	s.db.ExecContext(ctx, `INSERT INTO group_includes (group_name, included, created_at) VALUES ('low', 'top', 0)`)

	got, exists, err := s.GroupMembersResolved(ctx, "top")
	if err != nil || !exists || strings.Join(got, " ") != "l@x.org m@x.org t@x.org" {
		t.Fatalf("top = %v %v %v", got, exists, err)
	}
	for _, e := range []string{"t@x.org", "m@x.org", "l@x.org", "a@x.org"} {
		groups, _ := s.GroupsForEmail(ctx, e)
		in := false
		for _, g := range groups {
			in = in || g == "top"
		}
		listed := strings.Contains(" "+strings.Join(got, " ")+" ", " "+e+" ")
		if in != listed {
			t.Errorf("%s: sign-in groups %v, listed in top = %v", e, groups, listed)
		}
	}
	if got, exists, err := s.GroupMembersResolved(ctx, "nope"); exists || err != nil || got != nil {
		t.Errorf("missing group = %v %v %v", got, exists, err)
	}
	if got, exists, _ := s.GroupMembersResolved(ctx, "aside"); !exists || len(got) != 1 {
		t.Errorf("aside = %v", got)
	}
}
