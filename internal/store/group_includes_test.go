package store

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func mustGroups(t *testing.T, s *SQLite, names ...string) {
	t.Helper()
	for _, n := range names {
		if err := s.CreateGroup(context.Background(), n, ""); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGroupsForEmailFollowsIncludes(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	mustGroups(t, s, "rch-consultants", "planka-users", "staff", "other")
	if err := s.AddGroupMember(ctx, "rch-consultants", "a@x.org"); err != nil {
		t.Fatal(err)
	}
	// planka-users includes rch-consultants; staff includes planka-users.
	for _, inc := range [][2]string{{"planka-users", "rch-consultants"}, {"staff", "planka-users"}} {
		if err := s.AddGroupInclude(ctx, inc[0], inc[1]); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.GroupsForEmail(ctx, "a@x.org")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"planka-users", "rch-consultants", "staff"}; !reflect.DeepEqual(got, want) {
		t.Errorf("groups = %v, want %v", got, want)
	}
}

func TestAddGroupIncludeRefusesCycles(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	mustGroups(t, s, "a", "b", "c")
	if err := s.AddGroupInclude(ctx, "a", "a"); !errors.Is(err, ErrIncludeCycle) {
		t.Errorf("self include = %v, want ErrIncludeCycle", err)
	}
	if err := s.AddGroupInclude(ctx, "a", "b"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddGroupInclude(ctx, "b", "c"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddGroupInclude(ctx, "c", "a"); !errors.Is(err, ErrIncludeCycle) {
		t.Errorf("c includes a (a->b->c) = %v, want ErrIncludeCycle", err)
	}
	if err := s.AddGroupInclude(ctx, "a", "nope"); err == nil {
		t.Error("include of a group that does not exist accepted")
	}
}

func TestGroupIncludesCascadeOnDelete(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	mustGroups(t, s, "parent", "child")
	if err := s.AddGroupMember(ctx, "child", "a@x.org"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddGroupInclude(ctx, "parent", "child"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup(ctx, "child"); err != nil {
		t.Fatal(err)
	}
	inc, _ := s.ListGroupIncludes(ctx)
	if len(inc) != 0 {
		t.Errorf("includes after delete = %v", inc)
	}
	if got, _ := s.GroupsForEmail(ctx, "a@x.org"); len(got) != 0 {
		t.Errorf("groups after delete = %v", got)
	}
}

func TestAddGroupMembersReportsNewOnly(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	mustGroups(t, s, "team")
	if err := s.AddGroupMember(ctx, "team", "old@x.org"); err != nil {
		t.Fatal(err)
	}
	added, err := s.AddGroupMembers(ctx, "team", []string{"old@x.org", "new1@x.org", "new2@x.org"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"new1@x.org", "new2@x.org"}; !reflect.DeepEqual(added, want) {
		t.Errorf("added = %v, want %v", added, want)
	}
	if _, err := s.AddGroupMembers(ctx, "missing", []string{"a@x.org"}); err == nil {
		t.Error("bulk add to a group that does not exist accepted")
	}
}
