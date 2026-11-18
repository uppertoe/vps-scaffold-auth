package store

import (
	"context"
	"testing"
	"time"
)

func TestMemberReaderApprovals(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 17, 1, 0, 0, 0, time.UTC)

	if ok, err := s.MemberReaderApproved(ctx, "digest", "coordinators"); err != nil || ok {
		t.Fatalf("approved before approval = %v, %v", ok, err)
	}
	// A group that does not exist cannot be approved.
	if added, err := s.ApproveMemberReader(ctx, "digest", "coordinators", "admin@example.com", at); err != nil || added {
		t.Fatalf("approve a missing group = %v, %v", added, err)
	}
	for _, g := range []string{"coordinators", "leads", "fellows"} {
		if err := s.CreateGroup(ctx, g, ""); err != nil {
			t.Fatal(err)
		}
	}
	if added, err := s.ApproveMemberReader(ctx, "digest", "coordinators", "admin@example.com", at); err != nil || !added {
		t.Fatalf("approve = %v, %v", added, err)
	}
	// A second approval changes nothing, and keeps the first approver.
	if added, err := s.ApproveMemberReader(ctx, "digest", "coordinators", "boss@example.com", at.Add(time.Hour)); err != nil || added {
		t.Fatalf("second approve = %v, %v", added, err)
	}
	s.ApproveMemberReader(ctx, "digest", "leads", "admin@example.com", at)
	s.ApproveMemberReader(ctx, "planka", "fellows", "admin@example.com", at)
	if ok, _ := s.MemberReaderApproved(ctx, "digest", "coordinators"); !ok {
		t.Fatal("not approved after approval")
	}
	// The pair, not the app or the group alone, is approved.
	if ok, _ := s.MemberReaderApproved(ctx, "planka", "coordinators"); ok {
		t.Fatal("another app inherited the approval")
	}
	list, err := s.ListMemberReaderApprovals(ctx)
	if err != nil || len(list) != 3 || list[0].App != "digest" || list[0].Group != "coordinators" ||
		list[0].ApprovedBy != "admin@example.com" || !list[0].ApprovedAt.Equal(at) {
		t.Fatalf("list = %+v, %v", list, err)
	}

	if removed, err := s.WithdrawMemberReader(ctx, "digest", "leads"); err != nil || !removed {
		t.Fatalf("withdraw = %v, %v", removed, err)
	}
	if removed, _ := s.WithdrawMemberReader(ctx, "digest", "leads"); removed {
		t.Fatal("a second withdrawal removed something")
	}

	// Deleting a group deletes its approvals with it, so a group created
	// later under the same name is not approved.
	if err := s.DeleteGroup(ctx, "fellows"); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.ListMemberReaderApprovals(ctx); len(list) != 1 || list[0].Group != "coordinators" {
		t.Fatalf("after deleting the group = %+v", list)
	}
	s.CreateGroup(ctx, "fellows", "")
	if ok, _ := s.MemberReaderApproved(ctx, "planka", "fellows"); ok {
		t.Fatal("a recreated group inherited the approval")
	}
}
