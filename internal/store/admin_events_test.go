package store

import (
	"context"
	"testing"
	"time"
)

func TestAdminEventsRoundTripAndOrder(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	t0 := time.Unix(1_700_000_000, 0)

	events := []AdminEvent{
		{Actor: "admin@x", Action: AdminActionBreakCreate, Target: "ward-a", Detail: "group=ward", ClientIP: "1.2.3.4", UserAgent: "ua", CreatedAt: t0},
		{Actor: "admin@x", Action: AdminActionGroupAddMember, Target: "ward", Detail: "nurse@x", ClientIP: "1.2.3.4", CreatedAt: t0.Add(time.Minute)},
		{Actor: "other@x", Action: AdminActionTOTPRemove, Target: "admin@x", CreatedAt: t0.Add(2 * time.Minute)},
	}
	for _, e := range events {
		if err := s.RecordAdminEvent(ctx, e); err != nil {
			t.Fatalf("RecordAdminEvent: %v", err)
		}
	}

	got, err := s.ListAdminEvents(ctx, 100, 0)
	if err != nil {
		t.Fatalf("ListAdminEvents: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d events, want 3", len(got))
	}
	// Newest first.
	if got[0].Action != AdminActionTOTPRemove || got[2].Action != AdminActionBreakCreate {
		t.Errorf("wrong order: %s ... %s", got[0].Action, got[2].Action)
	}
	// Attribution + fields preserved.
	if got[2].Actor != "admin@x" || got[2].Target != "ward-a" || got[2].Detail != "group=ward" || got[2].ClientIP != "1.2.3.4" {
		t.Errorf("fields not preserved: %+v", got[2])
	}
	if !got[2].CreatedAt.Equal(t0) {
		t.Errorf("timestamp = %v, want %v", got[2].CreatedAt, t0)
	}
}

func TestPruneAuditRemovesAdminEvents(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	t0 := time.Unix(1_700_000_000, 0)

	if err := s.RecordAdminEvent(ctx, AdminEvent{Actor: "a@x", Action: AdminActionGroupCreate, Target: "old", CreatedAt: t0}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordAdminEvent(ctx, AdminEvent{Actor: "a@x", Action: AdminActionGroupCreate, Target: "new", CreatedAt: t0.Add(48 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.PruneAuditBefore(ctx, t0.Add(24*time.Hour)); err != nil {
		t.Fatalf("PruneAuditBefore: %v", err)
	}
	got, err := s.ListAdminEvents(ctx, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Target != "new" {
		t.Errorf("prune left %d events (want 1, 'new'): %+v", len(got), got)
	}
}
