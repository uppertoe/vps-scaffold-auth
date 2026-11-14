package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func newInvite(s *SQLite, t *testing.T, email, hash string, now time.Time, until time.Time) int64 {
	t.Helper()
	ids, err := s.CreateInvitations(context.Background(), []Invitation{{
		Email: email, App: "enquiries", Role: "admin", Until: until, TokenHash: hash, CreatedBy: "boss@example.org",
		CreatedAt: now, SentAt: now, ExpiresAt: now.Add(14 * 24 * time.Hour),
	}}, []AdminEvent{{Actor: "boss@example.org", Action: AdminActionInviteCreate, CreatedAt: now}})
	if err != nil {
		t.Fatal(err)
	}
	return ids[0]
}

func TestInvitationLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	until := now.Add(60 * 24 * time.Hour)
	id := newInvite(s, t, "K.Lee@Example.org", "h1", now, until)

	v, ok, err := s.InvitationByTokenHash(ctx, "h1")
	if err != nil || !ok || v.ID != id || v.Email != "k.lee@example.org" || !v.Until.Equal(until) {
		t.Fatalf("lookup = %+v %v %v", v, ok, err)
	}
	if !v.Open(now) || v.Open(now.Add(14*24*time.Hour)) {
		t.Error("an invitation should be open until it expires, and not after")
	}
	if _, ok, _ := s.InvitationByTokenHash(ctx, ""); ok {
		t.Error("an empty hash found an invitation")
	}

	// A resend replaces the hash: the old link finds nothing.
	later := now.Add(time.Hour)
	if err := s.ResendInvitation(ctx, id, "h2", later, later.Add(14*24*time.Hour), AdminEvent{Action: AdminActionInviteResend, CreatedAt: later}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.InvitationByTokenHash(ctx, "h1"); ok {
		t.Error("the old link still finds the invitation after a resend")
	}
	// A failed delivery of the old email does not mark the new one.
	if err := s.MarkInvitationUndelivered(ctx, id, "h1"); err != nil {
		t.Fatal(err)
	}
	if v, _, _ := s.GetInvitation(ctx, id); v.Undelivered {
		t.Error("a failure of the old email marked the resent invitation undelivered")
	}

	// The wrong address cannot accept it.
	if _, err := s.AcceptInvitation(ctx, id, "other@example.org", later, AdminEvent{CreatedAt: later}); !errors.Is(err, ErrInvitationClosed) {
		t.Errorf("wrong address: err = %v", err)
	}
	// Accepting gives the role, by invitation, created by the inviter.
	if _, err := s.AcceptInvitation(ctx, id, "k.lee@example.org", later, AdminEvent{Action: AdminActionInviteAccept, CreatedAt: later}); err != nil {
		t.Fatal(err)
	}
	as, _ := s.ListRoleAssignments(ctx, "enquiries")
	if len(as) != 1 || as[0].Ref != "k.lee@example.org" || as[0].How != AssignedByInvite || !as[0].Until.Equal(until) || as[0].CreatedBy != "boss@example.org" {
		t.Fatalf("assignments = %+v", as)
	}
	// Accepted once only, and it can no longer be resent or withdrawn.
	if _, err := s.AcceptInvitation(ctx, id, "k.lee@example.org", later, AdminEvent{CreatedAt: later}); !errors.Is(err, ErrInvitationClosed) {
		t.Errorf("second accept: err = %v", err)
	}
	if err := s.WithdrawInvitation(ctx, id, later, AdminEvent{CreatedAt: later}); !errors.Is(err, ErrInvitationClosed) {
		t.Errorf("withdraw after accept: err = %v", err)
	}
	if err := s.ResendInvitation(ctx, id, "h3", later, later, AdminEvent{CreatedAt: later}); !errors.Is(err, ErrInvitationClosed) {
		t.Errorf("resend after accept: err = %v", err)
	}
}

func TestInvitationWithdrawnOrExpiredCannotBeAccepted(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	a := newInvite(s, t, "a@example.org", "ha", now, time.Time{})
	b := newInvite(s, t, "b@example.org", "hb", now, time.Time{})
	if err := s.WithdrawInvitation(ctx, a, now, AdminEvent{CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvitation(ctx, a, "a@example.org", now, AdminEvent{CreatedAt: now}); !errors.Is(err, ErrInvitationClosed) {
		t.Errorf("withdrawn: err = %v", err)
	}
	if _, err := s.AcceptInvitation(ctx, b, "b@example.org", now.Add(15*24*time.Hour), AdminEvent{CreatedAt: now}); !errors.Is(err, ErrInvitationClosed) {
		t.Errorf("expired: err = %v", err)
	}
	if as, _ := s.ListRoleAssignments(ctx, ""); len(as) != 0 {
		t.Errorf("assignments = %+v", as)
	}
}

func TestAcceptingKeepsTheLaterEnd(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	if err := s.AddRoleAssignment(ctx, RoleAssignment{App: "enquiries", Role: "admin", Kind: AssignPerson, Ref: "p@example.org", How: AssignedByAdmin}); err != nil {
		t.Fatal(err)
	}
	id := newInvite(s, t, "p@example.org", "hp", now, now.Add(24*time.Hour))
	if _, err := s.AcceptInvitation(ctx, id, "p@example.org", now, AdminEvent{CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	as, _ := s.ListRoleAssignments(ctx, "enquiries")
	if len(as) != 1 || !as[0].Until.IsZero() || as[0].How != AssignedByInvite || !as[0].CreatedAt.Equal(now) {
		t.Fatalf("a permanent role was shortened by an invitation: %+v", as)
	}
}

func TestReminderSentOnce(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	until := time.Unix(1_800_000_000, 0)
	first, err := s.MarkReminderSent(ctx, "enquiries", "admin", "p@example.org", until, until)
	if err != nil || !first {
		t.Fatalf("first = %v %v", first, err)
	}
	if again, _ := s.MarkReminderSent(ctx, "enquiries", "admin", "p@example.org", until, until); again {
		t.Error("the same reminder was recorded twice")
	}
	if extended, _ := s.MarkReminderSent(ctx, "enquiries", "admin", "p@example.org", until.Add(time.Hour), until); !extended {
		t.Error("a new end date did not get its own reminder")
	}
}

// A failed delivery closes the invitation: it cannot be accepted. Sending it
// again keeps it closed until the new email is delivered, which reopens it;
// a delivery of an older email changes nothing.
func TestUndeliveredInvitationIsClosedUntilDelivered(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	id := newInvite(s, t, "k.lee@example.org", "h1", now, time.Time{})
	if err := s.MarkInvitationUndelivered(ctx, id, "h1"); err != nil {
		t.Fatal(err)
	}
	if v, _, _ := s.GetInvitation(ctx, id); !v.Undelivered || v.Open(now) {
		t.Fatalf("an undelivered invitation is open: %+v", v)
	}
	if _, err := s.AcceptInvitation(ctx, id, "k.lee@example.org", now, AdminEvent{CreatedAt: now}); !errors.Is(err, ErrInvitationClosed) {
		t.Errorf("accept undelivered: err = %v", err)
	}
	later := now.Add(time.Hour)
	if err := s.ResendInvitation(ctx, id, "h2", later, later.Add(14*24*time.Hour), AdminEvent{Action: AdminActionInviteResend, CreatedAt: later}); err != nil {
		t.Fatal(err)
	}
	if v, _, _ := s.GetInvitation(ctx, id); v.Open(later) {
		t.Error("sending again reopened the invitation before the email was delivered")
	}
	if err := s.MarkInvitationDelivered(ctx, id, "h1"); err != nil {
		t.Fatal(err)
	}
	if v, _, _ := s.GetInvitation(ctx, id); v.Open(later) {
		t.Error("the delivery of the old email reopened the invitation")
	}
	if err := s.MarkInvitationDelivered(ctx, id, "h2"); err != nil {
		t.Fatal(err)
	}
	v, _, _ := s.GetInvitation(ctx, id)
	if v.Undelivered || !v.Open(later) || !v.ExpiresAt.Equal(later.Add(14*24*time.Hour)) {
		t.Errorf("after delivery: %+v", v)
	}
	if _, err := s.AcceptInvitation(ctx, id, "k.lee@example.org", later, AdminEvent{CreatedAt: later}); err != nil {
		t.Errorf("accept after delivery: %v", err)
	}
}
