package store

import (
	"context"
	"testing"
)

func TestGroupsCRUDAndMembership(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.CreateGroup(ctx, "whitelisted", "Whitelisted users"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateGroup(ctx, "whitelisted", "Whitelisted users"); err != nil {
		t.Fatalf("re-create should be idempotent: %v", err)
	}
	groups, err := s.ListGroups(ctx)
	if err != nil || len(groups) != 1 || groups[0].Name != "whitelisted" {
		t.Fatalf("ListGroups = %+v, %v", groups, err)
	}

	if err := s.AddGroupMember(ctx, "whitelisted", "a@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddGroupMember(ctx, "whitelisted", "a@example.com"); err != nil {
		t.Fatalf("re-add should be idempotent: %v", err)
	}
	members, err := s.ListGroupMembers(ctx, "whitelisted")
	if err != nil || len(members) != 1 || members[0] != "a@example.com" {
		t.Fatalf("ListGroupMembers = %v, %v", members, err)
	}

	forEmail, err := s.GroupsForEmail(ctx, "a@example.com")
	if err != nil || len(forEmail) != 1 || forEmail[0] != "whitelisted" {
		t.Fatalf("GroupsForEmail = %v, %v", forEmail, err)
	}

	if err := s.RemoveGroupMember(ctx, "whitelisted", "a@example.com"); err != nil {
		t.Fatal(err)
	}
	if forEmail, _ := s.GroupsForEmail(ctx, "a@example.com"); len(forEmail) != 0 {
		t.Fatalf("expected no groups after removal, got %v", forEmail)
	}

	// Deleting the group cascades its (now empty) membership rows.
	if err := s.AddGroupMember(ctx, "whitelisted", "b@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup(ctx, "whitelisted"); err != nil {
		t.Fatal(err)
	}
	if forEmail, _ := s.GroupsForEmail(ctx, "b@example.com"); len(forEmail) != 0 {
		t.Fatalf("expected cascade to drop memberships, got %v", forEmail)
	}
}

func TestBreakGlassLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	id, err := s.CreateBreakGlassCode(ctx, BreakGlassCode{
		Label:       "Angiography Lab 1",
		Note:        "By the workstation",
		TargetGroup: "code_stroke_break_glass",
		TokenEnc:    "v1:ciphertext",
		TokenHash:   "hash-old",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Lookup by hash finds the active code.
	c, ok, err := s.LookupBreakGlassByTokenHash(ctx, "hash-old")
	if err != nil || !ok || c.ID != id || c.Status != BreakGlassActive {
		t.Fatalf("lookup = %+v, ok=%v, err=%v", c, ok, err)
	}
	if c.TargetGroup != "code_stroke_break_glass" {
		t.Errorf("target group = %q", c.TargetGroup)
	}

	// Revoke: still found, but now marked revoked (for audit of stale-card scans).
	if err := s.RevokeBreakGlassCode(ctx, id); err != nil {
		t.Fatal(err)
	}
	if c, ok, _ := s.LookupBreakGlassByTokenHash(ctx, "hash-old"); !ok || c.Status != BreakGlassRevoked {
		t.Errorf("after revoke: ok=%v status=%q, want revoked", ok, c.Status)
	}

	// Re-mint: old hash stays dead, new hash works, status active again.
	if err := s.RemintBreakGlassCode(ctx, id, "v1:newcipher", "hash-new"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.LookupBreakGlassByTokenHash(ctx, "hash-old"); ok {
		t.Error("old hash still resolves after re-mint")
	}
	c, ok, err = s.LookupBreakGlassByTokenHash(ctx, "hash-new")
	if err != nil || !ok || c.TokenEnc != "v1:newcipher" || c.Status != BreakGlassActive {
		t.Fatalf("re-mint lookup = %+v, ok=%v, err=%v", c, ok, err)
	}

	// Duplicate label is rejected by the UNIQUE constraint.
	if _, err := s.CreateBreakGlassCode(ctx, BreakGlassCode{
		Label: "Angiography Lab 1", TargetGroup: "g", TokenEnc: "x", TokenHash: "h2",
	}); err == nil {
		t.Error("expected duplicate-label error")
	}

	// Events: record then list.
	for _, outcome := range []string{OutcomeGranted, OutcomeUnknown} {
		if err := s.RecordBreakGlassEvent(ctx, BreakGlassEvent{
			CodeID: id, Label: "Angiography Lab 1", ClientIP: "10.0.0.1", Outcome: outcome,
		}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := s.ListBreakGlassEvents(ctx, id, 10, 0)
	if err != nil || len(events) != 2 {
		t.Fatalf("ListBreakGlassEvents = %d events, %v", len(events), err)
	}
	if all, _ := s.ListBreakGlassEvents(ctx, 0, 10, 0); len(all) != 2 {
		t.Fatalf("ListBreakGlassEvents(all) = %d", len(all))
	}
}

func TestBrandingRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, ok, err := s.GetBranding(ctx); ok || err != nil {
		t.Fatalf("expected no branding initially, ok=%v err=%v", ok, err)
	}

	if err := s.SaveBrandingText(ctx, "Title", "Body", "Step 1\nStep 2"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetBrandingImage(ctx, BrandingLogo, []byte{1, 2, 3}, "image/png"); err != nil {
		t.Fatal(err)
	}
	b, ok, err := s.GetBranding(ctx)
	if err != nil || !ok || b.Title != "Title" || b.Instructions != "Step 1\nStep 2" {
		t.Fatalf("branding = %+v, ok=%v, err=%v", b, ok, err)
	}
	if string(b.Logo) != "\x01\x02\x03" || b.LogoType != "image/png" {
		t.Errorf("logo not stored: %v %q", b.Logo, b.LogoType)
	}

	// Saving text again must not wipe the stored image.
	if err := s.SaveBrandingText(ctx, "T2", "B2", "I2"); err != nil {
		t.Fatal(err)
	}
	if b, _, _ := s.GetBranding(ctx); len(b.Logo) != 3 || b.Title != "T2" {
		t.Errorf("text save clobbered image or title: %+v", b)
	}

	// Clearing the image leaves text intact.
	if err := s.ClearBrandingImage(ctx, BrandingLogo); err != nil {
		t.Fatal(err)
	}
	if b, _, _ := s.GetBranding(ctx); len(b.Logo) != 0 || b.Title != "T2" {
		t.Errorf("clear image affected text or left logo: %+v", b)
	}
}
