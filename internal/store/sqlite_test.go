package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *SQLite {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.db")
	s, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestConsumeCodeHappyPath(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)

	if err := s.SaveCode(ctx, "a@example.com", "hash1", now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	res, err := s.ConsumeCode(ctx, "a@example.com", "1.1.1.1", "hash1", 5, now)
	if err != nil {
		t.Fatal(err)
	}
	if res != ConsumeOK {
		t.Fatalf("res = %v, want ConsumeOK", res)
	}
	// Single use: a second consume finds nothing.
	res, _ = s.ConsumeCode(ctx, "a@example.com", "1.1.1.1", "hash1", 5, now)
	if res != ConsumeNoCode {
		t.Errorf("replay res = %v, want ConsumeNoCode", res)
	}
}

func TestHasRecentCode(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	const ttl = 10 * time.Minute
	const cooldown = time.Minute
	// Callers pass minExpiry = now + TTL - cooldown: a code counts as "recent" iff
	// its expiry is later than this, i.e. it was issued within the last `cooldown`.
	minExpiry := now.Add(ttl - cooldown)

	// No row at all → not recent.
	if got, err := s.HasRecentCode(ctx, "a@example.com", minExpiry); err != nil || got {
		t.Fatalf("no row: got %v err %v, want false", got, err)
	}

	// Freshly issued (expires now+TTL) → recent.
	_ = s.SaveCode(ctx, "a@example.com", "hash1", now.Add(ttl))
	if got, err := s.HasRecentCode(ctx, "a@example.com", minExpiry); err != nil || !got {
		t.Fatalf("fresh row: got %v err %v, want true", got, err)
	}

	// Issued just over a cooldown ago (expires now+TTL-cooldown-1s, i.e. not later
	// than minExpiry) → stale, so a resend should be allowed.
	_ = s.SaveCode(ctx, "a@example.com", "hash1", now.Add(ttl-cooldown-time.Second))
	if got, err := s.HasRecentCode(ctx, "a@example.com", minExpiry); err != nil || got {
		t.Fatalf("stale row: got %v err %v, want false", got, err)
	}
}

func TestConsumeCodeExpired(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	_ = s.SaveCode(ctx, "a@example.com", "hash1", now.Add(time.Minute))
	res, _ := s.ConsumeCode(ctx, "a@example.com", "1.1.1.1", "hash1", 5, now.Add(2*time.Minute))
	if res != ConsumeExpired {
		t.Errorf("res = %v, want ConsumeExpired", res)
	}
	// Expired code is cleared.
	res, _ = s.ConsumeCode(ctx, "a@example.com", "1.1.1.1", "hash1", 5, now)
	if res != ConsumeNoCode {
		t.Errorf("res = %v, want ConsumeNoCode after expiry cleanup", res)
	}
}

func TestConsumeCodeAttemptCapPerIP(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	_ = s.SaveCode(ctx, "a@example.com", "right", now.Add(10*time.Minute))

	// maxAttempts=3 for the attacker IP: two mismatches, third hits the cap.
	const attacker = "9.9.9.9"
	if res, _ := s.ConsumeCode(ctx, "a@example.com", attacker, "wrong", 3, now); res != ConsumeMismatch {
		t.Fatalf("attempt1 = %v, want ConsumeMismatch", res)
	}
	if res, _ := s.ConsumeCode(ctx, "a@example.com", attacker, "wrong", 3, now); res != ConsumeMismatch {
		t.Fatalf("attempt2 = %v, want ConsumeMismatch", res)
	}
	if res, _ := s.ConsumeCode(ctx, "a@example.com", attacker, "wrong", 3, now); res != ConsumeTooManyAttempts {
		t.Fatalf("attempt3 = %v, want ConsumeTooManyAttempts", res)
	}
	// The attacker's IP is now blocked — even a correct guess from it is refused.
	if res, _ := s.ConsumeCode(ctx, "a@example.com", attacker, "right", 3, now); res != ConsumeTooManyAttempts {
		t.Errorf("attacker after cap = %v, want ConsumeTooManyAttempts", res)
	}
	// Burn resistance: the legitimate user (a different, non-spoofable IP) still
	// has a working code — the attacker's wrong guesses did NOT delete it.
	if res, _ := s.ConsumeCode(ctx, "a@example.com", "1.1.1.1", "right", 3, now); res != ConsumeOK {
		t.Errorf("victim = %v, want ConsumeOK (code must survive an attacker's burn)", res)
	}
}

func TestConsumeCodeNoCode(t *testing.T) {
	s := newTestStore(t)
	res, err := s.ConsumeCode(context.Background(), "nobody@example.com", "1.1.1.1", "x", 5, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if res != ConsumeNoCode {
		t.Errorf("res = %v, want ConsumeNoCode", res)
	}
}

func TestSaveCodeResetsAttempts(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	_ = s.SaveCode(ctx, "a@example.com", "old", now.Add(10*time.Minute))
	_, _ = s.ConsumeCode(ctx, "a@example.com", "1.1.1.1", "wrong", 5, now) // attempts=1
	// Re-issue resets attempts and replaces the hash.
	_ = s.SaveCode(ctx, "a@example.com", "new", now.Add(10*time.Minute))
	if res, _ := s.ConsumeCode(ctx, "a@example.com", "1.1.1.1", "new", 5, now); res != ConsumeOK {
		t.Errorf("res = %v, want ConsumeOK after re-issue", res)
	}
}

func TestTOTPSecretRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, ok, _ := s.GetTOTPSecret(ctx, "admin@example.com"); ok {
		t.Fatal("expected no secret initially")
	}
	if err := s.SetTOTPSecret(ctx, "admin@example.com", "SECRET123"); err != nil {
		t.Fatal(err)
	}
	secret, ok, err := s.GetTOTPSecret(ctx, "admin@example.com")
	if err != nil || !ok || secret != "SECRET123" {
		t.Errorf("GetTOTPSecret = %q ok=%v err=%v", secret, ok, err)
	}
	// Upsert replaces.
	_ = s.SetTOTPSecret(ctx, "admin@example.com", "SECRET456")
	secret, _, _ = s.GetTOTPSecret(ctx, "admin@example.com")
	if secret != "SECRET456" {
		t.Errorf("secret = %q, want replaced", secret)
	}

	// Delete removes it; deleting again is a no-op.
	if err := s.DeleteTOTPSecret(ctx, "admin@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.GetTOTPSecret(ctx, "admin@example.com"); ok {
		t.Error("secret still present after delete")
	}
	if err := s.DeleteTOTPSecret(ctx, "admin@example.com"); err != nil {
		t.Errorf("delete of absent secret should be a no-op, got %v", err)
	}
}
