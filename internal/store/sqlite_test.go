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
	res, err := s.ConsumeCode(ctx, "a@example.com", "hash1", 5, now)
	if err != nil {
		t.Fatal(err)
	}
	if res != ConsumeOK {
		t.Fatalf("res = %v, want ConsumeOK", res)
	}
	// Single use: a second consume finds nothing.
	res, _ = s.ConsumeCode(ctx, "a@example.com", "hash1", 5, now)
	if res != ConsumeNoCode {
		t.Errorf("replay res = %v, want ConsumeNoCode", res)
	}
}

func TestConsumeCodeExpired(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	_ = s.SaveCode(ctx, "a@example.com", "hash1", now.Add(time.Minute))
	res, _ := s.ConsumeCode(ctx, "a@example.com", "hash1", 5, now.Add(2*time.Minute))
	if res != ConsumeExpired {
		t.Errorf("res = %v, want ConsumeExpired", res)
	}
	// Expired code is cleared.
	res, _ = s.ConsumeCode(ctx, "a@example.com", "hash1", 5, now)
	if res != ConsumeNoCode {
		t.Errorf("res = %v, want ConsumeNoCode after expiry cleanup", res)
	}
}

func TestConsumeCodeAttemptCap(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	_ = s.SaveCode(ctx, "a@example.com", "right", now.Add(10*time.Minute))

	// maxAttempts=3: two mismatches, third reaches the cap and invalidates.
	if res, _ := s.ConsumeCode(ctx, "a@example.com", "wrong", 3, now); res != ConsumeMismatch {
		t.Fatalf("attempt1 = %v, want ConsumeMismatch", res)
	}
	if res, _ := s.ConsumeCode(ctx, "a@example.com", "wrong", 3, now); res != ConsumeMismatch {
		t.Fatalf("attempt2 = %v, want ConsumeMismatch", res)
	}
	if res, _ := s.ConsumeCode(ctx, "a@example.com", "wrong", 3, now); res != ConsumeTooManyAttempts {
		t.Fatalf("attempt3 = %v, want ConsumeTooManyAttempts", res)
	}
	// Even the correct code now fails — the code was invalidated.
	if res, _ := s.ConsumeCode(ctx, "a@example.com", "right", 3, now); res != ConsumeNoCode {
		t.Errorf("after cap = %v, want ConsumeNoCode", res)
	}
}

func TestConsumeCodeNoCode(t *testing.T) {
	s := newTestStore(t)
	res, err := s.ConsumeCode(context.Background(), "nobody@example.com", "x", 5, time.Now())
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
	_, _ = s.ConsumeCode(ctx, "a@example.com", "wrong", 5, now) // attempts=1
	// Re-issue resets attempts and replaces the hash.
	_ = s.SaveCode(ctx, "a@example.com", "new", now.Add(10*time.Minute))
	if res, _ := s.ConsumeCode(ctx, "a@example.com", "new", 5, now); res != ConsumeOK {
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
