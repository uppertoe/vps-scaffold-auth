package store

import (
	"context"
	"testing"
	"time"
)

func TestTOTPFailureCounterWindowAndClear(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	t0 := time.Unix(1_700_000_000, 0)
	const window = 15 * time.Minute
	const email = "admin@example.com"

	// No failures yet.
	if n, err := s.TOTPFailureCount(ctx, email, window, t0); err != nil || n != 0 {
		t.Fatalf("initial count = %d err %v, want 0", n, err)
	}
	// Two failures accumulate within the window.
	if n, _ := s.RecordTOTPFailure(ctx, email, window, t0); n != 1 {
		t.Errorf("failure 1 = %d, want 1", n)
	}
	if n, _ := s.RecordTOTPFailure(ctx, email, window, t0.Add(time.Minute)); n != 2 {
		t.Errorf("failure 2 = %d, want 2", n)
	}
	if n, _ := s.TOTPFailureCount(ctx, email, window, t0.Add(2*time.Minute)); n != 2 {
		t.Errorf("count within window = %d, want 2", n)
	}
	// A read past the window reports 0 (the lockout has lapsed).
	if n, _ := s.TOTPFailureCount(ctx, email, window, t0.Add(16*time.Minute)); n != 0 {
		t.Errorf("count after window = %d, want 0", n)
	}
	// A failure past the window restarts the counter at 1.
	if n, _ := s.RecordTOTPFailure(ctx, email, window, t0.Add(20*time.Minute)); n != 1 {
		t.Errorf("failure after window = %d, want 1 (restart)", n)
	}
	// Clearing (on success) resets to 0.
	if err := s.ClearTOTPFailures(ctx, email); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.TOTPFailureCount(ctx, email, window, t0.Add(20*time.Minute)); n != 0 {
		t.Errorf("count after clear = %d, want 0", n)
	}
}
