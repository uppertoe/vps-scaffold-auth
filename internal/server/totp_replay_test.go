package server

import (
	"testing"
	"time"
)

// Deterministic unit test of the replay guard with a controllable clock: a code
// is accepted once, rejected as a replay within the window, and accepted again
// only after the window elapses. Different codes never collide.
func TestTOTPReplayGuard(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	g := newTOTPReplay(func() time.Time { return now })

	if !g.use("admin@example.com", "123456") {
		t.Fatal("first use should be accepted")
	}
	if g.use("admin@example.com", "123456") {
		t.Fatal("immediate reuse of the same code must be rejected as a replay")
	}
	// A different code for the same admin is independent.
	if !g.use("admin@example.com", "654321") {
		t.Fatal("a different code should be accepted")
	}
	// The same code for a different admin is independent.
	if !g.use("other@example.com", "123456") {
		t.Fatal("same code for a different admin should be accepted")
	}
	// Once the window has fully elapsed, the record is pruned and the code is no
	// longer remembered (by then it has long stopped validating anyway).
	now = now.Add(totpReplayWindow + time.Second)
	if !g.use("admin@example.com", "123456") {
		t.Fatal("after the window elapses the code is forgotten and accepted")
	}
}
