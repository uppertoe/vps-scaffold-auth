package ratelimit

import (
	"testing"
	"time"
)

func TestAllowWithinLimit(t *testing.T) {
	l := New(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !l.Allow("k") {
			t.Fatalf("event %d should be allowed", i)
		}
	}
	if l.Allow("k") {
		t.Error("4th event should be denied")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l := New(1, time.Minute)
	if !l.Allow("a") {
		t.Error("a first should pass")
	}
	if !l.Allow("b") {
		t.Error("b first should pass")
	}
	if l.Allow("a") {
		t.Error("a second should be denied")
	}
}

func TestRefillOverTime(t *testing.T) {
	l := New(2, time.Minute)
	clock := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return clock }

	if !l.Allow("k") || !l.Allow("k") {
		t.Fatal("first two should pass")
	}
	if l.Allow("k") {
		t.Fatal("third should be denied immediately")
	}
	// Advance past one window: tokens fully refill.
	clock = clock.Add(time.Minute)
	if !l.Allow("k") {
		t.Error("should be allowed after refill window")
	}
}
