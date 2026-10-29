package ratelimit

import (
	"fmt"
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

func TestRefundReturnsOneToken(t *testing.T) {
	l := New(2, time.Hour)
	if !l.Allow("k") || !l.Allow("k") {
		t.Fatal("first two should pass")
	}
	l.Refund("k")
	if !l.Allow("k") {
		t.Fatal("a refunded token should be spendable")
	}
	if l.Allow("k") {
		t.Fatal("only one token was refunded")
	}
	for i := 0; i < 5; i++ {
		l.Refund("k")
	}
	if !l.Allow("k") || !l.Allow("k") || l.Allow("k") {
		t.Error("refunds should not raise a bucket above its limit")
	}
}

// A spray of distinct keys does not grow the map without bound: buckets that
// have refilled are swept, at most once per gcInterval.
func TestSprayIsSwept(t *testing.T) {
	l := New(5, time.Minute) // a spent token refills in 12 s
	clock := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return clock }
	for i := 0; i < 50_000; i++ {
		l.Allow(fmt.Sprintf("k%d", i))
		clock = clock.Add(10 * time.Millisecond) // 100 new keys a second
	}
	// At 100 keys a second and 12 s to refill, about 1,200 are live; allow for
	// the sweep running only once a second.
	if n := len(l.buckets); n > 2*gcThreshold {
		t.Errorf("map holds %d buckets after a spray, want about 1,300", n)
	}
}

// Sweeping never forgets a bucket that is still limiting.
func TestSweepKeepsSpentBuckets(t *testing.T) {
	l := New(1, time.Hour)
	clock := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return clock }
	l.Allow("held")
	for i := 0; i < 3*gcThreshold; i++ {
		clock = clock.Add(2 * time.Millisecond)
		l.Allow(fmt.Sprintf("k%d", i))
	}
	if l.Allow("held") {
		t.Error("a spent bucket was swept and its key allowed again")
	}
}
