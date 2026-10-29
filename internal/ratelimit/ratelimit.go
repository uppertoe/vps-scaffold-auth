// Package ratelimit provides a small in-memory token-bucket limiter, keyed by
// an arbitrary string (email or client IP). It is sufficient for a
// single-instance service; there is no shared state across replicas.
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// Limiter allows up to `count` events per `window` per key, refilling
// continuously.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	count   float64
	rate    float64 // tokens per second
	window  time.Duration
	now     func() time.Time
	lastGC  time.Time
}

// New returns a Limiter permitting count events per window per key.
func New(count int, window time.Duration) *Limiter {
	return &Limiter{
		buckets: make(map[string]*bucket),
		count:   float64(count),
		rate:    float64(count) / window.Seconds(),
		window:  window,
		now:     time.Now,
	}
}

// Allow consumes one token for key, returning false if the key is over its
// limit.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.refill(key)
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// Refund returns one token to key, up to the limit: for a caller that charges
// every attempt up front, so that simultaneous attempts cannot all pass a
// check before any is charged, and gives the token back when the outcome
// should be free (a correct code).
func (l *Limiter) Refund(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.refill(key)
	if b.tokens++; b.tokens > l.count {
		b.tokens = l.count
	}
}

// refill returns key's bucket, created full on first sighting and topped up
// for the time since it was last seen. Called with the lock held.
func (l *Limiter) refill(key string) *bucket {
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.count, lastSeen: now}
		l.buckets[key] = b
		l.gc(now)
		return b
	}
	b.tokens += now.Sub(b.lastSeen).Seconds() * l.rate
	if b.tokens > l.count {
		b.tokens = l.count
	}
	b.lastSeen = now
	return b
}

// gc drops buckets that have refilled completely: a full bucket behaves
// exactly like an absent one, so dropping it changes no decision. Each bucket
// is full again within window/count of its last token being spent, so under a
// spray of new keys the map holds only recent activity. gc runs while the lock
// is held, only once the map is large, and at most once per gcInterval, so a
// spray cannot make every insert pay for a full sweep.
func (l *Limiter) gc(now time.Time) {
	if len(l.buckets) < gcThreshold || now.Sub(l.lastGC) < gcInterval {
		return
	}
	l.lastGC = now
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.lastSeen).Seconds()*l.rate >= l.count {
			delete(l.buckets, k)
		}
	}
}

const (
	gcThreshold = 1000
	gcInterval  = time.Second
)
