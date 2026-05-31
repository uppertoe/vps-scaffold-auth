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

	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		// First sighting starts full, then immediately spends one token.
		b = &bucket{tokens: l.count, lastSeen: now}
		l.buckets[key] = b
		l.gc(now)
	} else {
		elapsed := now.Sub(b.lastSeen).Seconds()
		b.tokens += elapsed * l.rate
		if b.tokens > l.count {
			b.tokens = l.count
		}
		b.lastSeen = now
	}

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// gc opportunistically drops idle buckets so the map cannot grow without
// bound. Called while the lock is held, and only when the map is large.
func (l *Limiter) gc(now time.Time) {
	if len(l.buckets) < 10000 {
		return
	}
	cutoff := now.Add(-l.window)
	for k, b := range l.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
}
