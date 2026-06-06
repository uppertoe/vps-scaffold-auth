package server

import (
	"sync"
	"time"
)

// totpReplayWindow bounds how long an accepted TOTP code is remembered. The
// validator accepts only the current 30s step (skew 0), so two steps covers the
// whole window a code could still be valid, with margin for clock drift.
const totpReplayWindow = 90 * time.Second

// totpReplay records recently-accepted (admin, code) pairs so a single TOTP code
// cannot be replayed within its short validity window — e.g. by an attacker who
// phished or sniffed one code and races the legitimate admin. State is in-memory
// and self-pruning: sufficient for this single-instance service, matching the
// rate limiter's model (a restart simply forgets, which at worst re-allows one
// code for its remaining seconds).
type totpReplay struct {
	mu   sync.Mutex
	seen map[string]time.Time
	now  func() time.Time
}

func newTOTPReplay(now func() time.Time) *totpReplay {
	return &totpReplay{seen: make(map[string]time.Time), now: now}
}

// use reports whether (email, code) is fresh — not seen within totpReplayWindow —
// and records it. A replay returns false. Pruning is opportunistic, so the map
// stays bounded by the number of distinct codes used within the window.
func (g *totpReplay) use(email, code string) bool {
	key := email + "\x00" + code
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	for k, t := range g.seen {
		if now.Sub(t) > totpReplayWindow {
			delete(g.seen, k)
		}
	}
	if t, ok := g.seen[key]; ok && now.Sub(t) <= totpReplayWindow {
		return false
	}
	g.seen[key] = now
	return true
}
