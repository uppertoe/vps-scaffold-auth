package server

import (
	"sync"
	"time"
)

// groupRecheckTTL is how long a "groups unchanged" result is remembered for a
// refused session. While it holds, a refused request is decided from memory,
// so a signed-in person repeatedly opening a route they are refused from does
// not put a query on the single SQLite connection each time. Membership
// changes made on the admin pages clear it (forgetAll), so they apply at once.
const groupRecheckTTL = 30 * time.Second

// groupRecheck remembers, per email and group snapshot, that the database
// agreed with the snapshot recently.
type groupRecheck struct {
	mu    sync.Mutex
	until map[string]time.Time
	// gen counts forgetAll calls. A request captures it before reading the
	// database and records its result only if no membership change happened
	// in between, so a read that raced an admin's change cannot be cached.
	gen uint64
}

func newGroupRecheck() *groupRecheck {
	return &groupRecheck{until: make(map[string]time.Time)}
}

func groupRecheckKey(email, groups string) string { return email + "\x00" + groups }

// fresh reports whether the snapshot was confirmed unchanged within the TTL.
func (g *groupRecheck) fresh(email, groups string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	t, ok := g.until[groupRecheckKey(email, groups)]
	return ok && now.Before(t)
}

// forgetAll drops every remembered result. Called whenever an administrator
// changes a membership or deletes a group, so the change is seen on the very
// next request rather than after the TTL.
func (g *groupRecheck) forgetAll() {
	g.mu.Lock()
	defer g.mu.Unlock()
	clear(g.until)
	g.gen++
}

// generation returns the current forgetAll count (see gen).
func (g *groupRecheck) generation() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.gen
}

// confirm records that the snapshot matched the database at now. Expired
// entries are swept when the map grows, so it stays bounded by the number of
// people refused within one TTL.
func (g *groupRecheck) confirm(email, groups string, now time.Time, gen uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if gen != g.gen {
		return // a membership changed while this request was reading
	}
	if len(g.until) >= 1024 {
		for k, t := range g.until {
			if !now.Before(t) {
				delete(g.until, k)
			}
		}
	}
	g.until[groupRecheckKey(email, groups)] = now.Add(groupRecheckTTL)
}
