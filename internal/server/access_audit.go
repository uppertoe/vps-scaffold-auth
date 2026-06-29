package server

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// accessAudit records, off the hot path, which principal reached which app —
// deduplicated to one row per (email, host, kind, hour). handleVerify runs on
// every request to a protected app (assets, API calls and all), so a per-request
// DB write is untenable; instead an in-memory set absorbs every sighting after
// the first for each (principal, app) within the current hour, making the steady
// state a map lookup. The hourly rollover clears that set and opportunistically
// prunes rows past the retention window, so the table stays bounded without a
// dedicated background scheduler.
type accessAudit struct {
	store     store.Store
	retention time.Duration

	mu      sync.Mutex
	hour    int64
	seen    map[string]struct{}
	pruning bool
}

func newAccessAudit(st store.Store, retention time.Duration) *accessAudit {
	return &accessAudit{store: st, retention: retention, seen: make(map[string]struct{})}
}

// record notes an authenticated access. It is safe for concurrent use and touches
// the database only on the first sighting of a (principal, app, kind) tuple in a
// given hour. A blank host (a /verify with no X-Forwarded-Host) is ignored.
func (a *accessAudit) record(ctx context.Context, email, host, kind string, now time.Time) {
	if host == "" {
		return
	}
	bucket := now.Unix() / 3600
	key := email + "\x00" + kind + "\x00" + host

	a.mu.Lock()
	if bucket != a.hour {
		// New hour: reset the dedup set and (best-effort) prune old rows.
		a.hour = bucket
		a.seen = make(map[string]struct{})
		a.kickPruneLocked(now)
	}
	if _, ok := a.seen[key]; ok {
		a.mu.Unlock()
		return
	}
	// Mark seen before writing so concurrent first-sightings collapse to one
	// write; the DB's UNIQUE constraint is the backstop if a write is lost.
	a.seen[key] = struct{}{}
	a.mu.Unlock()

	if err := a.store.RecordAppAccess(ctx, store.AppAccess{
		Email: email, Host: host, Kind: kind, Bucket: bucket, CreatedAt: now,
	}); err != nil {
		log.Printf("record app access %s -> %s: %v", email, host, err)
	}
}

// kickPruneLocked fires at most one background prune of expired audit rows. It is
// called under a.mu at the hourly rollover; the delete itself runs detached so it
// never sits in a request's path. A non-positive retention disables pruning.
func (a *accessAudit) kickPruneLocked(now time.Time) {
	if a.pruning || a.retention <= 0 {
		return
	}
	a.pruning = true
	cutoff := now.Add(-a.retention)
	go func() {
		defer func() {
			a.mu.Lock()
			a.pruning = false
			a.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := a.store.PruneAuditBefore(ctx, cutoff); err != nil {
			log.Printf("prune audit log: %v", err)
		}
	}()
}
