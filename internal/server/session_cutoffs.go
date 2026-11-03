package server

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// Sessions are signed cookies, so the gateway keeps no record of each one.
// To end sessions early it keeps, per person and per break-glass card, the
// time before which every session has ended ("sign out everywhere", an
// authenticator removed, a card revoked or re-minted). A session whose
// sign-in (Identity.Auth) is at or before that time is refused wherever a
// session is read. The times are held in memory, loaded from the database at
// start and written through on every change, so the check on each request
// is a map lookup. This assumes one gateway process per database, as the
// SQLite store already does.
//
// Separately, every membership change moves groupsChangedAt forward, and a
// session whose groups were worked out before it (Identity.Iat) is renewed
// at its next request, so a removal from a group takes effect at once rather
// than at the next scheduled renewal.
type sessionCutoffs struct {
	mu              sync.RWMutex
	ended           map[string]int64
	groupsChangedAt int64
}

func newSessionCutoffs(ctx context.Context, st store.Store) (*sessionCutoffs, error) {
	ended, err := st.ListSessionCutoffs(ctx)
	if err != nil {
		return nil, err
	}
	// Membership changes only through this process (the admin pages and
	// the feeds, which sync at start), so nothing has changed yet.
	return &sessionCutoffs{ended: ended}, nil
}

func cardKey(id int64) string { return "card:" + strconv.FormatInt(id, 10) }

// passkeyKey keys the sessions a passkey started. Passkey IDs are never
// reused, so any entry means the passkey has been removed.
func passkeyKey(id int64) string { return "passkey:" + strconv.FormatInt(id, 10) }

// endSessions ends every session for key that began at or before now. The
// database is written first: if it fails, nothing changes and the caller
// reports the failure.
func (s *Server) endSessions(ctx context.Context, key string, now time.Time) error {
	if err := s.store.EndSessionsBefore(ctx, key, now); err != nil {
		return err
	}
	c := s.cutoffs
	c.mu.Lock()
	if now.Unix() > c.ended[key] {
		c.ended[key] = now.Unix()
	}
	c.mu.Unlock()
	return nil
}

// markGroupsChanged makes every session work out its groups again at its next
// request, and forgets the refusal path's cached results.
func (s *Server) markGroupsChanged(at time.Time) {
	s.groupRecheck.forgetAll()
	c := s.cutoffs
	c.mu.Lock()
	if at.Unix() > c.groupsChangedAt {
		c.groupsChangedAt = at.Unix()
	}
	c.mu.Unlock()
}

// sessionEnded reports whether a validly signed session has nonetheless
// ended: it is older than SESSION_MAX_AGE, its person signed out everywhere
// (or lost their authenticator) after it began, the passkey that started it
// has been removed, or its break-glass card was revoked or re-minted after it
// began.
func (s *Server) sessionEnded(id *session.Identity, now time.Time) bool {
	// A session from before the sign-in time was recorded (Auth 0, or 1 once
	// renewed) counts as signed in at the start of time: it is past any
	// maximum age and before any cutoff, so it ends and the person signs in
	// again once.
	auth := id.Auth
	if auth <= 1 {
		auth = 0
	}
	if max := s.cfg.SessionMaxAge; max > 0 && now.Unix()-auth > int64(max.Seconds()) {
		return true
	}
	c := s.cutoffs
	c.mu.RLock()
	defer c.mu.RUnlock()
	if at, ok := c.ended[id.Email]; ok && auth <= at {
		return true
	}
	if id.PK != 0 {
		if _, removed := c.ended[passkeyKey(id.PK)]; removed {
			return true
		}
	}
	if id.Kind == session.KindBreakGlass {
		// A break-glass session with no card predates the card being
		// recorded; it ends at its own short lifetime.
		if at, ok := c.ended[cardKey(id.Card)]; id.Card != 0 && ok && auth <= at {
			return true
		}
	}
	return false
}

// groupsStale reports whether a session's groups were worked out before the
// last membership change. Break-glass sessions carry their card's group, not
// a membership, and are never renewed.
func (s *Server) groupsStale(id *session.Identity) bool {
	if id.Kind == session.KindBreakGlass {
		return false
	}
	c := s.cutoffs
	c.mu.RLock()
	defer c.mu.RUnlock()
	return id.Iat < c.groupsChangedAt
}

// readSession is the only way the gateway reads a session: a signed session
// that has ended is no session.
func (s *Server) readSession(r *http.Request, now time.Time) (*session.Identity, bool) {
	id, ok := s.sessions.ReadSession(r, now)
	if !ok || s.sessionEnded(id, now) {
		return nil, false
	}
	return id, true
}
