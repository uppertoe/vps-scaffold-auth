// Renewing, revoking and sweeping session rows.

package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// errGrantGone means the passkey or card a sign-in used was removed or
// withdrawn, or the session being replaced was ended, while the sign-in was
// under way.
var errGrantGone = errors.New("the passkey or card has been removed")

// grantStillValid reports whether the passkey or card a session is being
// started with still stands. Called under l.write.
func (s *Server) grantStillValid(ctx context.Context, id session.Identity) error {
	if id.PK != 0 {
		p, ok, err := s.store.GetPasskey(ctx, id.PK)
		if err != nil {
			return err
		}
		if !ok || p.Email != id.Email {
			return errGrantGone
		}
	}
	if id.Kind == session.KindBreakGlass && id.Card != 0 {
		c, ok, err := s.store.GetBreakGlassCode(ctx, id.Card)
		if err != nil {
			return err
		}
		if !ok || c.Status != store.BreakGlassActive || (id.CardCode != "" && c.TokenHash != id.CardCode) {
			return errGrantGone
		}
	}
	return nil
}

// writeCutoff records a cutoff in the database, then in memory.
func (s *Server) writeCutoff(ctx context.Context, key string, now time.Time) error {
	if err := s.store.EndSessionsBefore(ctx, key, now); err != nil {
		return err
	}
	l := s.live
	l.mu.Lock()
	if now.Unix() > l.cutoffs[key] {
		l.cutoffs[key] = now.Unix()
	}
	l.mu.Unlock()
	return nil
}

// renewSessionRow saves a renewal of the request's session: its kind and
// groups as worked out now, and a new expiry. The cookie is sent again, so
// the browser keeps it as long as the session lasts. ok is false when the
// session has ended meanwhile.
func (s *Server) renewSessionRow(w http.ResponseWriter, r *http.Request, id *session.Identity, kind, groups string, now time.Time) bool {
	_, token, _, err := s.resolveSession(r, now)
	if err != nil || token == "" {
		return false
	}
	l := s.live
	l.write.Lock()
	defer l.write.Unlock()
	l.mu.RLock()
	cur := l.byID[id.SID]
	var next store.Session
	if cur != nil {
		next = *cur
	}
	l.mu.RUnlock()
	if cur == nil {
		return false // ended while this request was on its way
	}
	next.Kind, next.Groups, next.Renewed = kind, groups, now
	// A guest never holds the remember-me lifetime (completeLogin), so a
	// session carried over as a guest's (carriedOverAsGuest) gives it up.
	if kind == session.KindGuest && s.cfg.SessionTTL > 0 && next.TTL > s.cfg.SessionTTL {
		next.TTL = s.cfg.SessionTTL
	}
	next.Expires = s.expiry(next.SignedIn, now, next.TTL)
	if err := s.store.UpdateSession(r.Context(), next); err != nil {
		// The session goes on as it was until its expiry; the renewal is
		// tried again at the next request.
		log.Printf("session renewal for %s: %v", id.Email, err)
		return true
	}
	l.mu.Lock()
	cur.Kind, cur.Groups, cur.Renewed, cur.TTL, cur.Expires = next.Kind, next.Groups, next.Renewed, next.TTL, next.Expires
	l.mu.Unlock()
	s.sessions.SetSession(w, token, next.Expires, now)
	return true
}

// markSeen moves a session's last-seen time to now in memory, and reports
// whether it was due (seenEvery), so that only one request writes it.
func (l *liveSessions) markSeen(id int64, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cur := l.byID[id]
	if cur == nil || now.Sub(cur.LastSeen) < seenEvery {
		return false
	}
	cur.LastSeen = now
	return true
}

// endSessionsWhere deletes every session match picks, and returns how many.
func (s *Server) endSessionsWhere(ctx context.Context, match func(*store.Session) bool) (int, error) {
	s.live.write.Lock()
	defer s.live.write.Unlock()
	return s.endSessionsLocked(ctx, match)
}

// endSessionsLocked is endSessionsWhere for a caller holding l.write.
func (s *Server) endSessionsLocked(ctx context.Context, match func(*store.Session) bool) (int, error) {
	l := s.live
	var ids []int64
	l.mu.RLock()
	for id, x := range l.byID {
		if match(x) {
			ids = append(ids, id)
		}
	}
	l.mu.RUnlock()
	slices.Sort(ids)
	if err := s.store.DeleteSessions(ctx, ids); err != nil {
		return 0, err
	}
	l.drop(ids)
	return len(ids), nil
}

// endSessions ends every session for key: a person's address, a passkey
// (passkeyKey) or a break-glass card (cardKey). Until the old cookie format
// is retired, the key's cutoff is written too, so an old cookie not yet
// converted is refused when it is (session_legacy.go). The cutoff is written
// first: if either write fails, the caller reports the failure.
func (s *Server) endSessions(ctx context.Context, key string, now time.Time) error {
	return s.revokeAnd(ctx, []string{key}, sessionsForKey(key), now, nil)
}

// revokeAnd ends the sessions match picks, writing the cutoff for each key
// first (session_legacy.go), and only then makes change: removing the
// passkey, withdrawing the card, replacing the authenticator. If ending the
// sessions fails, change is not made and the error is returned, so the
// administrator or person sees the failure and can try again with nothing
// lost. All of it runs under the lock a sign-in takes to start a session,
// and a sign-in checks its passkey or card again under it
// (grantStillValid), so no session started with the thing being changed can
// begin in between.
func (s *Server) revokeAnd(ctx context.Context, keys []string, match func(*store.Session) bool, now time.Time, change func() error) error {
	l := s.live
	l.write.Lock()
	defer l.write.Unlock()
	for _, k := range keys {
		if err := s.writeCutoff(ctx, k, now); err != nil {
			return err
		}
	}
	if _, err := s.endSessionsLocked(ctx, match); err != nil {
		return err
	}
	if change != nil {
		return change()
	}
	return nil
}

func cardKey(id int64) string { return "card:" + strconv.FormatInt(id, 10) }

// passkeyKey keys the sessions a passkey started. Passkey IDs are never
// reused.
func passkeyKey(id int64) string { return "passkey:" + strconv.FormatInt(id, 10) }

// sessionsForKey picks the sessions an endSessions key names.
func sessionsForKey(key string) func(*store.Session) bool {
	if n, ok := strings.CutPrefix(key, "passkey:"); ok {
		pk, _ := strconv.ParseInt(n, 10, 64)
		return func(x *store.Session) bool { return pk != 0 && x.Passkey == pk }
	}
	if n, ok := strings.CutPrefix(key, "card:"); ok {
		card, _ := strconv.ParseInt(n, 10, 64)
		return func(x *store.Session) bool {
			return card != 0 && x.Kind == session.KindBreakGlass && x.Card == card
		}
	}
	return func(x *store.Session) bool { return x.Kind != session.KindBreakGlass && x.Email == key }
}

// endThisSession ends the request's own session and clears its cookie.
func (s *Server) endThisSession(w http.ResponseWriter, r *http.Request, id *session.Identity) {
	if id != nil && id.SID != 0 {
		if _, err := s.endSessionsWhere(r.Context(), func(x *store.Session) bool { return x.ID == id.SID }); err != nil {
			log.Printf("end session of %s: %v", id.Email, err)
		}
	}
	s.sessions.ClearSession(w)
}

// liveSessionsNow returns a copy of every live session, most recently seen
// first; email, when set, keeps only that person's.
func (s *Server) liveSessionsNow(email string, now time.Time) []store.Session {
	l := s.live
	l.mu.RLock()
	out := make([]store.Session, 0, len(l.byID))
	for _, x := range l.byID {
		if (email == "" || x.Email == email) && s.sessionLive(x, now) {
			out = append(out, *x)
		}
	}
	l.mu.RUnlock()
	slices.SortFunc(out, func(a, b store.Session) int {
		if c := b.LastSeen.Compare(a.LastSeen); c != 0 {
			return c
		}
		return int(b.ID - a.ID)
	})
	return out
}

// sweepSessions deletes expired sessions, at most once every sweepEvery.
func (s *Server) sweepSessions(ctx context.Context, now time.Time) {
	l := s.live
	l.write.Lock()
	defer l.write.Unlock()
	if now.Sub(l.swept) < sweepEvery {
		return
	}
	l.swept = now
	if err := s.store.DeleteExpiredSessions(ctx, now); err != nil {
		log.Printf("delete expired sessions: %v", err)
		return
	}
	var gone []int64
	l.mu.Lock()
	for id, x := range l.byID {
		if !now.Before(x.Expires) {
			gone = append(gone, id)
		}
	}
	for h, until := range l.refused {
		if !now.Before(until) {
			delete(l.refused, h)
		}
	}
	l.mu.Unlock()
	l.drop(gone)
}

// markGroupsChanged makes every session work out its groups again at its next
// request, and forgets the refusal path's cached results.
func (s *Server) markGroupsChanged(at time.Time) {
	s.groupRecheck.forgetAll()
	// Stored first, so a restart cannot forget the change. If the write
	// fails, the change still reaches every session in this process.
	if err := s.writeCutoff(context.Background(), groupsKey, at); err != nil {
		log.Printf("record membership change: %v", err)
	}
	l := s.live
	l.mu.Lock()
	if at.Unix() > l.groupsChangedAt {
		l.groupsChangedAt = at.Unix()
	}
	l.mu.Unlock()
}

// groupsStale reports whether a session's groups were worked out before the
// last membership change. A break-glass session carries its card's app and
// role, not a membership, and is never renewed.
func (s *Server) groupsStale(id *session.Identity) bool {
	if id.Kind == session.KindBreakGlass {
		return false
	}
	l := s.live
	l.mu.RLock()
	defer l.mu.RUnlock()
	// At or before: a change in the same second as the session's groups were
	// worked out may have come after it. The renewal sets Iat to the current
	// second, so this repeats only within that second.
	return l.groupsChangedAt != 0 && id.Iat <= l.groupsChangedAt
}
