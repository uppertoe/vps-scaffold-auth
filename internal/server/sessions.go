package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// Sessions are kept by the gateway. The cookie carries a random token, and
// the sessions table holds its hash with everything the session says: the
// address, kind, groups, admin step, the passkey or card behind it, and when
// it was signed in, renewed and last seen. Ending a session is deleting its
// row, wherever the request for it comes from.
//
// The rows are held in memory, loaded at start and written through on every
// change (the database first, so a failed write changes nothing), so a request
// finds its session with a map lookup and the database being unavailable
// leaves existing sessions working. This assumes one gateway process per
// database, which lockDatabase enforces.
type liveSessions struct {
	// write serialises every change, so the maps and the table never
	// disagree: a sign-in and a revocation at the same moment are applied in
	// one order to both.
	write  sync.Mutex
	mu     sync.RWMutex
	byHash map[string]*store.Session
	byID   map[int64]*store.Session
	swept  time.Time
	// groupsChangedAt is when a membership last changed (Unix seconds). A
	// session whose groups were worked out at or before it renews at its
	// next request (groupsStale).
	groupsChangedAt int64
	// cutoffs mirrors session_cutoffs, and refused holds the old-format
	// cookies (by the hash of their new token) already refused or whose
	// row has been deleted, until their own expiry. Both only grow, so a
	// refusal read from them without the write lock is final, and a
	// refused old cookie sent again and again never waits on that lock or
	// reaches the database (session_legacy.go).
	cutoffs map[string]int64
	refused map[string]time.Time
}

// seenEvery is how often a session's last-seen time is written to the
// database. It is kept in memory at every request.
const seenEvery = 5 * time.Minute

// sweepEvery is how often expired sessions are deleted.
const sweepEvery = time.Hour

// groupsKey stores the time of the last membership change in the
// session_cutoffs table. It has no "@", so it is never a person's address.
const groupsKey = "groups"

func loadSessions(ctx context.Context, st store.Store, now time.Time) (*liveSessions, error) {
	rows, err := st.ListSessions(ctx, now)
	if err != nil {
		return nil, err
	}
	cut, err := st.ListSessionCutoffs(ctx)
	if err != nil {
		return nil, err
	}
	migrated, err := st.ListMigratedSessions(ctx, now)
	if err != nil {
		return nil, err
	}
	l := &liveSessions{byHash: map[string]*store.Session{}, byID: map[int64]*store.Session{}, groupsChangedAt: cut[groupsKey], cutoffs: cut, refused: map[string]time.Time{}}
	for i := range rows {
		x := rows[i]
		l.byHash[string(x.Hash)], l.byID[x.ID] = &x, &x
	}
	// A converted old cookie whose row is gone has ended.
	for h, until := range migrated {
		if l.byHash[h] == nil {
			l.refused[h] = until
		}
	}
	return l, nil
}

// identityOf is the session a row describes, as the handlers read it. It is
// a copy, so a handler may change it for its own response.
func identityOf(x *store.Session) *session.Identity {
	return &session.Identity{
		Email: x.Email, Groups: x.Groups, Kind: x.Kind,
		Iat: x.Renewed.Unix(), TTL: int64(x.TTL.Seconds()),
		TOTP: x.TOTP, Step: x.Step, PK: x.Passkey, Card: x.Card,
		Auth: x.SignedIn.Unix(), SID: x.ID,
	}
}

// expiry is when a session renewed at now with lifetime ttl expires: ttl
// from now, but never later than SESSION_MAX_AGE from sign-in.
func (s *Server) expiry(signedIn, now time.Time, ttl time.Duration) time.Time {
	exp := now.Add(ttl)
	if max := s.cfg.SessionMaxAge; max > 0 && exp.After(signedIn.Add(max)) {
		exp = signedIn.Add(max)
	}
	return exp
}

// sessionLive reports whether a row is a session at now.
func (s *Server) sessionLive(x *store.Session, now time.Time) bool {
	if !now.Before(x.Expires) {
		return false
	}
	max := s.cfg.SessionMaxAge
	return max <= 0 || now.Sub(x.SignedIn) <= max
}

// errSessionsUnavailable means the session could not be read because the
// database could not be reached. The caller answers 503 and leaves the cookie
// alone, rather than signing the person out.
var errSessionsUnavailable = errors.New("sessions unavailable")

// resolveSession finds the session a request's cookie names. token is the
// cookie value the session is known by from now on, which differs from the
// cookie the browser sent only for an old-format cookie (legacy).
func (s *Server) resolveSession(r *http.Request, now time.Time) (x *store.Session, token string, legacy bool, err error) {
	value, ok := s.sessions.SessionToken(r)
	if !ok {
		return nil, "", false, nil
	}
	token = value
	if session.IsLegacy(value) {
		// An old cookie is honoured only while it is itself valid, so a copy
		// taken before the upgrade gains no time from the row it reaches.
		if _, _, ok := s.sessions.ReadLegacySession(value, now); !ok {
			return nil, "", true, nil
		}
		legacy = true
		token = s.sessions.MigratedToken(value)
	}
	l := s.live
	l.mu.RLock()
	found := l.byHash[string(session.TokenHash(token))]
	var cp store.Session
	if found != nil {
		cp = *found
	}
	l.mu.RUnlock()
	if found == nil && legacy {
		got, err := s.convertLegacy(r, value, token, now)
		if err != nil {
			return nil, "", true, err
		}
		if got == nil {
			return nil, "", true, nil
		}
		cp = *got
		found = got
	}
	if found == nil || !s.sessionLive(&cp, now) {
		return nil, "", legacy, nil
	}
	if now.Sub(cp.LastSeen) >= seenEvery && l.markSeen(cp.ID, now) {
		// Outside the write lock: a request never waits behind a sign-in or
		// a revocation for this. A failed write is not retried until the
		// next interval, and a write to a row deleted meanwhile changes
		// nothing.
		if err := s.store.TouchSession(r.Context(), cp.ID, now); err != nil {
			log.Printf("session last seen: %v", err)
		}
	}
	return &cp, token, legacy, nil
}

// readSession is the only way the gateway reads a session: the session the
// request's cookie names, if it is live.
func (s *Server) readSession(r *http.Request, now time.Time) (*session.Identity, bool) {
	x, _, _, err := s.resolveSession(r, now)
	if err != nil || x == nil {
		return nil, false
	}
	return identityOf(x), true
}

// startSession signs a person in: a new row, and a cookie naming it. A
// session the request already carried is replaced, since the browser keeps
// only one cookie; replacing it also gives a new token whenever the session
// gains the admin step.
//
// A session built from an existing one (id.SID set: the admin step) starts
// only if
// that session is still live under the write lock, so a revocation that
// lands after the handler read it cannot be outlived by its replacement.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, id session.Identity, ttl time.Duration, now time.Time) error {
	token, x, err := s.newSessionRow(r, id, ttl, now)
	if err != nil {
		return err
	}
	var replaced []int64
	if cur, _, _, err := s.resolveSession(r, now); err == nil && cur != nil {
		replaced = []int64{cur.ID}
	}
	l := s.live
	l.write.Lock()
	// The passkey or card behind the session is checked again under the
	// lock every revocation takes (revokeAnd), so a sign-in already under
	// way when it is removed or withdrawn cannot start a session after.
	err = s.grantStillValid(r.Context(), id)
	if err == nil && id.SID != 0 {
		l.mu.RLock()
		_, live := l.byID[id.SID]
		l.mu.RUnlock()
		if !live {
			err = errGrantGone
		}
	}
	if err == nil {
		x.ID, err = s.store.CreateSession(r.Context(), x)
	}
	if err == nil {
		l.add(&x)
		// The replaced session is only one the browser can no longer name;
		// if deleting it fails, it expires on its own.
		if err := s.store.DeleteSessions(r.Context(), replaced); err != nil {
			log.Printf("replace session: %v", err)
		} else {
			l.drop(replaced)
		}
	}
	l.write.Unlock()
	if err != nil {
		return err
	}
	s.sessions.SetSession(w, token, x.Expires, now)
	s.sweepSessions(r.Context(), now)
	return nil
}

// newSessionRow builds the row for a session under a new token. A session
// carried over from an existing row (id.SID and id.Iat set: a new token after
// a sign-out of other sessions) keeps the time its groups were worked out, so
// a membership change since then still makes it renew at its next request
// (groupsStale). A session whose groups were worked out just now (a sign-in,
// the admin step) is renewed now.
func (s *Server) newSessionRow(r *http.Request, id session.Identity, ttl time.Duration, now time.Time) (string, store.Session, error) {
	if ttl <= 0 {
		ttl = s.sessions.DefaultTTL()
	}
	token, err := session.NewToken()
	if err != nil {
		return "", store.Session{}, err
	}
	signedIn := now
	if id.Auth > 0 {
		signedIn = time.Unix(id.Auth, 0)
	}
	renewed := now
	if id.SID != 0 && id.Iat > 0 && id.Iat < now.Unix() {
		renewed = time.Unix(id.Iat, 0)
	}
	return token, store.Session{
		Hash: session.TokenHash(token), Email: id.Email, Kind: id.Kind, Groups: id.Groups,
		TOTP: id.TOTP, Step: id.Step, Passkey: id.PK, Card: id.Card,
		SignedIn: signedIn, Renewed: renewed, TTL: ttl, Expires: s.expiry(signedIn, now, ttl),
		LastSeen: now, Device: deviceSummary(r.UserAgent()),
	}, nil
}

// endOthersAndRotate ends every session match picks other than the request's
// own (id.SID), and gives the request's own session a new token, as one
// change under the write lock: the new row is made first, then the old row
// and the others are deleted in one statement. If either write fails, nothing
// has changed (the new row, whose token was never sent, is deleted again) and
// the error is returned. If the request's own session has ended by the time
// the lock is held, nothing is done and mineLive is false. The cookie is set
// only once everything has been written.
func (s *Server) endOthersAndRotate(w http.ResponseWriter, r *http.Request, id *session.Identity, now time.Time, match func(*store.Session) bool) (ended []store.Session, mineLive bool, err error) {
	token, x, err := s.newSessionRow(r, *id, s.sessions.SessionTTL(id), now)
	if err != nil {
		return nil, true, err
	}
	l := s.live
	l.write.Lock()
	l.mu.RLock()
	mineLive = l.byID[id.SID] != nil
	ids := []int64{id.SID}
	for xid, row := range l.byID {
		if xid != id.SID && match(row) {
			ids = append(ids, xid)
			ended = append(ended, *row)
		}
	}
	l.mu.RUnlock()
	if !mineLive {
		l.write.Unlock()
		return nil, false, nil
	}
	if err = s.grantStillValid(r.Context(), *id); err == nil {
		x.ID, err = s.store.CreateSession(r.Context(), x)
		if err == nil {
			slices.Sort(ids[1:])
			if err = s.store.DeleteSessions(r.Context(), ids); err != nil {
				if derr := s.store.DeleteSessions(r.Context(), []int64{x.ID}); derr != nil {
					log.Printf("delete an unused new session: %v", derr)
				}
			}
		}
	}
	if err == nil {
		l.add(&x)
		l.drop(ids)
	}
	l.write.Unlock()
	if err != nil {
		return nil, true, err
	}
	s.sessions.SetSession(w, token, x.Expires, now)
	return ended, true, nil
}

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

func (l *liveSessions) add(x *store.Session) {
	l.mu.Lock()
	l.byHash[string(x.Hash)], l.byID[x.ID] = x, x
	l.mu.Unlock()
}

func (l *liveSessions) drop(ids []int64) {
	l.mu.Lock()
	for _, id := range ids {
		if x := l.byID[id]; x != nil {
			delete(l.byHash, string(x.Hash))
			delete(l.byID, id)
			// If the row came from an old cookie, that cookie stays refused.
			l.refused[string(x.Hash)] = x.Expires
		}
	}
	l.mu.Unlock()
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
	next.Expires = s.expiry(next.SignedIn, now, next.TTL)
	if err := s.store.UpdateSession(r.Context(), next); err != nil {
		// The session goes on as it was until its expiry; the renewal is
		// tried again at the next request.
		log.Printf("session renewal for %s: %v", id.Email, err)
		return true
	}
	l.mu.Lock()
	cur.Kind, cur.Groups, cur.Renewed, cur.Expires = next.Kind, next.Groups, next.Renewed, next.Expires
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
// last membership change. Break-glass sessions carry their card's group, not
// a membership, and are never renewed.
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

// deviceSummary names the browser and the system it runs on, such as
// "Safari on iPhone", for the list of sessions. Only the summary is kept.
func deviceSummary(ua string) string {
	browser := ""
	switch {
	case strings.Contains(ua, "Edg/"):
		browser = "Edge"
	case strings.Contains(ua, "Firefox/") || strings.Contains(ua, "FxiOS/"):
		browser = "Firefox"
	case strings.Contains(ua, "Chrome/") || strings.Contains(ua, "CriOS/"):
		browser = "Chrome"
	case strings.Contains(ua, "Safari/"):
		browser = "Safari"
	}
	system := ""
	switch {
	case strings.Contains(ua, "iPhone"):
		system = "iPhone"
	case strings.Contains(ua, "iPad"):
		system = "iPad"
	case strings.Contains(ua, "Android"):
		system = "Android"
	case strings.Contains(ua, "Windows"):
		system = "Windows"
	case strings.Contains(ua, "CrOS"):
		system = "ChromeOS"
	case strings.Contains(ua, "Macintosh"):
		system = "Mac"
	case strings.Contains(ua, "Linux"):
		system = "Linux"
	}
	switch {
	case browser != "" && system != "":
		return browser + " on " + system
	case browser != "":
		return browser
	default:
		return system
	}
}
