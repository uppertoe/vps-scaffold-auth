package server

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// The conversion of old-format session cookies, which carried the whole
// identity in a signed envelope and kept no record on the gateway. This file
// goes, with session.ReadLegacySession, the cutoff writes in endSessions and
// the session_cutoffs rows other than groupsKey, once SESSION_MAX_AGE has
// passed since the release that added the sessions table: no old cookie can
// be honoured after that, since none outlives SESSION_MAX_AGE from its
// sign-in.
//
// An old cookie is checked as it always was (signature, purpose, expiry,
// SESSION_MAX_AGE, and the cutoffs: "sign out on every device", an
// authenticator replaced, a passkey removed, a card withdrawn, and "sign out
// everyone"). If it passes, it becomes a session row keeping its sign-in time,
// expiry, groups, passkey and card, under a token derived from the old cookie
// (MigratedToken), so parallel requests with the same old cookie reach the
// same row. The conversion is recorded until the old cookie's own expiry, so
// once the row is deleted the old cookie is refused rather than converted
// again.

// everyoneKey is the cutoff "sign out everyone" writes. It has no "@", so it
// is never a person's address.
const everyoneKey = "everyone"

// convertLegacy converts an old-format cookie value. A nil session with no
// error means the cookie is not, or is no longer, a session.
func (s *Server) convertLegacy(r *http.Request, value, token string, now time.Time) (*store.Session, error) {
	id, exp, ok := s.sessions.ReadLegacySession(value, now)
	if !ok || !knownSessionKind(id.Kind) {
		return nil, nil
	}
	ttl := s.sessions.SessionTTL(id)
	x := store.Session{
		Hash: session.TokenHash(token), Email: id.Email, Kind: id.Kind, Groups: id.Groups,
		TOTP: id.TOTP, Step: id.Step, Passkey: id.PK, Card: id.Card,
		SignedIn: time.Unix(id.Auth, 0), Renewed: time.Unix(id.Iat, 0), TTL: ttl,
		Expires: exp, LastSeen: now, Device: deviceSummary(r.UserAgent()),
	}
	if max := s.cfg.SessionMaxAge; max > 0 && x.Expires.After(x.SignedIn.Add(max)) {
		x.Expires = x.SignedIn.Add(max)
	}
	// Everything from here runs under the lock every revocation takes
	// (revokeAnd), so a revocation lands either before the cutoffs are
	// read, and refuses the cookie, or after the row is made, and deletes
	// it.
	l := s.live
	l.write.Lock()
	defer l.write.Unlock()
	// Another request with the same cookie may have converted it meanwhile.
	l.mu.RLock()
	got := l.byHash[string(x.Hash)]
	var cp store.Session
	if got != nil {
		cp = *got
	}
	l.mu.RUnlock()
	if got != nil {
		return &cp, nil
	}
	cut, err := s.store.ListSessionCutoffs(r.Context())
	if err != nil {
		log.Printf("session conversion: %v", err)
		return nil, errSessionsUnavailable
	}
	if legacyEnded(id, cut, s.cfg.SessionMaxAge, now) {
		return nil, nil
	}
	// A passkey removed before its removal wrote a cutoff (early November
	// 2026) ended its sessions only at renewal; its old cookies are refused
	// here.
	if err := s.grantStillValid(r.Context(), session.Identity{Email: id.Email, PK: id.PK}); errors.Is(err, errGrantGone) {
		return nil, nil
	} else if err != nil {
		log.Printf("session conversion: %v", err)
		return nil, errSessionsUnavailable
	}
	var ok2 bool
	x.ID, ok2, err = s.store.CreateMigratedSession(r.Context(), x, exp)
	if err != nil {
		log.Printf("session conversion for %s: %v", id.Email, err)
		return nil, errSessionsUnavailable
	}
	if !ok2 {
		return nil, nil // converted before, and since ended
	}
	l.add(&x)
	cp = x
	return &cp, nil
}

// legacyEnded reports whether an old-format session has ended: it is older
// than SESSION_MAX_AGE, or a cutoff for its person, its passkey, its card or
// everyone was written at or after its sign-in.
func legacyEnded(id *session.Identity, cut map[string]int64, maxAge time.Duration, now time.Time) bool {
	// A session from before the sign-in time was recorded (Auth 0, or 1 once
	// renewed) counts as signed in at the start of time: it is past any
	// maximum age and before any cutoff, so it ends and the person signs in
	// again once.
	auth := id.Auth
	if auth <= 1 {
		return true
	}
	if maxAge > 0 && now.Unix()-auth > int64(maxAge.Seconds()) {
		return true
	}
	if at, ok := cut[everyoneKey]; ok && auth <= at {
		return true
	}
	if id.Kind != session.KindBreakGlass {
		if at, ok := cut[id.Email]; ok && id.Email != groupsKey && auth <= at {
			return true
		}
	}
	if id.PK != 0 {
		if _, removed := cut[passkeyKey(id.PK)]; removed {
			return true
		}
	}
	if id.Kind == session.KindBreakGlass {
		// A break-glass session with no card predates the card being
		// recorded; it ends at its own short lifetime.
		if at, ok := cut[cardKey(id.Card)]; id.Card != 0 && ok && auth <= at {
			return true
		}
	}
	return false
}
