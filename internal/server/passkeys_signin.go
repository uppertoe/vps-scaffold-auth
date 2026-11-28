// Signing in with a passkey, and the cookie that remembers which passkeys this browser holds.

package server

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/passkey"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// handlePasskeyLogin signs a person in with a passkey.
func (s *Server) handlePasskeyLogin(w http.ResponseWriter, r *http.Request) {
	if s.passkeysOff(w, r) || !s.requireSameOrigin(w, r) {
		return
	}
	now := s.now()
	rd := authz.SafeRedirect(r.PostFormValue("rd"), s.cfg.Domain, "")
	remember := r.PostFormValue("remember") == "1"
	unknown := ""
	failed := func(msg string) {
		if msg == "" {
			msg = "Your passkey could not be used to sign in. Please try again, or sign in with an email code."
		}
		s.renderLogin(w, r, http.StatusUnauthorized, pageData{Error: msg, Redirect: rd, Remember: remember, Passkey: &passkeyPage{Unknown: unknown}})
	}
	// Charged up front and refunded on success, as for email codes.
	ip := clientIP(r)
	if !s.wrongCodes.Allow(ip) {
		failed("Too many attempts. Please wait and try again.")
		return
	}
	ch, ok := s.sessions.ReadPasskeyChallenge(r, false, now)
	if !ok || !s.passkeyChallenges.use(r.Context(), ch.Challenge) {
		failed("")
		return
	}
	s.sessions.ClearPasskeyChallenge(w, false)
	credID, ok1 := unb64(r.PostFormValue("id"))
	cd, ok2 := unb64(r.PostFormValue("clientDataJSON"))
	ad, ok3 := unb64(r.PostFormValue("authenticatorData"))
	sig, ok4 := unb64(r.PostFormValue("signature"))
	handle, ok5 := unb64(r.PostFormValue("userHandle"))
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		failed("")
		return
	}
	pk, found, err := s.store.PasskeyByCredentialID(r.Context(), credID)
	if err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong", Redirect: rd})
		return
	}
	if !found {
		log.Printf("passkey sign-in with an unknown credential from %s", ip)
		unknown = b64(credID)
		s.forgetPasskeyHere(w, r, credID)
		failed("This passkey can no longer be used to sign in. Please sign in with an email code.")
		return
	}
	if string(handle) != string(pk.UserHandle) {
		s.recordAuth(r, pk.Email, store.AuthEventPasskey, store.AuthOutcomeBadPasskey)
		failed("")
		return
	}
	count, err := s.relyingParty().VerifyAssertion(passkey.Assertion{
		CredentialID: credID, ClientDataJSON: cd, AuthenticatorData: ad, Signature: sig, UserHandle: handle,
	}, ch.Challenge, pk.PublicKey, pk.SignCount)
	if err != nil {
		outcome := store.AuthOutcomeBadPasskey
		if err == passkey.ErrCounter {
			outcome = store.AuthOutcomePasskeyCounter
		}
		log.Printf("passkey sign-in for %s refused: %v", pk.Email, err)
		s.recordAuth(r, pk.Email, store.AuthEventPasskey, outcome)
		failed("")
		return
	}
	if err := s.store.TouchPasskey(r.Context(), pk.ID, count, now); err != nil {
		log.Printf("touch passkey %d: %v", pk.ID, err)
	}
	// The role comes from the current policy, exactly as for an email code
	// to the same destination (loginRole). A passkey is never a way in for an
	// address that may no longer sign in, and makes a guest only where an
	// emailed code would.
	if s.rolesUnavailable(r.Context()) {
		s.renderUnavailable(w, rd)
		return
	}
	role := s.loginRole(r.Context(), pk.Email, s.isOpenHost(r.Context(), rd))
	if !mayHoldPasskey(role) {
		s.recordAuth(r, pk.Email, store.AuthEventPasskey, store.AuthOutcomeDenied)
		s.renderLogin(w, r, http.StatusForbidden, pageData{Error: "This account is not permitted.", Redirect: rd})
		return
	}
	s.wrongCodes.Refund(ip)
	s.recordAuth(r, pk.Email, store.AuthEventPasskey, store.AuthOutcomeOK)
	// A passkey that has just signed in here is one this device holds.
	s.rememberPasskeyHere(w, r, credID)
	// A passkey used at the admin door signs the person in afresh. If the
	// session it replaces was a remembered one of the same person, the new one
	// is remembered too, so that opening the admin pages does not shorten it.
	if cur, ok := s.readSession(r, now); ok && personSession(cur) && cur.Email == pk.Email && s.sessions.SessionTTL(cur) > s.cfg.SessionTTL {
		remember = true
	}
	// A passkey that stands in for the second step gives the admin tier at
	// once. Any other gives an ordinary session, and the admin door asks for
	// the authenticator code when it is needed.
	s.completeLogin(w, r, pk.Email, role, rd, remember, role == authz.RoleAdmin && s.cfg.TOTPEnabled && pk.AdminGrade, pk.ID, now)
}

// passkeyHereName is the name of passkeyHereCookie. Under TLS it carries the
// __Host- prefix, as the challenge cookies do (session.pkCookie): a browser
// accepts such a cookie only from this host, Secure, with no Domain and
// Path=/, so a sibling app on the domain can neither plant a list that makes
// a department computer ask for a passkey nor shadow this host's own list. A
// cookie of the bare name, which a sibling could set for the whole domain,
// is never read. Without TLS (development) the prefix would make the browser
// refuse the cookie, so it is left off.
func (s *Server) passkeyHereName() string {
	if s.cfg.CookieInsecure {
		return passkeyHereCookie
	}
	return "__Host-" + passkeyHereCookie
}

// passkeysHere reads passkeyHereCookie: the credential IDs this device has
// added or used, newest first, each a well-formed ID and at most
// passkeyHereMax of them.
func (s *Server) passkeysHere(r *http.Request) []string {
	ck, err := r.Cookie(s.passkeyHereName())
	if err != nil {
		return nil
	}
	var out []string
	for _, v := range strings.Split(ck.Value, ".") {
		if b, ok := unb64(v); ok && len(b) <= 1023 && len(out) < passkeyHereMax {
			out = append(out, b64(b))
		}
	}
	return out
}

func (s *Server) setPasskeysHere(w http.ResponseWriter, ids []string) {
	ck := &http.Cookie{
		Name: s.passkeyHereName(), Path: "/", Secure: !s.cfg.CookieInsecure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	}
	if len(ids) == 0 {
		ck.MaxAge = -1
	} else {
		ck.Value, ck.MaxAge = strings.Join(ids, "."), int(passkeyHereTTL.Seconds())
	}
	http.SetCookie(w, ck)
}

// rememberPasskeyHere records that this device holds credID, newest first.
// Older IDs are dropped past passkeyHereMax or passkeyHereBytes.
func (s *Server) rememberPasskeyHere(w http.ResponseWriter, r *http.Request, credID []byte) {
	first := b64(credID)
	if len(first) > passkeyHereBytes {
		return
	}
	ids, size := []string{first}, len(first)
	for _, c := range s.passkeysHere(r) {
		if c == first || len(ids) == passkeyHereMax || size+1+len(c) > passkeyHereBytes {
			continue
		}
		ids, size = append(ids, c), size+1+len(c)
	}
	s.setPasskeysHere(w, ids)
}

// forgetPasskeyHere drops credID from passkeyHereCookie, if it is there.
func (s *Server) forgetPasskeyHere(w http.ResponseWriter, r *http.Request, credID []byte) {
	gone := b64(credID)
	have := s.passkeysHere(r)
	ids := make([]string, 0, len(have))
	for _, c := range have {
		if c != gone {
			ids = append(ids, c)
		}
	}
	if len(ids) != len(have) {
		s.setPasskeysHere(w, ids)
	}
}

// renderLogin draws the sign-in page. On a computer that holds passkeys of
// the gateway's (passkeyHereCookie), the page may ask for those; on any
// other computer it asks for none, as before computers could hold one.
func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, status int, data pageData) {
	if s.cfg.PasskeysEnabled {
		unknown := ""
		if data.Passkey != nil {
			unknown = data.Passkey.Unknown
		}
		live := s.prunePasskeysHere(w, r, unknown)
		pp := &passkeyPage{Unknown: unknown, Gone: s.takePasskeyForget(w, r)}
		if !isPhone(r) {
			pp.Allow = strings.Join(live, ",")
		}
		data.Passkey = pp
	}
	s.render(w, status, "login", data)
}

// prunePasskeysHere drops from passkeyHereCookie, quietly, the IDs no account
// holds, and returns those kept. The browser is never asked to forget them:
// the database may be the one that is wrong. An ID another person on the
// same computer holds is kept. except is one the caller has already dropped.
// A database error keeps the ID, since the check cannot be made.
func (s *Server) prunePasskeysHere(w http.ResponseWriter, r *http.Request, except string) []string {
	here := s.passkeysHere(r)
	var live []string
	for _, c := range here {
		if c == except {
			continue
		}
		id, _ := unb64(c)
		_, found, err := s.store.PasskeyByCredentialID(r.Context(), id)
		if err != nil {
			log.Printf("passkey here check: %v", err)
		}
		if found || err != nil {
			live = append(live, c)
		}
	}
	if len(live) != len(here) {
		s.setPasskeysHere(w, live)
	}
	return live
}

// passkeyForgetCookie carries, from a removal to the page it leads to, the
// passkey its owner has just removed on this device, for passkey.js to ask
// the browser to forget. It is set only by that removal, lasts a few
// minutes, is read once, and is __Host- under TLS (passkeyHereName), so no
// sibling app can plant one.
const (
	passkeyForgetCookie = "vps_auth_pk_forget"
	passkeyForgetTTL    = 5 * time.Minute
)

func (s *Server) passkeyForgetName() string {
	if s.cfg.CookieInsecure {
		return passkeyForgetCookie
	}
	return "__Host-" + passkeyForgetCookie
}

func (s *Server) setPasskeyForget(w http.ResponseWriter, credID []byte) {
	http.SetCookie(w, &http.Cookie{
		Name: s.passkeyForgetName(), Value: b64(credID), Path: "/", MaxAge: int(passkeyForgetTTL.Seconds()),
		Secure: !s.cfg.CookieInsecure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

// takePasskeyForget reads and clears passkeyForgetCookie. It returns the
// passkey to forget only while the gateway still holds no such passkey.
func (s *Server) takePasskeyForget(w http.ResponseWriter, r *http.Request) string {
	ck, err := r.Cookie(s.passkeyForgetName())
	if err != nil {
		return ""
	}
	http.SetCookie(w, &http.Cookie{
		Name: s.passkeyForgetName(), Path: "/", MaxAge: -1,
		Secure: !s.cfg.CookieInsecure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	id, ok := unb64(ck.Value)
	if !ok || len(id) > 1023 {
		return ""
	}
	if _, found, err := s.store.PasskeyByCredentialID(r.Context(), id); err != nil || found {
		return ""
	}
	return b64(id)
}

// adminPasskeysHere lists, comma-separated, the passkeys of email's that this
// computer holds (passkeyHereCookie) and that stand in for the admin second
// step: the passkeys the admin door may ask a computer for.
func (s *Server) adminPasskeysHere(r *http.Request, email string) string {
	here := map[string]bool{}
	for _, c := range s.passkeysHere(r) {
		here[c] = true
	}
	if len(here) == 0 {
		return ""
	}
	list, err := s.store.ListPasskeys(r.Context(), email)
	if err != nil {
		log.Printf("passkeys for %s: %v", email, err)
		return ""
	}
	var out []string
	for _, p := range list {
		if c := b64(p.CredentialID); p.AdminGrade && here[c] {
			out = append(out, c)
		}
	}
	return strings.Join(out, ",")
}

// renewWithin says how long a removed passkey's sessions can last, for the
// administrator's page: the renewal interval, in words.
func renewWithin(d time.Duration) string {
	switch {
	case d == time.Hour:
		return "an hour"
	case d%time.Hour == 0:
		return fmt.Sprintf("%d hours", int(d/time.Hour))
	case d == time.Minute:
		return "a minute"
	case d%time.Minute == 0:
		return fmt.Sprintf("%d minutes", int(d/time.Minute))
	}
	return d.String()
}
