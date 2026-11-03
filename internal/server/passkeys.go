package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/breakglass"
	"github.com/uppertoe/vps-scaffold-auth/internal/email"
	"github.com/uppertoe/vps-scaffold-auth/internal/passkey"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
	"github.com/uppertoe/vps-scaffold-auth/internal/totp"
)

// Passkeys (PASSKEYS_ENABLED). A person signs in with an email code as
// before; on a phone, the gateway then offers to add a passkey, and the next
// sign-in on that phone needs only the phone's face, fingerprint or PIN
// check. The rules that hold the design together:
//
//   - Passkeys are bound to the sign-in host (the relying-party ID is the host
//     of AUTH_PUBLIC_URL), so no other application on the domain can ask the
//     browser to use them.
//   - Adding a passkey needs a recent sign-in (passkeyFreshness). An
//     administrator also needs the second factor: either the session's sign-in
//     passed it, or they enter an authenticator code with the request. A stolen
//     session cookie therefore cannot be turned into a lasting passkey.
//   - A passkey added by an administrator who passed the second factor is
//     admin grade: signing in with it satisfies the second factor, because a
//     passkey is itself two factors (the phone, and the face, fingerprint or
//     PIN). A passkey added before its owner became an administrator is not,
//     and its sign-in continues to the authenticator step.
//   - A session started with a passkey names it, and renewal ends the session
//     once the passkey is removed: by its owner on the passkeys page, or by an
//     administrator on the access page.
//   - Each challenge is used once (challengeGuard), and expires after
//     passkeyChallengeTTL.
//   - Passkeys need a script, and are the only reason the sign-in pages carry
//     one: /passkey.js, served from this host, and allowed by script-src 'self'
//     on the pages that use it and nowhere else.

const (
	passkeyChallengeTTL = 10 * time.Minute
	passkeyFreshness    = 15 * time.Minute
	// passkeyOfferedCookie once stopped the offer repeating for 90 days. The
	// offer now follows every emailed-code sign-in on a phone, so that a
	// person who chose "Not now" can still add a passkey later; a phone still
	// holding the old cookie has it cleared.
	passkeyOfferedCookie = "vps_auth_pk_offered"
)

//go:embed static/passkey.js
var passkeyScript []byte

// passkeyPage drives the passkey parts of the public pages.
type passkeyPage struct {
	// The ceremony's options, read by passkey.js from data attributes.
	Challenge string
	RPID      string
	RPName    string
	UserID    string
	UserName  string
	Exclude   string // comma-separated credential IDs the phone must not duplicate
	Phone     bool
	// Next is where Continue and Not now lead.
	Next string
	// The passkeys page.
	Rows      []passkeyRow
	CanAdd    bool // this page can add a passkey now
	NeedCode  bool // an administrator must confirm with an authenticator code first
	NeedEmail bool // the sign-in is not recent: sign in again first
	ReauthURL string
	Removed   bool
	// Unknown is a credential ID the gateway does not hold, posted by the
	// phone in a failed sign-in; passkey.js asks the phone to forget it.
	Unknown string
}

type passkeyRow struct {
	ID    int64
	Name  string
	Added string
	Used  string
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64(s string) ([]byte, bool) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	return b, err == nil && len(b) > 0
}

// relyingParty is the sign-in host as WebAuthn sees it.
func (s *Server) relyingParty() passkey.RelyingParty {
	id := ""
	if u, err := url.Parse(s.cfg.PublicURL); err == nil {
		id = strings.ToLower(u.Hostname())
	}
	return passkey.RelyingParty{ID: id, Origin: s.publicOrigin()}
}

// isPhone reports whether the request comes from a phone. Passkeys are
// offered only there: the department's computers cannot hold one, and on a
// computer the browser would offer to use a phone over Bluetooth, which those
// computers do not allow. This decides what is offered, never what is
// permitted.
func isPhone(r *http.Request) bool {
	if r.Header.Get("Sec-CH-UA-Mobile") == "?1" {
		return true
	}
	ua := r.UserAgent()
	return strings.Contains(ua, "iPhone") || (strings.Contains(ua, "Android") && strings.Contains(ua, "Mobile"))
}

// challengeGuard makes each passkey challenge single-use. A challenge lives in
// a signed cookie, so without this a captured sign-in could be replayed until
// the cookie expired.
type challengeGuard struct {
	mu        sync.Mutex
	seen      map[[32]byte]time.Time // challenge hash -> when it may be forgotten
	nextSweep time.Time
	now       func() time.Time
}

// challengeGuardMax bounds the guard. Each entry needs a signed challenge,
// which anyone can mint, and a post charged to the per-network limit; past
// the bound, passkey ceremonies are refused (fail closed) until entries
// expire, and emailed codes keep working.
const challengeGuardMax = 50000

func newChallengeGuard(now func() time.Time) *challengeGuard {
	return &challengeGuard{seen: make(map[[32]byte]time.Time), now: now}
}

// use reports whether the challenge is fresh, and records it.
func (g *challengeGuard) use(ch []byte) bool {
	key := sha256.Sum256(ch)
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	// Sweep at most once a minute, so a flood of entries does not make every
	// ceremony scan the whole map.
	if now.After(g.nextSweep) {
		for k, until := range g.seen {
			if now.After(until) {
				delete(g.seen, k)
			}
		}
		g.nextSweep = now.Add(time.Minute)
	}
	if until, ok := g.seen[key]; ok && !now.After(until) {
		return false
	}
	if len(g.seen) >= challengeGuardMax {
		return false
	}
	g.seen[key] = now.Add(passkeyChallengeTTL)
	return true
}

func newChallenge() ([]byte, error) {
	c := make([]byte, 32)
	_, err := rand.Read(c)
	return c, err
}

// passkeyLoginOptions mints the sign-in challenge for the login page. It is
// called from render, before the page is written. Whether to show the "Sign
// in with a passkey" link is left to passkey.js, which shows it only on a
// phone that can hold a passkey.
func (s *Server) passkeyLoginOptions(w http.ResponseWriter) *passkeyPage {
	ch, err := newChallenge()
	if err != nil {
		return nil
	}
	if err := s.sessions.SetPasskeyChallenge(w, false, session.PasskeyChallenge{Challenge: ch}, passkeyChallengeTTL, s.now()); err != nil {
		return nil
	}
	return &passkeyPage{Challenge: b64(ch), RPID: s.relyingParty().ID}
}

// passkeyRegisterOptions mints the challenge for adding a passkey for email,
// bound to that address.
func (s *Server) passkeyRegisterOptions(w http.ResponseWriter, r *http.Request, email string) (*passkeyPage, error) {
	return s.passkeyRegisterOptionsFor(w, r, email, false)
}

// passkeyRegisterOptionsFor mints the challenge; confirmed marks one minted
// just after an administrator's authenticator code.
func (s *Server) passkeyRegisterOptionsFor(w http.ResponseWriter, r *http.Request, email string, confirmed bool) (*passkeyPage, error) {
	existing, err := s.store.ListPasskeys(r.Context(), email)
	if err != nil {
		return nil, err
	}
	// One account ID per person, reused for every passkey, so the phone treats
	// a second passkey for the same account as a replacement, not a stranger.
	var handle []byte
	exclude := make([]string, 0, len(existing))
	for _, p := range existing {
		if handle == nil {
			handle = p.UserHandle
		}
		exclude = append(exclude, b64(p.CredentialID))
	}
	if handle == nil {
		if handle, err = newChallenge(); err != nil {
			return nil, err
		}
		handle = handle[:16]
	}
	ch, err := newChallenge()
	if err != nil {
		return nil, err
	}
	// The account ID rides in the challenge cookie, so the one stored is the
	// one the server chose, not whatever the browser posts back.
	if err := s.sessions.SetPasskeyChallenge(w, true, session.PasskeyChallenge{Challenge: ch, Email: email, Handle: handle, Confirmed: confirmed}, passkeyChallengeTTL, s.now()); err != nil {
		return nil, err
	}
	return &passkeyPage{
		Challenge: b64(ch),
		RPID:      s.relyingParty().ID,
		RPName:    s.relyingParty().ID,
		UserID:    b64(handle),
		UserName:  email,
		Exclude:   strings.Join(exclude, ","),
		Phone:     isPhone(r),
	}, nil
}

// shouldOfferPasskey decides whether completeLogin shows the offer to add a
// passkey: on a phone, for a staff or administrator account, after every
// sign-in with an emailed code. An emailed code on a phone is the moment a
// passkey would have saved the person a step; "Not now" costs one tap. A
// phone that already holds one of the person's passkeys says so if they tap
// Add (excludeCredentials).
func (s *Server) shouldOfferPasskey(r *http.Request, role string, pk int64) bool {
	if !s.cfg.PasskeysEnabled || pk != 0 || !isPhone(r) {
		return false
	}
	return role == authz.RoleUser || role == authz.RoleAdmin
}

// offerPasskey renders the offer in place of the redirect, once the session
// cookie has been set.
func (s *Server) offerPasskey(w http.ResponseWriter, r *http.Request, email, rd string) bool {
	pp, err := s.passkeyRegisterOptions(w, r, email)
	if err != nil {
		log.Printf("passkey offer for %s: %v", email, err)
		return false
	}
	if _, err := r.Cookie(passkeyOfferedCookie); err == nil {
		http.SetCookie(w, &http.Cookie{
			Name: passkeyOfferedCookie, Value: "", Path: "/", MaxAge: -1,
			Secure: !s.cfg.CookieInsecure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
	}
	pp.Next = s.loginRedirect(rd)
	s.render(w, http.StatusOK, "passkey_offer", pageData{Redirect: rd, Passkey: pp})
	return true
}

// passkeySession reads the session of a person who may manage passkeys: a
// normal sign-in, staff or administrator, with no second factor owed.
func (s *Server) passkeySession(r *http.Request) (*session.Identity, string, bool) {
	id, ok := s.sessions.ReadSession(r, s.now())
	if !ok || id.Kind != "" {
		return nil, "", false
	}
	role := s.policy.Role(id.Email)
	if role != authz.RoleUser && role != authz.RoleAdmin {
		return nil, "", false
	}
	if s.needsAdminStepUp(role == authz.RoleAdmin, id.TOTP) {
		return nil, "", false
	}
	// A session started with a removed passkey manages nothing, whether or not
	// it is due for renewal.
	if !s.passkeyStillValid(r, id) {
		return nil, "", false
	}
	return id, role, true
}

// freshSignIn reports whether the person signed in recently enough to add a
// passkey without proving themselves again.
//
// Only an emailed code counts. A session started with a passkey cannot add
// another: otherwise one stolen passkey could add the thief's own, which
// would survive the owner removing the stolen one.
func (s *Server) freshSignIn(id *session.Identity) bool {
	return id.PK == 0 && id.Auth != 0 && s.now().Unix()-id.Auth <= int64(passkeyFreshness.Seconds())
}

// mayAddPasskeyNow reports whether this session can add a passkey with no
// further step: a recent sign-in and, for an administrator, one that passed
// the second factor.
func (s *Server) mayAddPasskeyNow(id *session.Identity, role string) bool {
	if !s.freshSignIn(id) {
		return false
	}
	return role != authz.RoleAdmin || !s.cfg.TOTPEnabled || id.TOTP
}

func (s *Server) passkeysURL() string { return s.cfg.PublicURL + "/passkeys" }

func (s *Server) passkeysOff(w http.ResponseWriter, r *http.Request) bool {
	if !s.cfg.PasskeysEnabled {
		http.NotFound(w, r)
		return true
	}
	return false
}

// handlePasskeyScript serves the one script the sign-in pages use.
func (s *Server) handlePasskeyScript(w http.ResponseWriter, r *http.Request) {
	if s.passkeysOff(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Write(passkeyScript)
}

// handlePasskeys is the person's own passkeys page.
func (s *Server) handlePasskeys(w http.ResponseWriter, r *http.Request) {
	if s.passkeysOff(w, r) {
		return
	}
	id, role, ok := s.passkeySession(r)
	if !ok {
		http.Redirect(w, r, s.loginURL(s.passkeysURL()), http.StatusFound)
		return
	}
	s.renderPasskeys(w, r, id, role, false)
}

// renderPasskeys draws the passkeys page. confirmed is set straight after an
// administrator's authenticator code, which lets the page add a passkey
// although the sign-in is not recent.
func (s *Server) renderPasskeys(w http.ResponseWriter, r *http.Request, id *session.Identity, role string, confirmed bool) {
	list, err := s.store.ListPasskeys(r.Context(), id.Email)
	if err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong"})
		return
	}
	csrf, err := s.sessions.EnsureCSRF(w, r, csrfTTL, s.now())
	if err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong"})
		return
	}
	pp := &passkeyPage{Phone: isPhone(r)}
	if pp.Phone {
		switch {
		case confirmed || s.mayAddPasskeyNow(id, role):
			reg, err := s.passkeyRegisterOptionsFor(w, r, id.Email, confirmed)
			if err != nil {
				s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong"})
				return
			}
			pp = reg
			pp.CanAdd = true
		case role == authz.RoleAdmin && s.cfg.TOTPEnabled:
			pp.NeedCode = true
		default:
			pp.NeedEmail = true
			pp.ReauthURL = s.loginURL(s.passkeysURL())
		}
	}
	pp.Rows = s.passkeyRows(list)
	pp.Removed = r.URL.Query().Get("removed") == "1"
	pp.Next = s.passkeysURL()
	s.render(w, http.StatusOK, "passkeys", pageData{Passkey: pp, CSRF: csrf, Identity: id.Email})
}

// handlePasskeyConfirm asks an administrator for an authenticator code before
// a passkey is added, when their sign-in is not recent.
func (s *Server) handlePasskeyConfirm(w http.ResponseWriter, r *http.Request) {
	if s.passkeysOff(w, r) {
		return
	}
	_, role, ok := s.passkeySession(r)
	if !ok || role != authz.RoleAdmin || !s.cfg.TOTPEnabled {
		http.Redirect(w, r, s.passkeysURL(), http.StatusFound)
		return
	}
	s.renderPasskeyConfirm(w, r, http.StatusOK, "")
}

// The confirmation page takes the authenticator code on its own, before the
// phone makes a passkey, so a wrong code never leaves the phone holding a
// passkey the gateway has not stored. It runs no ceremony and needs no script.
func (s *Server) renderPasskeyConfirm(w http.ResponseWriter, r *http.Request, status int, msg string) {
	csrf, err := s.sessions.EnsureCSRF(w, r, csrfTTL, s.now())
	if err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong"})
		return
	}
	s.render(w, status, "passkey_confirm", pageData{Passkey: &passkeyPage{Next: s.passkeysURL()}, CSRF: csrf, Error: msg})
}

// handlePasskeyConfirmCode checks an administrator's authenticator code and,
// if it is right, shows the passkeys page ready to add a passkey.
func (s *Server) handlePasskeyConfirmCode(w http.ResponseWriter, r *http.Request) {
	if s.passkeysOff(w, r) || !s.requireSameOrigin(w, r) {
		return
	}
	id, role, ok := s.passkeySession(r)
	if !ok || role != authz.RoleAdmin || !s.cfg.TOTPEnabled {
		http.Redirect(w, r, s.passkeysURL(), http.StatusFound)
		return
	}
	if !s.sessions.VerifyCSRF(r, r.PostFormValue("csrf"), s.now()) {
		s.renderPasskeyConfirm(w, r, http.StatusForbidden, "This page had expired. Please enter the code again.")
		return
	}
	if msg, ok := s.checkAdminCode(r, id.Email, strings.TrimSpace(r.PostFormValue("code")), s.now()); !ok {
		s.renderPasskeyConfirm(w, r, http.StatusUnauthorized, msg)
		return
	}
	s.renderPasskeys(w, r, id, role, true)
}

// handlePasskeyRegister stores a new passkey. Its protection against a forged
// request from another application on the domain is threefold: the
// same-origin check; the challenge, which is random, bound to the signed-in
// address, single-use, and revealed only in this host's own page; and the
// ceremony itself, whose client data must name this host's origin.
func (s *Server) handlePasskeyRegister(w http.ResponseWriter, r *http.Request) {
	if s.passkeysOff(w, r) || !s.requireSameOrigin(w, r) {
		return
	}
	now := s.now()
	rd := authz.SafeRedirect(r.PostFormValue("rd"), s.cfg.Domain, "")
	id, role, ok := s.passkeySession(r)
	if !ok {
		http.Redirect(w, r, s.loginURL(s.passkeysURL()), http.StatusFound)
		return
	}
	ch, ok := s.sessions.ReadPasskeyChallenge(r, true, now)
	if !ok || ch.Email != id.Email || !s.passkeyChallenges.use(ch.Challenge) {
		s.passkeyNotAdded(w, r, id.Email, rd)
		return
	}
	s.sessions.ClearPasskeyChallenge(w, true)

	// A recent sign-in, or for an administrator a challenge minted just after
	// an authenticator code. Confirmed is honoured only for a current
	// administrator: it is inside the signed cookie, so only this server sets
	// it, and only after checkAdminCode.
	if !s.mayAddPasskeyNow(id, role) && !(ch.Confirmed && role == authz.RoleAdmin) {
		http.Redirect(w, r, s.loginURL(s.passkeysURL()), http.StatusFound)
		return
	}

	// Admin grade means the administrator passed the second factor to add
	// this passkey. With TOTP off there was no second factor to pass, so a
	// passkey added then must not stand in for one once TOTP is turned on.
	adminGrade := role == authz.RoleAdmin && s.cfg.TOTPEnabled && (ch.Confirmed || id.TOTP)

	reg, ok := parseRegistration(r)
	if !ok {
		s.passkeyNotAdded(w, r, id.Email, rd)
		return
	}
	cred, err := s.relyingParty().VerifyRegistration(reg, ch.Challenge)
	if err != nil {
		log.Printf("passkey registration for %s refused: %v", id.Email, err)
		s.recordAuth(r, id.Email, store.AuthEventPasskeyAdd, store.AuthOutcomeBadPasskey)
		s.passkeyNotAdded(w, r, id.Email, rd)
		return
	}
	handle := ch.Handle
	if len(handle) == 0 {
		s.passkeyNotAdded(w, r, id.Email, rd)
		return
	}
	if _, err := s.store.CreatePasskey(r.Context(), store.Passkey{
		Email:        id.Email,
		CredentialID: cred.ID,
		PublicKey:    cred.PublicKey,
		UserHandle:   handle,
		SignCount:    cred.SignCount,
		Label:        passkeyLabel(cred.AAGUID, r),
		AdminGrade:   adminGrade,
		CreatedAt:    now,
	}); err != nil {
		log.Printf("store passkey for %s: %v", id.Email, err)
		s.passkeyNotAdded(w, r, id.Email, rd)
		return
	}
	s.recordAuth(r, id.Email, store.AuthEventPasskeyAdd, store.AuthOutcomeOK)
	s.notifyPasskeyAdded(r, id.Email, now)
	s.render(w, http.StatusOK, "passkey_added", pageData{Identity: id.Email, Redirect: s.loginRedirect(rd), Passkey: &passkeyPage{Next: s.passkeysURL()}})
}

func (s *Server) passkeyNotAdded(w http.ResponseWriter, r *http.Request, email, rd string) {
	s.render(w, http.StatusBadRequest, "message", pageData{
		Title:    "Your passkey has not been added",
		Message:  "Please try again from Your passkeys. You can still sign in with an email code.",
		Redirect: s.passkeysURL(),
	})
}

// checkAdminCode verifies an administrator's authenticator code with the same
// limits as the sign-in step (handleTOTP): the per-IP limiter, the per-account
// reservation, and the replay guard.
func (s *Server) checkAdminCode(r *http.Request, email, code string, now time.Time) (string, bool) {
	ip := clientIP(r)
	if !s.wrongCodes.Allow(ip) {
		return "Too many attempts. Please wait and try again.", false
	}
	n, err := s.store.ReserveTOTPAttempt(r.Context(), email, totpLockoutWindow, now)
	if err != nil {
		log.Printf("reserve totp attempt for %s: %v", email, err)
		return "The code could not be checked just now. Please try again in a moment.", false
	}
	if n > s.cfg.OTPMaxAttempts {
		s.recordAuth(r, email, store.AuthEventTOTP, store.AuthOutcomeLockedOut)
		return "Too many incorrect codes. This account is temporarily locked; try again shortly.", false
	}
	secret, ok, err := s.getTOTPSecret(r.Context(), email)
	if err != nil || !ok || !totp.Validate(code, secret) {
		s.recordAuth(r, email, store.AuthEventTOTP, store.AuthOutcomeWrongCode)
		return "Incorrect code. Please try again.", false
	}
	if !s.totpReplay.use(email, code) {
		s.recordAuth(r, email, store.AuthEventTOTP, store.AuthOutcomeReplayed)
		return "That code has already been used. Wait for your authenticator to show a new one.", false
	}
	s.wrongCodes.Refund(ip)
	if err := s.store.ClearTOTPFailures(r.Context(), email); err != nil {
		log.Printf("clear totp failures for %s: %v", email, err)
	}
	s.recordAuth(r, email, store.AuthEventTOTP, store.AuthOutcomeOK)
	return "", true
}

func parseRegistration(r *http.Request) (passkey.Registration, bool) {
	id, ok1 := unb64(r.PostFormValue("id"))
	cd, ok2 := unb64(r.PostFormValue("clientDataJSON"))
	ad, ok3 := unb64(r.PostFormValue("authenticatorData"))
	pk, ok4 := unb64(r.PostFormValue("publicKey"))
	alg, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("publicKeyAlg")))
	if !ok1 || !ok2 || !ok3 || !ok4 || err != nil {
		return passkey.Registration{}, false
	}
	return passkey.Registration{CredentialID: id, ClientDataJSON: cd, AuthenticatorData: ad, PublicKey: pk, PublicKeyAlg: alg}, true
}

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
		s.render(w, http.StatusUnauthorized, "login", pageData{Error: msg, Redirect: rd, Remember: remember, Passkey: &passkeyPage{Unknown: unknown}})
	}
	// Charged up front and refunded on success, as for email codes.
	ip := clientIP(r)
	if !s.wrongCodes.Allow(ip) {
		failed("Too many attempts. Please wait and try again.")
		return
	}
	ch, ok := s.sessions.ReadPasskeyChallenge(r, false, now)
	if !ok || !s.passkeyChallenges.use(ch.Challenge) {
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
	// The role comes from the current policy, as for an email code. A passkey
	// is never a way in for an address the allow-list no longer permits, and
	// never makes a guest.
	role := s.policy.LoginRole(pk.Email, s.isOpenHost(rd))
	if role != authz.RoleUser && role != authz.RoleAdmin {
		s.recordAuth(r, pk.Email, store.AuthEventPasskey, store.AuthOutcomeDenied)
		s.render(w, http.StatusForbidden, "login", pageData{Error: "This account is not permitted.", Redirect: rd})
		return
	}
	s.wrongCodes.Refund(ip)
	s.recordAuth(r, pk.Email, store.AuthEventPasskey, store.AuthOutcomeOK)
	if role == authz.RoleAdmin && s.cfg.TOTPEnabled && !pk.AdminGrade {
		s.startTOTP(w, r, pk.Email, role, rd, remember, pk.ID, now)
		return
	}
	s.completeLogin(w, r, pk.Email, role, rd, remember, role == authz.RoleAdmin && s.cfg.TOTPEnabled && pk.AdminGrade, pk.ID, now)
}

// handlePasskeyRemove removes one of the signed-in person's passkeys.
func (s *Server) handlePasskeyRemove(w http.ResponseWriter, r *http.Request) {
	if s.passkeysOff(w, r) || !s.requireSameOrigin(w, r) {
		return
	}
	id, _, ok := s.passkeySession(r)
	if !ok {
		http.Redirect(w, r, s.loginURL(s.passkeysURL()), http.StatusFound)
		return
	}
	if !s.sessions.VerifyCSRF(r, r.PostFormValue("csrf"), s.now()) {
		s.render(w, http.StatusForbidden, "message", pageData{
			Title: "Please try again", Message: "This page had expired, so the passkey has not been removed. Open Your passkeys and try again.",
		})
		return
	}
	pid, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	removed, err := s.store.DeletePasskey(r.Context(), id.Email, pid)
	if err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong"})
		return
	}
	if removed {
		s.recordAuth(r, id.Email, store.AuthEventPasskeyRemove, store.AuthOutcomeOK)
	}
	http.Redirect(w, r, s.passkeysURL()+"?removed=1", http.StatusFound)
}

// handleAdminRemovePasskeys removes every passkey of one person.
func (s *Server) handleAdminRemovePasskeys(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	emailAddr := normalizeEmail(r.PostFormValue("email"))
	n, err := s.store.DeletePasskeys(r.Context(), emailAddr)
	if err != nil {
		s.adminError(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionPasskeysRemove, emailAddr, strconv.Itoa(n))
	http.Redirect(w, r, "/admin/access?email="+url.QueryEscape(emailAddr)+"&passkeys_removed=1", http.StatusFound)
}

// passkeyStillValid is the renewal check for a session started with a
// passkey: the passkey must still exist and still belong to the session's
// address. A database error ends the session too, since the check cannot be
// made; the person signs in again.
func (s *Server) passkeyStillValid(r *http.Request, id *session.Identity) bool {
	if id.PK == 0 {
		return true
	}
	p, ok, err := s.store.GetPasskey(r.Context(), id.PK)
	if err != nil {
		log.Printf("renewal passkey check for %s: %v", id.Email, err)
		return false
	}
	return ok && p.Email == id.Email
}

func (s *Server) passkeyRows(list []store.Passkey) []passkeyRow {
	today := s.now().In(s.loc).Format("2006-01-02")
	out := make([]passkeyRow, 0, len(list))
	for _, p := range list {
		row := passkeyRow{ID: p.ID, Name: p.Label, Added: p.CreatedAt.In(s.loc).Format("2 January 2006")}
		switch {
		case p.LastUsedAt.IsZero():
			row.Used = "Not used yet"
		case p.LastUsedAt.In(s.loc).Format("2006-01-02") == today:
			row.Used = "Last used today"
		default:
			row.Used = "Last used " + p.LastUsedAt.In(s.loc).Format("2 January 2006")
		}
		if row.Name == "" {
			row.Name = "Passkey"
		}
		out = append(out, row)
	}
	return out
}

// passkeyProviders names the common passkey providers by the identifier
// (AAGUID) they report. A name is only a label for the person's own list; an
// unknown or withheld identifier falls back to the kind of phone.
var passkeyProviders = map[string]string{
	"ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "Google Password Manager",
	"fbfc3007-154e-4ecc-8c0b-6e020557d7bd": "iCloud Keychain",
	"dd4ec289-e01d-41c9-bb89-70fa845d4bf2": "iCloud Keychain",
	"bada5566-a7aa-401f-bd96-45619a55120d": "1Password",
	"d548826e-79b4-db40-a3d8-11116f7e8349": "Bitwarden",
	"53414d53-554e-4700-0000-000000000000": "Samsung Pass",
}

func passkeyLabel(aaguid [16]byte, r *http.Request) string {
	if name, ok := passkeyProviders[passkey.AAGUIDString(aaguid)]; ok {
		return name
	}
	ua := r.UserAgent()
	switch {
	case strings.Contains(ua, "iPhone"):
		return "Passkey on an iPhone"
	case strings.Contains(ua, "Android"):
		return "Passkey on an Android phone"
	}
	return "Passkey"
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

// notifyPasskeyAdded emails the account holder whenever a passkey is added.
// A passkey needs no proof of the device that made it, so a session cookie
// stolen soon after a sign-in could register a key of the thief's; this email
// is how the person learns of it. It is sent on a detached goroutine, like the
// sign-in code, so mail delivery never delays the page.
func (s *Server) notifyPasskeyAdded(r *http.Request, to string, now time.Time) {
	msg := s.passkeyAddedEmail(to, passkeyDevice(r.UserAgent()), now)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := s.sender.Send(ctx, msg); err != nil {
			log.Printf("send passkey notice to %s: %v", to, err)
		}
	}()
}

// passkeyAddedData is the view model for the passkey notice. The template
// renders with text/template, which does not escape, so every string is
// HTML-escaped by renderPasskeyAddedHTML; the colours are validated "#rrggbb".
type passkeyAddedData struct {
	BrandName, Added, OK, NotYou, Link string
	HeaderColor, HeaderText            string
	AccentColor, AccentText            string
}

// renderPasskeyAddedHTML lays the notice out like the sign-in code email, in
// the admin branding's colours, falling back to plain paragraphs if the
// template ever fails so that the notice is still sent.
func (s *Server) renderPasskeyAddedHTML(added, ok, notYou, link string, now time.Time) string {
	header := breakglass.DefaultPalette.Header
	accent := breakglass.DefaultPalette.Accent
	if b, err := s.publicBrandingAt(context.Background(), now); err == nil {
		header = hexOrDefault(b.headerColor, header)
		accent = hexOrDefault(b.accentColor, accent)
	}
	esc := html.EscapeString
	var buf bytes.Buffer
	err := s.emailTmpl.ExecuteTemplate(&buf, "email_passkey_added", passkeyAddedData{
		BrandName: esc(s.cfg.BrandName), Added: esc(added), OK: esc(ok), NotYou: esc(notYou), Link: esc(link),
		HeaderColor: header, HeaderText: emailTextOn(header),
		AccentColor: accent, AccentText: emailTextOn(accent),
	})
	if err == nil {
		return buf.String()
	}
	log.Printf("render passkey notice: %v", err)
	return `<p>` + esc(added) + `</p><p>` + esc(ok) + `</p><p>` + esc(notYou) + `</p><p><a href="` + esc(link) + `">Your passkeys</a></p>`
}

// passkeyDevice names the kind of phone for the notice, or "" if unknown.
func passkeyDevice(ua string) string {
	switch {
	case strings.Contains(ua, "iPhone"):
		return "an iPhone"
	case strings.Contains(ua, "Android"):
		return "an Android phone"
	}
	return ""
}

func (s *Server) passkeyAddedEmail(to, device string, now time.Time) email.Message {
	when := now.In(s.loc)
	stamp := when.Format("2 January 2006") + " at " + strings.ToLower(when.Format("3:04 pm"))
	first := fmt.Sprintf("A passkey was added to your account at %s on %s", s.relyingParty().ID, stamp)
	if device != "" {
		first += ", on " + device
	}
	first += "."
	const ok = "If you added this passkey, there is nothing more to do."
	const notYou = "If you did not add it, open Your passkeys, remove it, then contact an administrator for assistance."
	link := s.passkeysURL()
	text := first + "\n\n" + ok + "\n\n" + notYou + "\n\nYour passkeys: " + link + "\n"
	htmlBody := s.renderPasskeyAddedHTML(first, ok, notYou, link, now)
	return email.Message{To: to, Subject: "A passkey has been added to your account", Text: text, HTML: htmlBody}
}
