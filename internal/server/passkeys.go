package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"errors"
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
// check. On a computer, a person may add a passkey held by the computer
// itself (Touch ID, Windows Hello), but only when they ask for one on the
// passkeys page. The rules that hold the design together:
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
//
// On a computer, the further rules:
//
//   - The department's computers cannot hold a passkey, and their browsers
//     would offer to use a phone over Bluetooth or a QR code instead, which
//     those computers block. A computer is therefore never offered a passkey
//     after an email code, and the passkeys page adds one only once the
//     person has chosen to, after a warning to do so only on a computer
//     nobody else signs in to. The one offer a computer is made unasked is
//     at the admin door, straight after a right authenticator code, to an
//     administrator whose computer holds no admin passkey of theirs and is
//     not on a listed network (shouldOfferAdminPasskey); it carries the same
//     warning, the same ceremony, and the same refusals.
//   - A computer's passkey is held by the computer. The ceremony asks for a
//     platform authenticator, with the "client-device" hint, and a
//     registration whose browser reports the passkey anywhere else (a phone
//     over "hybrid", a security key) is refused (HeldByThisDevice). The report
//     is not signed, so this stops a mistaken choice, not a hostile script;
//     who may add a passkey is decided, as on a phone, by the session.
//   - The gateway never asks a computer for a phone's passkey. A computer
//     that holds one of the gateway's passkeys is known by passkeyHereCookie,
//     set when the passkey is added or used there; only such a computer is
//     asked for a passkey at sign-in, only for those passkeys, as held by the
//     computer ("internal"), and only when the person presses the button. A
//     computer gets no quiet offer in the email field (conditional
//     mediation), whose list would include any synced passkey and, in some
//     browsers, "use another device". Every other computer's sign-in page is
//     as it was. A synced
//     passkey that happens to be on the computer may work; nothing fetches
//     one from a phone.
//   - The browser is asked to forget a passkey (signalUnknownCredential,
//     where it has it) only after an event on this device that shows the
//     passkey is of no use here: a sign-in with it refused as unknown, or
//     its owner removing it on this device (passkeyForgetCookie). A page
//     never asks it to forget a passkey merely because the database lacks
//     it, since a database restored from an old backup, or an empty one,
//     would then delete good passkeys from every browser that visited. Such
//     an ID is only dropped from the cookie, quietly (prunePasskeysHere). A
//     passkey removed on another device or by an administrator is therefore
//     forgotten at its next refused sign-in on this computer.
//   - The cookie only steers what the browser is asked for and which row the
//     passkeys page calls "This computer". Everything it names is checked as
//     any other sign-in is, so a planted or stale cookie gains nothing.
//   - No computer on a network in NETWORK_RANGES (the hospital's) may add a
//     passkey: such a computer is shared, whatever the person says of it. The
//     client address is the one the gateway already trusts (clientIP, the
//     last X-Forwarded-For entry, which Caddy writes), and it is checked both
//     when the challenge is minted and when the registration is posted, so a
//     challenge minted off the network cannot be completed on it, nor the
//     reverse (passkeyBlockedNetwork). Signing in there with a passkey the
//     computer already holds is unchanged, and so is every phone.
//   - The network rule, like the computer check, rests on the user agent
//     (isPhone) and the browser's unsigned report. It stops an honest choice
//     on a shared computer, not a determined person: a computer that claims
//     to be a phone is treated as one. It also covers only the address
//     families listed, so where the hospital reaches the gateway over IPv6
//     as well, NETWORK_RANGES must list its IPv6 ranges beside the IPv4.
//   - The other rules hold on a computer as on a phone: the same host, the
//     same recent sign-in and second factor to add one, the same admin grade,
//     the same sessions that name their passkey, the same single-use
//     challenges.

const (
	passkeyChallengeTTL = 10 * time.Minute
	passkeyFreshness    = 15 * time.Minute
	// passkeyOfferedCookie once stopped the offer repeating for 90 days. The
	// offer now follows every emailed-code sign-in on a phone, so that a
	// person who chose "Not now" can still add a passkey later; a phone still
	// holding the old cookie has it cleared.
	passkeyOfferedCookie = "vps_auth_pk_offered"
	// passkeyHereCookie names the passkeys this device holds, as the
	// credential IDs it added or used here, newest first. Under TLS it carries
	// the __Host- prefix (passkeyHereName).
	passkeyHereCookie = "vps_auth_pk_here"
	passkeyHereTTL    = 400 * 24 * time.Hour
	passkeyHereMax    = 8    // credential IDs kept
	passkeyHereBytes  = 2400 // and their total length, within a cookie's 4 KB
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
	// Computer marks a page drawn for a computer, and AddComputer the
	// passkeys page once the person has chosen to add a passkey there.
	Computer    bool
	AddComputer bool
	// HeldHere marks a computer's passkeys page that already lists a passkey
	// the computer holds, which offers no other.
	HeldHere bool
	// OnNetwork is the sentence a computer on a listed network is shown in
	// place of the offer (passkeyBlockedNetwork).
	OnNetwork string
	// Allow lists, comma-separated, the passkeys a computer's sign-in may ask
	// for: those passkeyHereCookie names. Empty, a computer is asked for none.
	Allow string
	// Text is the wording for computers (passkey_computer_text.go).
	Text *passkeyText
	// Next is where Continue and Not now lead.
	Next string
	// The passkeys page.
	Rows      []passkeyRow
	CanAdd    bool // this page can add a passkey now
	NeedCode  bool // an administrator must confirm with an authenticator code first
	NeedEmail bool // the sign-in is not recent: sign in again first
	ReauthURL string
	Removed   bool
	// AdminDoor marks the offer made at the admin door, straight after an
	// authenticator code, which adds a passkey that can open the admin pages.
	AdminDoor bool
	// Unknown is a credential ID the gateway does not hold, posted by the
	// phone in a failed sign-in; passkey.js asks the phone to forget it.
	Unknown string
	// Gone is a passkey its owner has just removed on this device
	// (passkeyForgetCookie); passkey.js asks the browser to forget it.
	Gone string
}

type passkeyRow struct {
	ID    int64
	Name  string
	Added string
	Used  string
	// Kind is "This computer", "A phone" and so on, for the person's own
	// page; Device is "Computer" or "Phone", for the administrator's.
	Kind     string
	Device   string
	Computer bool
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
// offered unasked only there: the department's computers cannot hold one, and
// on a computer the browser would offer to use a phone over Bluetooth, which
// those computers do not allow. A computer adds one only when the person asks
// (renderPasskeys). This decides what is offered, never what is permitted.
func isPhone(r *http.Request) bool {
	return r.Header.Get("Sec-CH-UA-Mobile") == "?1" || isPhoneUA(r.UserAgent())
}

func isPhoneUA(ua string) bool {
	return strings.Contains(ua, "iPhone") || (strings.Contains(ua, "Android") && strings.Contains(ua, "Mobile"))
}

// challengeGuard makes each passkey challenge single-use. A challenge lives in
// a signed cookie, so without this a captured sign-in could be replayed until
// the cookie expired. Used challenges are kept in SQLite until they expire, so
// a restart does not forget them.
type challengeGuard struct {
	store store.Store
	now   func() time.Time

	mu        sync.Mutex
	nextSweep time.Time
	count     int // entries at the last sweep, plus those added since
}

// challengeGuardMax bounds the guard. Each entry needs a signed challenge,
// which anyone can mint, and a post charged to the per-network limit; past
// the bound, passkey ceremonies are refused (fail closed) until entries
// expire, and emailed codes keep working.
const challengeGuardMax = 50000

func newChallengeGuard(st store.Store, now func() time.Time) *challengeGuard {
	return &challengeGuard{store: st, now: now}
}

// use reports whether the challenge is fresh, and records it. A database
// error refuses the ceremony: the gateway cannot tell whether the challenge
// was used.
func (g *challengeGuard) use(ctx context.Context, ch []byte) bool {
	key := sha256.Sum256(ch)
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	// Sweep at most once a minute, so a flood of entries does not make every
	// ceremony count the whole table.
	if now.After(g.nextSweep) {
		n, err := g.store.PruneChallenges(ctx, now)
		if err != nil {
			log.Printf("passkey challenges: %v", err)
			return false
		}
		g.count, g.nextSweep = n, now.Add(time.Minute)
	}
	if g.count >= challengeGuardMax {
		return false
	}
	fresh, err := g.store.UseChallenge(ctx, key[:], now.Add(passkeyChallengeTTL), now)
	if err != nil {
		log.Printf("passkey challenges: %v", err)
		return false
	}
	if fresh {
		g.count++
	}
	return fresh
}

func newChallenge() ([]byte, error) {
	c := make([]byte, 32)
	_, err := rand.Read(c)
	return c, err
}

// passkeyLoginOptions mints the sign-in challenge for the login page. It is
// called from render, before the page is written. Whether to show the "Sign
// in with a passkey" link is left to passkey.js, which shows it on a phone
// that can hold a passkey, and on a computer only for the passkeys the page
// lists as held there (Allow).
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
	if !isPhone(r) {
		if _, blocked := s.passkeyBlockedNetwork(r); blocked {
			return nil, errPasskeyOnNetwork
		}
	}
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
	computer := !isPhone(r)
	if err := s.sessions.SetPasskeyChallenge(w, true, session.PasskeyChallenge{Challenge: ch, Email: email, Handle: handle, Confirmed: confirmed, Computer: computer}, passkeyChallengeTTL, s.now()); err != nil {
		return nil, err
	}
	return &passkeyPage{
		Challenge: b64(ch),
		RPID:      s.relyingParty().ID,
		RPName:    s.relyingParty().ID,
		UserID:    b64(handle),
		UserName:  email,
		Exclude:   strings.Join(exclude, ","),
		Phone:     !computer,
		Computer:  computer,
		Text:      pkText,
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
	return role == authz.RoleUser || role == authz.RoleAdmin || role == authz.RoleMember
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

// offerAdminPasskey offers a passkey straight after an authenticator code at
// the admin door, on a phone or a computer (shouldOfferAdminPasskey). The
// challenge is marked confirmed, so the passkey added is one that stands in
// for the second step; on a computer it is also marked as a computer's, so
// the registration is refused on a listed network or when the passkey is not
// held by the computer.
func (s *Server) offerAdminPasskey(w http.ResponseWriter, r *http.Request, email, next string) bool {
	pp, err := s.passkeyRegisterOptionsFor(w, r, email, true)
	if err != nil {
		log.Printf("admin passkey offer for %s: %v", email, err)
		return false
	}
	pp.Next = next
	pp.AdminDoor = true
	s.render(w, http.StatusOK, "passkey_offer", pageData{Redirect: next, Passkey: pp})
	return true
}

// passkeySession reads the session of a person who may manage passkeys: a
// normal sign-in, staff or administrator. An administrator need not hold the
// admin tier to see or remove their passkeys; adding one asks for the
// authenticator code first (mayAddPasskeyNow).
func (s *Server) passkeySession(r *http.Request) (*session.Identity, string, bool) {
	id, ok := s.readSession(r, s.now())
	if !ok || !personSession(id) {
		return nil, "", false
	}
	role := s.currentRole(r.Context(), id.Email)
	if role != authz.RoleUser && role != authz.RoleAdmin && role != authz.RoleMember {
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
	return role != authz.RoleAdmin || !s.cfg.TOTPEnabled || s.adminStepFresh(id)
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
	phone := isPhone(r)
	// On a computer, a passkey is added only once the person has chosen to;
	// confirmed follows that choice, through the code confirmation.
	addComputer := !phone && (confirmed || r.URL.Query().Get("add") == "computer")
	pp := &passkeyPage{Phone: phone, Computer: !phone, Text: pkText}
	if !phone {
		if msg, blocked := s.passkeyBlockedNetwork(r); blocked {
			pp.OnNetwork, addComputer = msg, false
		}
	}
	if phone || addComputer {
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
			back := s.passkeysURL()
			if addComputer {
				back += "?add=computer"
			}
			pp.ReauthURL = s.loginURL(back)
		}
	}
	pp.AddComputer = addComputer
	pp.Rows = s.ownPasskeyRows(r, id, list)
	for _, row := range pp.Rows {
		pp.HeldHere = pp.HeldHere || row.Kind == msgPkThisComputer
	}
	pp.Removed = r.URL.Query().Get("removed") == "1"
	pp.Next = s.passkeysURL()
	pp.RPID = s.relyingParty().ID
	s.prunePasskeysHere(w, r, "")
	pp.Gone = s.takePasskeyForget(w, r)
	s.render(w, http.StatusOK, "passkeys", pageData{Passkey: pp, CSRF: csrf, Identity: id.Email})
}

// handlePasskeyConfirm asks an administrator for an authenticator code before
// a passkey is added, when their sign-in is not recent.
func (s *Server) handlePasskeyConfirm(w http.ResponseWriter, r *http.Request) {
	if s.passkeysOff(w, r) {
		return
	}
	_, role, ok := s.passkeySession(r)
	if !ok || role != authz.RoleAdmin || !s.cfg.TOTPEnabled || s.computerOnNetwork(r) {
		http.Redirect(w, r, s.passkeysURL(), http.StatusFound)
		return
	}
	s.renderPasskeyConfirm(w, r, http.StatusOK, "")
}

// computerOnNetwork reports whether a computer on a listed network makes the
// request. The code confirmation sends it to the passkeys page, which says
// why it cannot add a passkey, before a code is asked for or spent.
func (s *Server) computerOnNetwork(r *http.Request) bool {
	if isPhone(r) {
		return false
	}
	_, blocked := s.passkeyBlockedNetwork(r)
	return blocked
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
	if !ok || role != authz.RoleAdmin || !s.cfg.TOTPEnabled || s.computerOnNetwork(r) {
		http.Redirect(w, r, s.passkeysURL(), http.StatusFound)
		return
	}
	if !s.sessions.VerifyCSRF(r, r.PostFormValue("csrf"), s.now()) {
		s.renderPasskeyConfirm(w, r, http.StatusForbidden, "This page had expired. Please enter the code again.")
		return
	}
	if msg, status, ok := s.checkAdminCode(r, id.Email, strings.TrimSpace(r.PostFormValue("code")), s.now()); !ok {
		s.renderPasskeyConfirm(w, r, status, msg)
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
	if !ok || ch.Email != id.Email || !s.passkeyChallenges.use(r.Context(), ch.Challenge) {
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
	// A computer's challenge is refused on a listed network, wherever it was
	// minted.
	if ch.Computer {
		if msg, blocked := s.passkeyBlockedNetwork(r); blocked {
			log.Printf("passkey registration for %s refused: a computer on a listed network", id.Email)
			s.recordAuth(r, id.Email, store.AuthEventPasskeyAdd, store.AuthOutcomeDenied)
			s.render(w, http.StatusForbidden, "message", pageData{
				Title:    "Your passkey has not been added",
				Message:  msg,
				Redirect: s.passkeysURL(),
			})
			return
		}
	}

	// Admin grade means the administrator passed the second factor to add
	// this passkey. With TOTP off there was no second factor to pass, so a
	// passkey added then must not stand in for one once TOTP is turned on.
	adminGrade := role == authz.RoleAdmin && s.cfg.TOTPEnabled && (ch.Confirmed || s.adminStepFresh(id))

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
	// A computer's passkey must be held by the computer, not saved to a phone
	// over Bluetooth or a QR code. A phone's registration is taken as it
	// comes, as it always was.
	device := store.DevicePhone
	if ch.Computer {
		device = store.DeviceComputer
		if !reg.HeldByThisDevice() {
			log.Printf("passkey registration for %s refused: held elsewhere (%q, %v)", id.Email, reg.Attachment, reg.Transports)
			s.recordAuth(r, id.Email, store.AuthEventPasskeyAdd, store.AuthOutcomeBadPasskey)
			s.render(w, http.StatusBadRequest, "message", pageData{
				Title:    "Your passkey has not been added",
				Message:  msgPkComputerRefused,
				Redirect: s.passkeysURL(),
			})
			return
		}
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
		Device:       device,
		Attachment:   reg.Attachment,
		Transports:   strings.Join(reg.Transports, ","),
		CreatedAt:    now,
	}); err != nil {
		log.Printf("store passkey for %s: %v", id.Email, err)
		s.passkeyNotAdded(w, r, id.Email, rd)
		return
	}
	s.rememberPasskeyHere(w, r, cred.ID)
	s.recordAuth(r, id.Email, store.AuthEventPasskeyAdd, store.AuthOutcomeOK)
	s.notifyPasskeyAdded(r, id.Email, now)
	s.render(w, http.StatusOK, "passkey_added", pageData{Identity: id.Email, Redirect: s.loginRedirect(rd), Passkey: &passkeyPage{Next: s.passkeysURL(), Computer: ch.Computer, Text: pkText}})
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
func (s *Server) checkAdminCode(r *http.Request, email, code string, now time.Time) (string, int, bool) {
	ip := clientIP(r)
	if !s.wrongCodes.Allow(ip) {
		return "Too many attempts. Please wait and try again.", http.StatusTooManyRequests, false
	}
	n, err := s.store.ReserveTOTPAttempt(r.Context(), email, totpLockoutWindow, now)
	if err != nil {
		log.Printf("reserve totp attempt for %s: %v", email, err)
		return "The code could not be checked just now. Please try again in a moment.", http.StatusServiceUnavailable, false
	}
	if n > s.cfg.OTPMaxAttempts {
		s.recordAuth(r, email, store.AuthEventTOTP, store.AuthOutcomeLockedOut)
		return "Too many incorrect codes. This account is temporarily locked; try again shortly.", http.StatusTooManyRequests, false
	}
	secret, ok, err := s.getTOTPSecret(r.Context(), email)
	if err != nil || !ok || !totp.Validate(code, secret) {
		s.recordAuth(r, email, store.AuthEventTOTP, store.AuthOutcomeWrongCode)
		return "Incorrect code. Please try again.", http.StatusUnauthorized, false
	}
	if !s.totpReplay.use(email, code) {
		s.recordAuth(r, email, store.AuthEventTOTP, store.AuthOutcomeReplayed)
		return "That code has already been used. Wait for your authenticator to show a new one.", http.StatusUnauthorized, false
	}
	s.wrongCodes.Refund(ip)
	if err := s.store.ClearTOTPFailures(r.Context(), email); err != nil {
		log.Printf("clear totp failures for %s: %v", email, err)
	}
	s.recordAuth(r, email, store.AuthEventTOTP, store.AuthOutcomeOK)
	return "", http.StatusOK, true
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
	return passkey.Registration{
		CredentialID: id, ClientDataJSON: cd, AuthenticatorData: ad, PublicKey: pk, PublicKeyAlg: alg,
		Attachment: parseAttachment(r.PostFormValue("attachment")),
		Transports: parseTransports(r.PostFormValue("transports")),
	}, true
}

// parseAttachment keeps an attachment WebAuthn defines, and drops anything
// else as unreported.
func parseAttachment(v string) string {
	switch v = strings.TrimSpace(v); v {
	case "platform", "cross-platform":
		return v
	}
	return ""
}

// parseTransports keeps the transports WebAuthn defines, once each, in the
// order reported.
func parseTransports(v string) []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range strings.Split(v, ",") {
		t = strings.TrimSpace(t)
		switch t {
		case "internal", "hybrid", "usb", "nfc", "ble", "smart-card":
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	return out
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
	// The role comes from the current policy, as for an email code. A passkey
	// is never a way in for an address the allow-list no longer permits, and
	// never makes a guest.
	if s.rolesUnavailable(r.Context()) {
		s.renderUnavailable(w, rd)
		return
	}
	role := s.loginRole(r.Context(), pk.Email, s.isOpenHost(rd))
	if role != authz.RoleUser && role != authz.RoleAdmin && role != authz.RoleMember {
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
	held, found, err := s.store.GetPasskey(r.Context(), pid)
	if err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong"})
		return
	}
	removed := false
	if found && held.Email == id.Email {
		// The sessions the passkey started end first; the passkey is removed
		// only once they have, so a failure leaves it listed to try again.
		err = s.revokeAnd(r.Context(), []string{passkeyKey(pid)}, func(x *store.Session) bool { return x.Passkey == pid }, s.now(), func() error {
			var err error
			removed, err = s.store.DeletePasskey(r.Context(), id.Email, pid)
			return err
		})
		if err != nil {
			log.Printf("remove passkey %d: %v", pid, err)
			s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Please try again", Message: msgPkRemoveFailed})
			return
		}
	}
	if removed {
		// The person removed it on this device: the page this redirects to
		// asks the browser to forget it.
		s.forgetPasskeyHere(w, r, held.CredentialID)
		s.setPasskeyForget(w, held.CredentialID)
		s.recordAuth(r, id.Email, store.AuthEventPasskeyRemove, store.AuthOutcomeOK)
		s.notifyPasskeyRemoved(r, id.Email, s.now())
	}
	http.Redirect(w, r, s.passkeysURL()+"?removed=1", http.StatusFound)
}

// handleAdminRemovePasskeys removes every passkey of one person.
func (s *Server) handleAdminRemovePasskeys(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	emailAddr := normalizeEmail(r.PostFormValue("email"))
	keys, err := s.store.ListPasskeys(r.Context(), emailAddr)
	if err != nil {
		s.adminError(w, r)
		return
	}
	// The sessions the passkeys started end first, those of a passkey added
	// since the list included; the passkeys are removed only once they have.
	cut := make([]string, 0, len(keys))
	for _, k := range keys {
		cut = append(cut, passkeyKey(k.ID))
	}
	var n int
	if err := s.revokeAnd(r.Context(), cut, func(x *store.Session) bool { return x.Email == emailAddr && x.Passkey != 0 }, s.now(), func() error {
		var err error
		n, err = s.store.DeletePasskeys(r.Context(), emailAddr)
		return err
	}); err != nil {
		s.adminError(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionPasskeysRemove, emailAddr, strconv.Itoa(n))
	http.Redirect(w, r, "/admin/access?email="+url.QueryEscape(emailAddr)+"&passkeys_removed=1", http.StatusFound)
}

// passkeyRows lists passkeys for the administrator's page, and is the base of
// the person's own (ownPasskeyRows).
func (s *Server) passkeyRows(list []store.Passkey) []passkeyRow {
	today := s.now().In(s.loc).Format("2006-01-02")
	out := make([]passkeyRow, 0, len(list))
	for _, p := range list {
		row := passkeyRow{ID: p.ID, Name: p.Label, Added: p.CreatedAt.In(s.loc).Format("2 January 2006")}
		row.Computer = p.Device == store.DeviceComputer
		if row.Computer {
			row.Device, row.Kind = msgPkDeviceComputer, msgPkAComputer
		} else {
			row.Device, row.Kind = msgPkDevicePhone, msgPkAPhone
		}
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

// ownPasskeyRows lists a person's passkeys for their own page, naming the
// one this device holds, as far as the gateway can tell: the passkey that
// started this session, or one that passkeyHereCookie names.
func (s *Server) ownPasskeyRows(r *http.Request, id *session.Identity, list []store.Passkey) []passkeyRow {
	here := map[string]bool{}
	for _, c := range s.passkeysHere(r) {
		here[c] = true
	}
	rows := s.passkeyRows(list)
	for i, p := range list {
		if p.ID != id.PK && !here[b64(p.CredentialID)] {
			continue
		}
		if rows[i].Computer {
			rows[i].Kind = msgPkThisComputer
		} else {
			rows[i].Kind = msgPkThisPhone
		}
	}
	return rows
}

// errPasskeyOnNetwork refuses a computer's challenge on a listed network.
var errPasskeyOnNetwork = errors.New("passkey: a computer on a listed network")

// passkeyBlockedNetwork reports whether the request comes from a network in
// NETWORK_RANGES, whose computers may not add a passkey, and the sentence
// that says so. With no ranges set, nothing is blocked.
func (s *Server) passkeyBlockedNetwork(r *http.Request) (string, bool) {
	addr := clientAddr(r)
	if !addr.IsValid() {
		return "", false
	}
	addr = addr.Unmap()
	for _, name := range s.networkNames() {
		for _, p := range s.cfg.NetworkRanges[name] {
			if p.Contains(addr) {
				return fmt.Sprintf(msgPkComputerOnNetwork, s.networkLabel(name)), true
			}
		}
	}
	return "", false
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
	"08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
	"9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello",
	"6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello",
	"adce0002-35bc-c60a-648b-0b25f1f05503": "Chrome on Mac",
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
	case strings.Contains(ua, "Macintosh"):
		return msgPkLabelMac
	case strings.Contains(ua, "Windows"):
		return msgPkLabelWindows
	case !isPhoneUA(ua):
		return msgPkLabelComputer
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
	s.sendNotice("passkey notice to "+to, func(ctx context.Context) error { return s.sender.Send(ctx, msg) })
}

// notifyPasskeyRemoved emails the account holder when they remove one of
// their passkeys. A session started with one passkey can remove the others,
// so a stolen, unlocked phone could strip the owner's other passkeys; this
// email is how the owner learns of it.
func (s *Server) notifyPasskeyRemoved(r *http.Request, to string, now time.Time) {
	msg := s.passkeyRemovedEmail(to, passkeyDevice(r.UserAgent()), now)
	s.sendNotice("passkey notice to "+to, func(ctx context.Context) error { return s.sender.Send(ctx, msg) })
}

// passkeyNoticeData is the view model for a passkey notice. The template
// renders with text/template, which does not escape, so every string is
// HTML-escaped by renderPasskeyNoticeHTML; the colours are validated "#rrggbb".
type passkeyNoticeData struct {
	BrandName, Heading, First, OK, NotYou, Link string
	HeaderColor, HeaderText                     string
	AccentColor, AccentText                     string
}

// renderPasskeyNoticeHTML lays a notice out like the sign-in code email, in
// the admin branding's colours, falling back to plain paragraphs if the
// template ever fails so that the notice is still sent.
func (s *Server) renderPasskeyNoticeHTML(heading, first, ok, notYou, link string, now time.Time) string {
	header := breakglass.DefaultPalette.Header
	accent := breakglass.DefaultPalette.Accent
	if b, err := s.publicBrandingAt(context.Background(), now); err == nil {
		header = hexOrDefault(b.headerColor, header)
		accent = hexOrDefault(b.accentColor, accent)
	}
	esc := html.EscapeString
	var buf bytes.Buffer
	err := s.emailTmpl.ExecuteTemplate(&buf, "email_passkey_notice", passkeyNoticeData{
		BrandName: esc(s.cfg.BrandName), Heading: esc(heading), First: esc(first), OK: esc(ok), NotYou: esc(notYou), Link: esc(link),
		HeaderColor: header, HeaderText: emailTextOn(header),
		AccentColor: accent, AccentText: emailTextOn(accent),
	})
	if err == nil {
		return buf.String()
	}
	log.Printf("render passkey notice: %v", err)
	return `<p>` + esc(first) + `</p><p>` + esc(ok) + `</p><p>` + esc(notYou) + `</p><p><a href="` + esc(link) + `">Your passkeys</a></p>`
}

// passkeyDevice names the kind of phone or computer for the notice, or "" if
// unknown.
func passkeyDevice(ua string) string {
	switch {
	case strings.Contains(ua, "iPhone"):
		return "an iPhone"
	case strings.Contains(ua, "Android"):
		return "an Android phone"
	case strings.Contains(ua, "Macintosh"):
		return msgPkNoticeMac
	case strings.Contains(ua, "Windows"):
		return msgPkNoticeWindows
	case ua != "" && !isPhoneUA(ua):
		return msgPkNoticeOther
	}
	return ""
}

// passkeyNotice builds a notice whose first line reads "A passkey was <done>
// your account at <host> on <date> at <time>[, on <device>]."
func (s *Server) passkeyNotice(to, subject, done, device, ok, notYou string, now time.Time) email.Message {
	when := now.In(s.loc)
	stamp := when.Format("2 January 2006") + " at " + strings.ToLower(when.Format("3:04 pm"))
	first := fmt.Sprintf("A passkey was %s your account at %s on %s", done, s.relyingParty().ID, stamp)
	if device != "" {
		first += ", on " + device
	}
	first += "."
	link := s.passkeysURL()
	text := first + "\n\n" + ok + "\n\n" + notYou + "\n\nYour passkeys: " + link + "\n"
	htmlBody := s.renderPasskeyNoticeHTML(subject, first, ok, notYou, link, now)
	return email.Message{To: to, Subject: subject, Text: text, HTML: htmlBody}
}

func (s *Server) passkeyAddedEmail(to, device string, now time.Time) email.Message {
	return s.passkeyNotice(to, "A passkey has been added to your account", "added to", device,
		"If you added this passkey, there is nothing more to do.",
		"If you did not add it, open Your passkeys, remove it, then contact an administrator for assistance.", now)
}

func (s *Server) passkeyRemovedEmail(to, device string, now time.Time) email.Message {
	return s.passkeyNotice(to, "A passkey has been removed from your account", "removed from", device,
		"If you removed this passkey, there is nothing more to do.",
		"If you did not remove it, sign in, check Your passkeys, then contact an administrator for assistance.", now)
}
