package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/passkey"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
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
// passkey: on a phone, for a staff, administrator, member or guest account,
// after every sign-in with an emailed code. An emailed code on a phone is the moment a
// passkey would have saved the person a step; "Not now" costs one tap. A
// phone that already holds one of the person's passkeys says so if they tap
// Add (excludeCredentials).
func (s *Server) shouldOfferPasskey(r *http.Request, role string, pk int64) bool {
	if !s.cfg.PasskeysEnabled || pk != 0 || !isPhone(r) {
		return false
	}
	return mayHoldPasskey(role)
}

// adminGradeFor decides whether a passkey being added stands in for the admin
// second step: only an administrator's, with TOTP on, straight after an
// authenticator code (confirmed) or while the admin step is fresh. The role
// is checked first and on its own, so a guest's, a member's or staff's
// passkey is never admin grade whatever the session or challenge says.
func adminGradeFor(role string, totpOn, confirmed, stepFresh bool) bool {
	if role != authz.RoleAdmin {
		return false
	}
	return totpOn && (confirmed || stepFresh)
}

// mayHoldPasskey reports whether a sign-in with this role may add and use a
// passkey: staff, an administrator, a member or a guest, under the same
// rules. A guest's passkey is never admin grade (only an administrator's
// is), and signing in with it gives whatever an emailed code would give the
// address on that destination (loginRole), so a guest's passkey signs in as
// a guest only where guests may sign in.
func mayHoldPasskey(role string) bool {
	switch role {
	case authz.RoleUser, authz.RoleAdmin, authz.RoleMember, authz.RoleGuest:
		return true
	}
	return false
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

// passkeySession reads the session of a person who may manage passkeys and
// their own sessions: staff, an administrator, a member or a guest, never a
// break-glass card. A guest's role is RoleGuest while guests may still sign
// in (renewalRole), even if the address has since become staff, since the
// session stays a guest's until its person signs in again. An administrator
// need not hold the admin tier to see or remove their passkeys; adding one
// asks for the authenticator code first (mayAddPasskeyNow).
func (s *Server) passkeySession(r *http.Request) (*session.Identity, string, bool) {
	id, ok := s.readSession(r, s.now())
	if !ok {
		return nil, "", false
	}
	var role string
	switch {
	case personSession(id):
		role = s.currentRole(r.Context(), id.Email)
	case id.Kind == session.KindGuest:
		role = s.renewalRole(id)
	}
	if !mayHoldPasskey(role) || (id.Kind == session.KindGuest) != (role == authz.RoleGuest) {
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
