// Package session implements stateless, HMAC-signed cookies. The login session
// itself carries the user's identity; short-lived "state" and "pending"
// cookies carry the in-progress login (which email, where to return to, and
// whether an admin still owes a TOTP step). Nothing here touches a database.
package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// Cookie names.
const (
	SessionCookie = "vps_auth_session"
	StateCookie   = "vps_auth_state"
	PendingCookie = "vps_auth_pending"
	CSRFCookie    = "vps_auth_csrf"
)

// ErrInvalid is returned when a token fails signature or structural checks.
var ErrInvalid = errors.New("session: invalid token")

var b64 = base64.RawURLEncoding

// Signer produces and verifies HMAC-SHA256 signed tokens of the form
// base64(payload).base64(mac).
type Signer struct{ secret []byte }

// NewSigner returns a Signer using the given secret.
func NewSigner(secret []byte) Signer { return Signer{secret: secret} }

// Sign returns a signed token for payload.
func (s Signer) Sign(payload []byte) string {
	mac := s.mac(payload)
	return b64.EncodeToString(payload) + "." + b64.EncodeToString(mac)
}

// Verify checks a token's signature and returns its payload.
func (s Signer) Verify(token string) ([]byte, error) {
	dot := -1
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		return nil, ErrInvalid
	}
	payload, err := b64.DecodeString(token[:dot])
	if err != nil {
		return nil, ErrInvalid
	}
	gotMAC, err := b64.DecodeString(token[dot+1:])
	if err != nil {
		return nil, ErrInvalid
	}
	wantMAC := s.mac(payload)
	if subtle.ConstantTimeCompare(gotMAC, wantMAC) != 1 {
		return nil, ErrInvalid
	}
	return payload, nil
}

func (s Signer) mac(payload []byte) []byte {
	h := hmac.New(sha256.New, s.secret)
	h.Write(payload)
	return h.Sum(nil)
}

// envelope wraps an arbitrary payload with an absolute expiry.
type envelope struct {
	Exp  int64           `json:"exp"`
	Data json.RawMessage `json:"data"`
}

// Session kinds. The empty string is a normal email-OTP login; KindBreakGlass
// marks a session granted by scanning a break-glass QR code.
const (
	KindBreakGlass = "break_glass"
)

// Identity is the authenticated principal carried by the session cookie.
type Identity struct {
	Email  string `json:"email"`
	Groups string `json:"groups"`
	Iat    int64  `json:"iat"`
	// Kind distinguishes break-glass sessions, which must not be renewed.
	Kind string `json:"kind,omitempty"`
	// TTL is the session's chosen lifetime in seconds, so a renewal re-issues
	// with the same lifetime (e.g. a 30-day "remember me" session).
	TTL int64 `json:"ttl,omitempty"`
}

// State is the short-lived login progress carried between /request and
// /verify-code.
type State struct {
	Email    string `json:"email"`
	Redirect string `json:"rd"`
	Remember bool   `json:"rem,omitempty"`
}

// Pending marks an admin who has passed the email step but still owes TOTP.
type Pending struct {
	Email    string `json:"email"`
	Role     string `json:"role"`
	Redirect string `json:"rd"`
	Remember bool   `json:"rem,omitempty"`
}

// Manager issues and reads the typed cookies.
type Manager struct {
	signer       Signer
	ttl          time.Duration
	renew        time.Duration
	cookieDomain string
	secure       bool
}

// NewManager builds a Manager. secure controls the cookie Secure attribute
// (true in production behind TLS).
func NewManager(secret []byte, ttl, renew time.Duration, cookieDomain string, secure bool) *Manager {
	return &Manager{
		signer:       NewSigner(secret),
		ttl:          ttl,
		renew:        renew,
		cookieDomain: cookieDomain,
		secure:       secure,
	}
}

func (m *Manager) encode(v any, exp time.Time) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	env, err := json.Marshal(envelope{Exp: exp.Unix(), Data: data})
	if err != nil {
		return "", err
	}
	return m.signer.Sign(env), nil
}

func (m *Manager) decode(token string, now time.Time, v any) error {
	raw, err := m.signer.Verify(token)
	if err != nil {
		return err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return ErrInvalid
	}
	if now.Unix() > env.Exp {
		return ErrInvalid
	}
	return json.Unmarshal(env.Data, v)
}

func (m *Manager) setCookie(w http.ResponseWriter, name, value, domain string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   domain,
		MaxAge:   int(ttl.Seconds()),
		Secure:   m.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (m *Manager) clearCookie(w http.ResponseWriter, name, domain string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Domain:   domain,
		MaxAge:   -1,
		Secure:   m.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// --- Session ---

// IssueSession writes a normal session cookie using the default TTL.
func (m *Manager) IssueSession(w http.ResponseWriter, email, groups string, now time.Time) error {
	return m.IssueSessionTTL(w, email, groups, "", m.ttl, now)
}

// IssueSessionTTL writes a session cookie with an explicit lifetime and kind.
// The chosen TTL is stored in the identity so a later renewal preserves it.
func (m *Manager) IssueSessionTTL(w http.ResponseWriter, email, groups, kind string, ttl time.Duration, now time.Time) error {
	if ttl <= 0 {
		ttl = m.ttl
	}
	id := Identity{Email: email, Groups: groups, Iat: now.Unix(), Kind: kind, TTL: int64(ttl.Seconds())}
	tok, err := m.encode(id, now.Add(ttl))
	if err != nil {
		return err
	}
	m.setCookie(w, SessionCookie, tok, m.cookieDomain, ttl)
	return nil
}

// ReadSession returns the identity from a valid session cookie.
func (m *Manager) ReadSession(r *http.Request, now time.Time) (*Identity, bool) {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return nil, false
	}
	var id Identity
	if err := m.decode(c.Value, now, &id); err != nil {
		return nil, false
	}
	return &id, true
}

// NeedsRenew reports whether a session is past its sliding-renewal threshold.
// Break-glass sessions are never renewed: they must expire at their short,
// absolute lifetime rather than being silently extended.
func (m *Manager) NeedsRenew(id *Identity, now time.Time) bool {
	if id.Kind == KindBreakGlass {
		return false
	}
	return now.Unix() > id.Iat+int64(m.renew.Seconds())
}

// SessionTTL returns the lifetime to renew an identity with: its stored TTL if
// present, else the manager default.
func (m *Manager) SessionTTL(id *Identity) time.Duration {
	if id.TTL > 0 {
		return time.Duration(id.TTL) * time.Second
	}
	return m.ttl
}

// ClearSession expires the session cookie.
func (m *Manager) ClearSession(w http.ResponseWriter) {
	m.clearCookie(w, SessionCookie, m.cookieDomain)
}

// --- State (host-only cookie) ---

// SetState writes the login-progress cookie, valid for ttl.
func (m *Manager) SetState(w http.ResponseWriter, st State, ttl time.Duration, now time.Time) error {
	tok, err := m.encode(st, now.Add(ttl))
	if err != nil {
		return err
	}
	m.setCookie(w, StateCookie, tok, "", ttl)
	return nil
}

// ReadState returns the login-progress cookie if present and valid.
func (m *Manager) ReadState(r *http.Request, now time.Time) (*State, bool) {
	c, err := r.Cookie(StateCookie)
	if err != nil {
		return nil, false
	}
	var st State
	if err := m.decode(c.Value, now, &st); err != nil {
		return nil, false
	}
	return &st, true
}

// ClearState expires the state cookie.
func (m *Manager) ClearState(w http.ResponseWriter) {
	m.clearCookie(w, StateCookie, "")
}

// --- Pending TOTP (host-only cookie) ---

// SetPending writes the pending-TOTP cookie, valid for ttl.
func (m *Manager) SetPending(w http.ResponseWriter, p Pending, ttl time.Duration, now time.Time) error {
	tok, err := m.encode(p, now.Add(ttl))
	if err != nil {
		return err
	}
	m.setCookie(w, PendingCookie, tok, "", ttl)
	return nil
}

// ReadPending returns the pending-TOTP cookie if present and valid.
func (m *Manager) ReadPending(r *http.Request, now time.Time) (*Pending, bool) {
	c, err := r.Cookie(PendingCookie)
	if err != nil {
		return nil, false
	}
	var p Pending
	if err := m.decode(c.Value, now, &p); err != nil {
		return nil, false
	}
	return &p, true
}

// ClearPending expires the pending-TOTP cookie.
func (m *Manager) ClearPending(w http.ResponseWriter) {
	m.clearCookie(w, PendingCookie, "")
}

// --- CSRF (host-only, signed double-submit token) ---

// EnsureCSRF returns the request's CSRF token, minting and setting a fresh
// signed one (host-only cookie) if absent. Embed the returned value in admin
// forms; verify POSTs with VerifyCSRF.
func (m *Manager) EnsureCSRF(w http.ResponseWriter, r *http.Request, ttl time.Duration) (string, error) {
	if c, err := r.Cookie(CSRFCookie); err == nil {
		if _, err := m.signer.Verify(c.Value); err == nil {
			return c.Value, nil
		}
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := m.signer.Sign(buf)
	m.setCookie(w, CSRFCookie, token, "", ttl)
	return token, nil
}

// VerifyCSRF reports whether the submitted token matches the signed CSRF cookie.
func (m *Manager) VerifyCSRF(r *http.Request, submitted string) bool {
	if submitted == "" {
		return false
	}
	c, err := r.Cookie(CSRFCookie)
	if err != nil {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(c.Value), []byte(submitted)) != 1 {
		return false
	}
	_, err = m.signer.Verify(c.Value)
	return err == nil
}
