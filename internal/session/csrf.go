// Form tokens (CSRF) bound to a session.

package session

import (
	"crypto/rand"
	"crypto/subtle"
	"net/http"
	"time"
)

// --- CSRF (host-only, signed double-submit token) ---

// csrfPayload is the CSRF token body: an unguessable nonce bound to the current
// session subject (admin email). Binding to the subject means a token captured
// from one admin cannot be replayed against another; wrapping it in the signed
// envelope (encode/decode) gives it a real expiry, not just a cookie MaxAge.
type csrfPayload struct {
	Nonce []byte `json:"n"`
	Sub   string `json:"s"`
}

// csrfSub returns the subject the CSRF token is bound to: the current session's
// email, or "" when there is no session (pre-login forms).
func (m *Manager) csrfSub(r *http.Request, now time.Time) string {
	if m.Subject == nil {
		return ""
	}
	return m.Subject(r, now)
}

// EnsureCSRF returns the request's CSRF token, minting and setting a fresh one
// (host-only cookie) if absent, expired, or bound to a different session. Embed
// the returned value in admin forms; verify POSTs with VerifyCSRF.
func (m *Manager) EnsureCSRF(w http.ResponseWriter, r *http.Request, ttl time.Duration, now time.Time) (string, error) {
	sub := m.csrfSub(r, now)
	if c, err := r.Cookie(CSRFCookie); err == nil {
		var p csrfPayload
		if err := m.decode(typCSRF, c.Value, now, &p); err == nil && p.Sub == sub {
			return c.Value, nil // still valid and bound to this session
		}
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	token, err := m.encode(typCSRF, csrfPayload{Nonce: nonce, Sub: sub}, now.Add(ttl))
	if err != nil {
		return "", err
	}
	m.setCookie(w, CSRFCookie, token, "", ttl)
	return token, nil
}

// VerifyCSRF reports whether the submitted token matches the signed CSRF cookie,
// is unexpired, and is bound to the current session (double-submit + binding).
func (m *Manager) VerifyCSRF(r *http.Request, submitted string, now time.Time) bool {
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
	var p csrfPayload
	if err := m.decode(typCSRF, c.Value, now, &p); err != nil { // signature + expiry
		return false
	}
	return p.Sub == m.csrfSub(r, now)
}
