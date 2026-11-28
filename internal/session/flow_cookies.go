// The short-lived cookies of the sign-in flow: state, pending code, passkey offer and passkey challenge.

package session

import (
	"net/http"
	"time"
)

// --- State (host-only cookie) ---

// SetState writes the login-progress cookie, valid for ttl.
func (m *Manager) SetState(w http.ResponseWriter, st State, ttl time.Duration, now time.Time) error {
	tok, err := m.encode(typState, st, now.Add(ttl))
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
	if err := m.decode(typState, c.Value, now, &st); err != nil {
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
	tok, err := m.encode(typPending, p, now.Add(ttl))
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
	if err := m.decode(typPending, c.Value, now, &p); err != nil {
		return nil, false
	}
	return &p, true
}

// ClearPending expires the pending-TOTP cookie.
func (m *Manager) ClearPending(w http.ResponseWriter) {
	m.clearCookie(w, PendingCookie, "")
}

// --- Break-glass offer (host-only cookie) ---

// SetOffer writes the break-glass offer cookie, valid for ttl. Host-only (like
// State/Pending) so it is scoped to the auth host, where both the denial page
// and the activation endpoint live.
func (m *Manager) SetOffer(w http.ResponseWriter, o Offer, ttl time.Duration, now time.Time) error {
	tok, err := m.encode(typOffer, o, now.Add(ttl))
	if err != nil {
		return err
	}
	m.setCookie(w, OfferCookie, tok, "", ttl)
	return nil
}

// ReadOffer returns the break-glass offer cookie if present and valid.
func (m *Manager) ReadOffer(r *http.Request, now time.Time) (*Offer, bool) {
	c, err := r.Cookie(OfferCookie)
	if err != nil {
		return nil, false
	}
	var o Offer
	if err := m.decode(typOffer, c.Value, now, &o); err != nil {
		return nil, false
	}
	return &o, true
}

// ClearOffer expires the break-glass offer cookie.
func (m *Manager) ClearOffer(w http.ResponseWriter) {
	m.clearCookie(w, OfferCookie, "")
}

// --- Passkey challenges (host-only cookies) ---

// pkCookie names the challenge cookie. Under TLS the name carries the
// __Host- prefix, which a browser accepts only from this host, with Secure, no
// Domain and Path=/: a sibling app on the domain cannot plant a challenge of
// its own to spoil a person's passkey sign-in. Without TLS (development) the
// prefix would make the browser refuse the cookie, so it is left off.
func (m *Manager) pkCookie(register bool) (name, typ string) {
	name, typ = PasskeyLoginCookie, typPKLogin
	if register {
		name, typ = PasskeyRegCookie, typPKReg
	}
	if m.secure {
		name = "__Host-" + name
	}
	return name, typ
}

// SetPasskeyChallenge writes the challenge for a passkey sign-in or, when
// register is true, for adding a passkey.
func (m *Manager) SetPasskeyChallenge(w http.ResponseWriter, register bool, c PasskeyChallenge, ttl time.Duration, now time.Time) error {
	name, typ := m.pkCookie(register)
	tok, err := m.encode(typ, c, now.Add(ttl))
	if err != nil {
		return err
	}
	m.setCookie(w, name, tok, "", ttl)
	return nil
}

// ReadPasskeyChallenge returns the challenge cookie if present and valid.
func (m *Manager) ReadPasskeyChallenge(r *http.Request, register bool, now time.Time) (*PasskeyChallenge, bool) {
	name, typ := m.pkCookie(register)
	c, err := r.Cookie(name)
	if err != nil {
		return nil, false
	}
	var pc PasskeyChallenge
	if err := m.decode(typ, c.Value, now, &pc); err != nil || len(pc.Challenge) == 0 {
		return nil, false
	}
	return &pc, true
}

// ClearPasskeyChallenge expires the challenge cookie.
func (m *Manager) ClearPasskeyChallenge(w http.ResponseWriter, register bool) {
	name, _ := m.pkCookie(register)
	m.clearCookie(w, name, "")
}
