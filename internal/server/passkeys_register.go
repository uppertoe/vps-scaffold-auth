// Adding a passkey: the confirmation step, registration, and the network rule.

package server

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/passkey"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
	"github.com/uppertoe/vps-scaffold-auth/internal/totp"
)

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
	adminGrade := adminGradeFor(role, s.cfg.TOTPEnabled, ch.Confirmed, s.adminStepFresh(id))

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
