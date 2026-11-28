// The admin second step: TOTP or an admin passkey, and how fresh it must be.

package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/secretbox"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
)

// stepUpSession reads the session of an administrator at the admin door: a
// normal sign-in of an address that is an administrator now, whose passkey,
// if it started with one, has not been removed.
func (s *Server) stepUpSession(r *http.Request) (*session.Identity, bool) {
	id, ok := s.readSession(r, s.now())
	if !ok || id.Kind != "" || s.policy.Role(id.Email) != authz.RoleAdmin {
		return nil, false
	}
	return id, true
}

// adminTierHeld reports whether a session holds the admin tier now: the admin
// group in its groups and a recent second step.
func (s *Server) adminTierHeld(id *session.Identity) bool {
	return isAdminSession(id) && s.adminStepFresh(id)
}

// adminDest is where the admin door sends a person on: the page they asked
// for, else the admin pages.
func (s *Server) adminDest(rd string) string {
	if rd == "" {
		return s.cfg.PublicURL + "/admin/"
	}
	return s.loginRedirect(rd)
}

// handleStepUp is the admin door: the second step an administrator takes
// before the admin pages or an admin-only route, with a passkey that can
// stand in for it or with the authenticator code. Signing in never asks for
// it, so the clinical sites open on the first factor alone.
//
// Secrets are provisioned by an administrator (the admin UI or the
// -totp-enroll CLI), never self-enrolled here: letting a session bootstrap
// its own second factor would let someone who controls only the email inbox
// set up the factor that is meant to backstop a compromised inbox.
func (s *Server) handleStepUp(w http.ResponseWriter, r *http.Request) {
	rd := authz.SafeRedirect(r.URL.Query().Get("rd"), s.cfg.Domain, "")
	id, ok := s.readSession(r, s.now())
	if !ok {
		http.Redirect(w, r, s.loginURL(s.stepUpURL(rd)), http.StatusFound)
		return
	}
	if _, admin := s.stepUpSession(r); !admin {
		http.Redirect(w, r, s.cfg.PublicURL+"/denied?rd="+url.QueryEscape(s.adminDest(rd)), http.StatusFound)
		return
	}
	if s.adminTierHeld(id) {
		http.Redirect(w, r, s.adminDest(rd), http.StatusFound)
		return
	}
	s.renderStepUp(w, r, id, rd, http.StatusOK, "")
}

// renderStepUp draws the admin door. The passkey is offered on a phone that
// can use one, and only when the person holds a passkey that stands in for
// the second step; any other passkey would sign them in again as an ordinary
// user and bring them straight back here.
func (s *Server) renderStepUp(w http.ResponseWriter, r *http.Request, id *session.Identity, rd string, status int, msg string) {
	_, hasTOTP, err := s.getTOTPSecret(r.Context(), id.Email)
	if err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong", Redirect: rd})
		return
	}
	if !hasTOTP {
		s.render(w, http.StatusForbidden, "message", pageData{
			Title:    "Two-factor setup required",
			Message:  "The admin pages need an authenticator app, which has not been set up for your account yet. Please ask another administrator to set it up for you.",
			Redirect: rd,
		})
		return
	}
	csrf, err := s.sessions.EnsureCSRF(w, r, csrfTTL, s.now())
	if err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong", Redirect: rd})
		return
	}
	data := pageData{Redirect: rd, CSRF: csrf, Error: msg, Identity: id.Email}
	if s.cfg.PasskeysEnabled && isPhone(r) && s.hasAdminPasskey(r, id.Email) {
		data.Passkey = s.passkeyLoginOptions(w)
	}
	// A computer is asked only for the admin passkeys it holds.
	if s.cfg.PasskeysEnabled && !isPhone(r) {
		if allow := s.adminPasskeysHere(r, id.Email); allow != "" {
			if data.Passkey = s.passkeyLoginOptions(w); data.Passkey != nil {
				data.Passkey.Allow = allow
			}
		}
	}
	data.Message = stepUpSub(data.Passkey != nil)
	s.render(w, status, "totp", data)
}

// hasAdminPasskey reports whether email holds a passkey that stands in for
// the admin second step.
func (s *Server) hasAdminPasskey(r *http.Request, email string) bool {
	list, err := s.store.ListPasskeys(r.Context(), email)
	if err != nil {
		log.Printf("passkeys for %s: %v", email, err)
		return false
	}
	for _, p := range list {
		if p.AdminGrade {
			return true
		}
	}
	return false
}

// shouldOfferAdminPasskey decides whether the admin door offers a passkey
// after a right authenticator code. A phone is offered one while the account
// holds no admin passkey, as before. A computer is offered one while it holds
// no admin passkey of the account's (adminPasskeysHere), unless it is on a
// listed network, where no computer may add a passkey. The offer on a
// computer carries the warning to add one only on a computer nobody else
// signs in to, and its ceremony is the computer's: a platform authenticator,
// held by the computer, refused otherwise (handlePasskeyRegister).
func (s *Server) shouldOfferAdminPasskey(r *http.Request, email string) bool {
	if !s.cfg.PasskeysEnabled {
		return false
	}
	if isPhone(r) {
		return !s.hasAdminPasskey(r, email)
	}
	return !s.computerOnNetwork(r) && s.adminPasskeysHere(r, email) == ""
}

// handleTOTP takes the authenticator code at the admin door and gives the
// session the admin tier. The code is checked under the per-account cap and
// the replay guard (checkAdminCode).
func (s *Server) handleTOTP(w http.ResponseWriter, r *http.Request) {
	if !s.requireSameOrigin(w, r) {
		return
	}
	now := s.now()
	rd := authz.SafeRedirect(r.PostFormValue("rd"), s.cfg.Domain, "")
	id, ok := s.stepUpSession(r)
	if !ok {
		http.Redirect(w, r, s.loginURL(s.stepUpURL(rd)), http.StatusFound)
		return
	}
	// A second tap after the first succeeded (the code is single-use, so it
	// could not pass again) finds the tier already held and goes on.
	if s.adminTierHeld(id) {
		http.Redirect(w, r, s.adminDest(rd), http.StatusFound)
		return
	}
	if !s.sessions.VerifyCSRF(r, r.PostFormValue("csrf"), now) {
		s.renderStepUp(w, r, id, rd, http.StatusForbidden, "This page had expired. Please enter the code again.")
		return
	}
	if msg, status, ok := s.checkAdminCode(r, id.Email, strings.TrimSpace(r.PostFormValue("code")), now); !ok {
		s.renderStepUp(w, r, id, rd, status, msg)
		return
	}
	// The session gains the admin tier under a new token (startSession
	// replaces the old one), keeping its sign-in time and passkey.
	// SID names the session being replaced: if it has been ended while the
	// code was checked, no new session starts.
	next := session.Identity{Email: id.Email, TOTP: true, Step: now.Unix(), PK: id.PK, Auth: id.Auth, SID: id.SID}
	next.Groups = s.computeGroups(r.Context(), id.Email, authz.RoleAdmin)
	if err := s.startSession(w, r, next, s.sessions.SessionTTL(id), now); errors.Is(err, errGrantGone) {
		s.sessions.ClearSession(w)
		http.Redirect(w, r, s.loginURL(s.stepUpURL(rd)), http.StatusFound)
		return
	} else if err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong", Redirect: rd})
		return
	}
	dest := s.adminDest(rd)
	// Where no passkey that can open the admin pages is at hand, offer one
	// now, while the authenticator code is fresh, so that the code is not
	// needed again on this device (shouldOfferAdminPasskey). A passkey that
	// started this session is never upgraded in place: the cookie naming it
	// could have been planted by a sibling host, so the passkey offered is a
	// new one, made on the device in front of the person who has just entered
	// the code. Made for the same account, it replaces a phone's older
	// passkey there.
	if s.shouldOfferAdminPasskey(r, id.Email) && s.offerAdminPasskey(w, r, id.Email, dest) {
		return
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// totpLockoutWindow is the rolling window over which TOTP verification attempts
// are counted toward the per-account lockout (cap = OTP_MAX_ATTEMPTS).
const totpLockoutWindow = 15 * time.Minute

// adminStepMaxAge is how long the admin second step lasts. An administrator's
// session may last much longer (a remembered one, 30 days on RCH); the admin
// tier inside it lasts this long from the last authenticator code or admin
// passkey, then the admin door asks again.
const adminStepMaxAge = 12 * time.Hour

// The line under the heading of the admin second step, with a passkey offered
// and without. %s is adminStepMaxAge in words ("12 hours"). Approved by the
// owner on 23 November 2026.
const (
	msgStepUpSubPasskey = "The admin pages need a second step, which lasts %s. Use your passkey, or enter the 6-digit code from your authenticator app."
	msgStepUpSub        = "The admin pages need a second step, which lasts %s. Enter the 6-digit code from your authenticator app."
)

// stepUpSub is the line under the heading of the admin second step.
func stepUpSub(passkey bool) string {
	if passkey {
		return fmt.Sprintf(msgStepUpSubPasskey, renewWithin(adminStepMaxAge))
	}
	return fmt.Sprintf(msgStepUpSub, renewWithin(adminStepMaxAge))
}

// adminStepFresh reports whether a session has passed the admin second step
// recently enough to hold the admin tier. With TOTP off there is no second
// step, so every administrator's session holds it, as before. A session from
// before the step time was recorded counts from its sign-in.
func (s *Server) adminStepFresh(id *session.Identity) bool {
	if !s.cfg.TOTPEnabled {
		return true
	}
	if id == nil || id.Kind != "" || !id.TOTP {
		return false
	}
	at := id.Step
	if at == 0 {
		at = id.Auth
	}
	return at > 1 && s.now().Unix()-at <= int64(adminStepMaxAge.Seconds())
}

func (s *Server) stepUpURL(rd string) string {
	return s.cfg.PublicURL + "/totp?rd=" + url.QueryEscape(rd)
}

// getTOTPSecret reads and decrypts the stored TOTP secret. A legacy plaintext
// value is returned as-is and transparently re-encrypted for next time.
func (s *Server) getTOTPSecret(ctx context.Context, emailAddr string) (string, bool, error) {
	stored, ok, err := s.store.GetTOTPSecret(ctx, emailAddr)
	if err != nil || !ok {
		return "", ok, err
	}
	plain, err := s.secrets.Open(stored)
	if err == secretbox.ErrLegacyPlaintext {
		if reErr := s.setTOTPSecret(ctx, emailAddr, plain); reErr != nil {
			log.Printf("totp re-encrypt for %s: %v", emailAddr, reErr)
		}
		return plain, true, nil
	}
	if err != nil {
		return "", false, err
	}
	return plain, true, nil
}

// setTOTPSecret encrypts and stores a TOTP secret.
func (s *Server) setTOTPSecret(ctx context.Context, emailAddr, secret string) error {
	enc, err := s.secrets.Seal(secret)
	if err != nil {
		return err
	}
	return s.store.SetTOTPSecret(ctx, emailAddr, enc)
}
