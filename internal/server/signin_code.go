// Email-code sign-in: requesting a code, sending it, and checking it.

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/otp"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// handleRequest sends an OTP code. To avoid leaking which addresses are
// permitted, it always responds with the enter-code page regardless of whether
// the email is allowed.
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	if !s.requireSameOrigin(w, r) {
		return
	}
	now := s.now()
	if !s.ipLimiter.Allow(clientIP(r)) {
		s.render(w, http.StatusTooManyRequests, "message", pageData{
			Title:   "Too many requests",
			Message: "Please wait a little while and try again.",
		})
		return
	}

	emailAddr := normalizeEmail(r.PostFormValue("email"))
	rd := authz.SafeRedirect(r.PostFormValue("rd"), s.cfg.Domain, "") // empty fallback; see handleLogin
	remember := r.PostFormValue("remember") != ""

	rqd := clampHint(r.PostFormValue("rqd"))
	rqr, rhd := r.PostFormValue("rqr"), r.PostFormValue("rhd")

	if !validEmail(emailAddr) {
		data := pageData{Error: "Please enter a valid email address.", Redirect: rd, Remember: remember}
		applyAccessHint(&data, rqd)
		applyRoleHint(&data, rqr, rhd)
		s.renderLogin(w, r, http.StatusBadRequest, data)
		return
	}

	// UX-only early decline: when a role is held only by domain groups (the
	// guard carries their domains as rqd), an address at none of them can
	// never get in here, so say so now instead of emailing a code that would
	// be refused after sign-in. This is a courtesy, NOT a security boundary:
	// rqd rides in the (client-modifiable) login URL, so the authoritative
	// check stays in handleVerify.
	if rqd != "" && !authz.DomainIn(emailAddr, rqd) {
		data := pageData{
			Error:    fmt.Sprintf(msgDeclineDomain, formatDomains(rqd), withArticle(formatDomains(rqd))),
			Redirect: rd, Remember: remember,
		}
		applyAccessHint(&data, rqd)
		s.renderLogin(w, r, http.StatusForbidden, data)
		return
	}

	// Opportunistically prune expired codes so decoys (below) stored for
	// addresses that are never verified cannot accumulate without bound.
	if err := s.store.DeleteExpiredCodes(r.Context(), now); err != nil {
		log.Printf("prune expired codes: %v", err)
	}

	// Generate + email a code only for permitted addresses under their per-email
	// send limit. For everyone else, persist an unguessable, never-emailed decoy
	// instead, so the subsequent /verify-code step is indistinguishable between
	// permitted and non-permitted addresses. Without the decoy, a non-permitted
	// address has no stored code and so reports "expired" (ConsumeNoCode) while a
	// permitted one reports "incorrect" (ConsumeMismatch) and can reach the
	// attempt cap — a difference that leaks who may sign in, and thus which
	// off-domain addresses are admins. Either branch falls through to the same
	// response. EnsureCode is insert-if-absent, so a rate-limited permitted user's
	// live code is never overwritten.
	//
	// "Permitted" includes a would-be guest: when rd points at a host open to
	// guests (isOpenHost), any syntactically valid public address is sent a
	// real code (loginRole returns RoleGuest). That leaks nothing, since on
	// such a host everyone is mailed; on every other host the decoy behaviour
	// is unchanged.
	//
	// Both kinds of address go through the SAME cooldown, send-limit and
	// counter transitions; the only difference is whether mail is sent. A
	// decoy that kept its attempt counter across a re-request while a real
	// code's was reset (or that never spent a send token) would answer the
	// next wrong guess differently, and that difference is who
	// may sign in.
	// While the gateway cannot tell who is staff, nobody is sent a code or a
	// decoy: a member of staff would otherwise be refused, or made a guest.
	if s.rolesUnavailable(r.Context()) {
		s.renderUnavailable(w, rd)
		return
	}
	permitted := s.loginRole(r.Context(), emailAddr, s.isOpenHost(r.Context(), rd)) != authz.RoleDeny
	s.issueCode(r, emailAddr, permitted, now)

	if err := s.sessions.SetState(w, session.State{Email: emailAddr, Redirect: rd, Remember: remember}, s.cfg.OTPTTL, now); err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong", Redirect: rd})
		return
	}
	s.render(w, http.StatusOK, "code", pageData{Email: emailAddr, Redirect: rd, Remember: remember})
}

// issueCode sends a sign-in code to a permitted address, or stores a decoy
// for any other, under the cooldown and the send limits (see handleRequest).
// An invitation's page sends its code through here too.
func (s *Server) issueCode(r *http.Request, emailAddr string, permitted bool, now time.Time) {
	// Suppress a re-request while the last code is still fresh: a code minted
	// within the cooldown window has expires_at > now + OTPTTL - cooldown.
	// Deriving issue time from expiry is exact because SaveCode sets
	// expires_at = issue + OTPTTL.
	minExpiry := now.Add(s.cfg.OTPTTL - s.cfg.OTPResendCooldown)
	recent, err := s.store.HasRecentCode(r.Context(), emailAddr, minExpiry)
	if err != nil {
		// Fail on the safe side: an unknown answer is treated as "a live code
		// was issued within the cooldown", so a transient read error cannot
		// re-mint the code and hand a guesser fresh attempt counters.
		log.Printf("recent-code check for %s: %v (treating as within cooldown)", emailAddr, err)
		recent = true
	}
	switch {
	case s.mailSaturated():
		// Every mail slot is in use: a flood. No code is sent and no send
		// token is spent, for either kind of address. As when over the send
		// limit, a decoy is stored only if no code exists: a live code is never
		// overwritten, a wrong guess is answered "incorrect" as at any other
		// time (so the flood cannot be seen, and through it who may sign in),
		// and the decoy's expiry falls just short of the cooldown window, so
		// the person's next request after the flood sends a code at once.
		log.Printf("request for %s: no code sent, %d emails are already being sent", emailAddr, maxMailSends)
		if err := s.storeDecoyCode(r.Context(), emailAddr, now); err != nil {
			log.Printf("store decoy code for %s: %v", emailAddr, err)
		}
	case recent:
		// No-op: a live code was issued within the cooldown. Don't mint, don't
		// email, don't spend a send token. The existing code's attempt counter
		// stays intact, so a re-request can't reset the brute-force cap — which
		// is the guard that survives back-button / refresh / new-tab.
	case s.allowSend(r.Context(), emailAddr, clientIP(r), now):
		if permitted {
			if err := s.sendCode(r, emailAddr, now); err != nil { // SaveCode(overwrite) + email
				log.Printf("send code to %s: %v", emailAddr, err)
			}
		} else if err := s.saveDecoyCode(r.Context(), emailAddr, now); err != nil { // SaveCode(overwrite), no email
			log.Printf("save decoy code for %s: %v", emailAddr, err)
		}
	default:
		// Over the send limit: do NOT clobber a possibly-live code we can't
		// re-deliver. Insert-if-absent for both kinds of address.
		if err := s.storeDecoyCode(r.Context(), emailAddr, now); err != nil {
			log.Printf("store decoy code for %s: %v", emailAddr, err)
		}
	}
}

// knownDeviceWindow is how far back a successful sign-in from the same client
// IP lets an address past the send ceilings (see allowSend).
const knownDeviceWindow = 30 * 24 * time.Hour

// allowSend decides whether /request may send a code (or, for an address that
// is not permitted, mint its decoy). The allowance is per (address, client IP),
// so a stranger elsewhere cannot spend the owner's own. Beyond that, the
// per-address ceiling bounds a flood of one inbox spread across many IPs, and
// the per-IP send cap bounds the mail one client can cause across many
// addresses. An address that signed in successfully from this same IP within
// knownDeviceWindow passes both ceilings, so an attacker who exhausts them
// cannot lock the owner out from their usual network. Permitted and
// non-permitted addresses take the same path.
func (s *Server) allowSend(ctx context.Context, emailAddr, ip string, now time.Time) bool {
	if !s.emailLimiter.Allow(emailAddr + "|" + ip) {
		return false
	}
	// The per-IP cap is charged first and refunded if the ceiling refuses, so
	// that a request refused by either spends neither: otherwise one IP that
	// has filled its own send cap (with decoys, sending no mail) could still
	// drain an owner's ceiling.
	if s.sendsPerIP.Allow(ip) {
		if s.emailCeiling.Allow(emailAddr) {
			if s.emailDaily.Allow(emailAddr) {
				return true
			}
			s.emailCeiling.Refund(emailAddr)
			s.alertAboutCodes(emailAddr, codeAlertDaily, now)
		}
		s.sendsPerIP.Refund(ip)
	}
	known, err := s.store.HasRecentLogin(ctx, emailAddr, ip, now.Add(-knownDeviceWindow))
	if err != nil {
		log.Printf("recent-login check for %s: %v (treating as unknown)", emailAddr, err)
		return false
	}
	return known
}

// sendCode generates and stores a fresh OTP code, then dispatches the email on
// a detached goroutine. The code is persisted synchronously (so /verify-code
// works the instant /request returns), but the email delivery — the slow,
// backend-dependent step — must not gate the HTTP response: doing so leaks
// whether an address is permitted via a response-timing side channel, since
// only permitted addresses are ever sent mail. See handleRequest.
func (s *Server) sendCode(r *http.Request, emailAddr string, now time.Time) error {
	code, err := otp.Generate(s.cfg.OTPLength)
	if err != nil {
		return err
	}
	if err := s.store.SaveCode(r.Context(), emailAddr, s.hashCode(code), now.Add(s.cfg.OTPTTL)); err != nil {
		return err
	}
	origin := s.publicOrigin()
	s.sendMail("code to "+emailAddr, func(ctx context.Context) error {
		// The message is built here, not before the response: building it
		// reads branding from the store, and a read that only the permitted
		// path performed would be a (small) timing difference from the decoy
		// path.
		return s.sender.Send(ctx, s.buildCodeEmailAt(ctx, emailAddr, code, origin, now))
	})
	return nil
}

// cardGeneration names a card's current code without revealing it: a re-mint
// changes it. It is a digest of the stored hash, cut short, since it travels
// in the offer cookie.
func cardGeneration(code store.BreakGlassCode) string {
	h := sha256.Sum256([]byte("offer-gen\x00" + code.TokenHash))
	return hex.EncodeToString(h[:8])
}

// maxMailSends bounds the emails the gateway sends at once. The rate limits
// slow any one address or network, but nothing else bounds how many sends a
// flood from many networks starts; each holds a goroutine and a connection
// for up to 20 seconds.
const maxMailSends = 16

// sendMail sends an email on a detached goroutine, so the request that asked
// for it is answered without waiting. When maxMailSends are already under
// way, this one is not sent and the refusal is logged: the person can ask
// again, and the gateway stays up for everyone else.
func (s *Server) sendMail(what string, send func(ctx context.Context) error) {
	s.sendMailVia(s.mailSlots, what, send)
}

// mailSaturated reports whether every sign-in mail slot is in use. It reads
// global state only, never the address, so permitted and decoy addresses take
// the same branch.
func (s *Server) mailSaturated() bool { return len(s.mailSlots) >= cap(s.mailSlots) }

// sendNotice sends a security notice (a passkey added) through slots of its
// own, so a flood of sign-in codes cannot crowd it out.
func (s *Server) sendNotice(what string, send func(ctx context.Context) error) {
	s.sendMailVia(s.noticeSlots, what, send)
}

func (s *Server) sendMailVia(slots chan struct{}, what string, send func(ctx context.Context) error) {
	select {
	case slots <- struct{}{}:
	default:
		log.Printf("send %s: not sent, %d emails of this kind are already being sent", what, cap(slots))
		return
	}
	go func() {
		defer func() { <-slots }()
		// Detached context: the originating request is already answered.
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := send(ctx); err != nil {
			log.Printf("send %s: %v", what, err)
		}
	}()
}

// storeDecoyCode persists an unguessable, never-emailed code for an address we
// are deliberately not mailing (not permitted, or over its send limit). It uses
// insert-if-absent so a live code is never overwritten. This keeps /verify-code
// behaviourally identical for permitted and non-permitted addresses — see the
// rationale in handleRequest — so the verify step can't enumerate who may sign in.
func (s *Server) storeDecoyCode(ctx context.Context, emailAddr string, now time.Time) error {
	code, err := otp.Generate(s.cfg.OTPLength)
	if err != nil {
		return err
	}
	// Dated as if issued one cooldown ago, so it does not start the resend
	// cooldown. Otherwise an attacker who burns the owner's code and re-requests
	// over the limit would plant a decoy that makes the owner's own next request
	// a no-op, before allowSend's known-device check could let it through.
	return s.store.EnsureCode(ctx, emailAddr, s.hashCode(code), now.Add(s.cfg.OTPTTL-s.cfg.OTPResendCooldown))
}

// saveDecoyCode is the decoy twin of sendCode: it overwrites any existing code
// for the address with a fresh unguessable one and resets its attempt
// counters, exactly as a permitted address's re-request does, but sends no
// mail. See handleRequest for why the transitions must match.
func (s *Server) saveDecoyCode(ctx context.Context, emailAddr string, now time.Time) error {
	code, err := otp.Generate(s.cfg.OTPLength)
	if err != nil {
		return err
	}
	return s.store.SaveCode(ctx, emailAddr, s.hashCode(code), now.Add(s.cfg.OTPTTL))
}

// hashCode hashes an OTP code for storage. It is keyed (HMAC) with the session
// secret so a stolen database cannot brute-force a live code's small numeric
// space offline. Break-glass tokens are high-entropy and hashed separately.
func (s *Server) hashCode(code string) string {
	return otp.HashKeyed(code, s.cfg.SessionSecret)
}

// restartLogin sends the user back to the login page to start over, carrying
// an already-validated destination when one is known so it survives the
// restart instead of degrading the eventual login to the bare welcome page.
func (s *Server) restartLogin(w http.ResponseWriter, r *http.Request, rd string) {
	loginURL := "/login"
	if rd != "" {
		loginURL += "?rd=" + url.QueryEscape(rd)
	}
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// recordAuth appends a login-flow audit row (best-effort; a failed write is
// logged, never surfaced to the user). The clock comes from s.now so tests on a
// fake clock stay consistent.
func (s *Server) recordAuth(r *http.Request, email, eventType, outcome string) {
	if err := s.store.RecordAuthEvent(r.Context(), store.AuthEvent{
		Email:     email,
		EventType: eventType,
		Outcome:   outcome,
		ClientIP:  clientIP(r),
		UserAgent: clampUserAgent(r.UserAgent()),
		CreatedAt: s.now(),
	}); err != nil {
		log.Printf("record auth event %s/%s for %s: %v", eventType, outcome, email, err)
	}
}

// handleVerifyCode checks the submitted OTP code and, on success, issues a
// session (or starts the admin TOTP step).
func (s *Server) handleVerifyCode(w http.ResponseWriter, r *http.Request) {
	if !s.requireSameOrigin(w, r) {
		return
	}
	now := s.now()
	// The destination rides in two places: the state cookie (set by /request)
	// and a hidden field in the code form. Prefer the validated posted copy —
	// the state cookie is a single host-only cookie, so a second /request in
	// another tab silently overwrites it, while the hidden field follows the
	// tab the user actually completes. The cookie is the fallback and still
	// carries the email and remember flag, which the code form does not post.
	postedRD := authz.SafeRedirect(r.PostFormValue("rd"), s.cfg.Domain, "")
	st, ok := s.sessions.ReadState(r, now)
	if !ok {
		// Second submission after the first already succeeded (double-tap, autofill
		// race, retry on a slow app load): the code is consumed and the state
		// cleared, but the request now carries the freshly issued session. Don't
		// bounce an already-authenticated user back to /login — send them onward.
		if _, ok := s.readSession(r, now); ok {
			http.Redirect(w, r, s.loginRedirect(postedRD), http.StatusFound)
			return
		}
		// No usable state — the cookie only lives for OTP_TTL, so a slow email
		// or a long pause lands here. The user must restart, but the posted rd
		// keeps the destination alive across the restart.
		s.restartLogin(w, r, postedRD)
		return
	}
	rd := postedRD
	if rd == "" {
		rd = st.Redirect
	}
	// While the gateway cannot tell who is staff, the code is left unspent,
	// so the person can enter it again once it can.
	if s.rolesUnavailable(r.Context()) {
		s.renderUnavailable(w, rd)
		return
	}
	// Every attempt is charged up front, so simultaneous guesses cannot all
	// pass the check; a correct code is refunded below, so people signing in
	// behind one hospital NAT spend nothing.
	if !s.wrongCodes.Allow(clientIP(r)) {
		if st.Invite != 0 && s.renderInviteCodeError(w, r, http.StatusTooManyRequests, st, rd, "Too many attempts. Please wait and try again.", false) {
			return
		}
		s.render(w, http.StatusTooManyRequests, "code", pageData{
			Error: "Too many attempts. Please wait and try again.", Email: st.Email, Redirect: rd,
		})
		return
	}

	code := strings.TrimSpace(r.PostFormValue("code"))
	res, err := s.store.ConsumeCode(r.Context(), st.Email, clientIP(r), s.hashCode(code), s.cfg.OTPMaxAttempts, s.cfg.OTPMaxTotalAttempts, now)
	if err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong", Redirect: rd})
		return
	}

	switch res {
	case store.ConsumeOK:
		s.wrongCodes.Refund(clientIP(r))
		if st.Invite != 0 {
			s.acceptInvite(r, st.Invite, st.Email, now)
		}
		// Re-derive "open host" from the destination exactly as /request did. rd
		// is client-influenced (the posted copy wins), so this is not what keeps
		// strangers out: a guest session is the same whichever host minted it,
		// and the boundary is a role guard admitting guests only where an app
		// role is held by guests. The host check only decides where a guest login is offered.
		role := s.loginRole(r.Context(), st.Email, s.isOpenHost(r.Context(), rd))
		if role == authz.RoleDeny {
			s.recordAuth(r, st.Email, store.AuthEventVerify, store.AuthOutcomeDenied)
			s.sessions.ClearState(w)
			s.renderLogin(w, r, http.StatusForbidden, pageData{Error: "This account is not permitted.", Redirect: rd})
			return
		}
		// An emailed code is the first factor only, so the session records
		// totp=false. An administrator signs in like anyone else and is an
		// ordinary user until the admin door (/totp) takes the second step.
		// The step is recorded so the access log can show the sign-in was by
		// email code; a passkey sign-in records its own step.
		s.recordAuth(r, st.Email, store.AuthEventVerify, store.AuthOutcomeOK)
		s.completeLogin(w, r, st.Email, role, rd, st.Remember, false, 0, now)
	case store.ConsumeMismatch:
		s.recordAuth(r, st.Email, store.AuthEventVerify, store.AuthOutcomeWrongCode)
		if st.Invite != 0 && s.renderInviteCodeError(w, r, http.StatusUnauthorized, st, rd, msgInviteWrongCode, false) {
			return
		}
		s.render(w, http.StatusUnauthorized, "code", pageData{
			Error: "Incorrect code. Please try again.", Email: st.Email, Redirect: rd,
		})
	case store.ConsumeTooManyAttempts, store.ConsumeBurned:
		if res == store.ConsumeBurned {
			s.alertAboutCodes(st.Email, codeAlertBurned, now)
		}
		s.recordAuth(r, st.Email, store.AuthEventVerify, store.AuthOutcomeLockedOut)
		s.sessions.ClearState(w)
		if st.Invite != 0 && s.renderInviteCodeError(w, r, http.StatusUnauthorized, st, rd, msgInviteCodeTooMany, true) {
			return
		}
		s.renderLogin(w, r, http.StatusUnauthorized, pageData{
			Error: msgLoginTooMany, Redirect: rd,
		})
	default: // ConsumeExpired, ConsumeNoCode
		s.recordAuth(r, st.Email, store.AuthEventVerify, store.AuthOutcomeExpired)
		s.sessions.ClearState(w)
		if st.Invite != 0 && s.renderInviteCodeError(w, r, http.StatusUnauthorized, st, rd, "Your code has expired. Please request a new one.", true) {
			return
		}
		s.renderLogin(w, r, http.StatusUnauthorized, pageData{
			Error: "Your code has expired. Please request a new one.", Redirect: rd,
		})
	}
}

// completeLogin bakes the group set, issues the session cookie (using the
// remember-me lifetime when requested), and redirects to the target. totpVerified
// records whether the admin second factor was satisfied for this login, so a
// later /verify can tell a fully-authenticated admin session from a
// first-factor-only one (see needsAdminStepUp). pk is the passkey the person
// signed in with, zero for an email code; the session names it so that
// removing the passkey ends the session at its next renewal.
func (s *Server) completeLogin(w http.ResponseWriter, r *http.Request, emailAddr, role, rd string, remember, totpVerified bool, pk int64, now time.Time) {
	// The admin tier needs the second step; without it an administrator's
	// session is built as an ordinary user's (see tierRole).
	next := session.Identity{Email: emailAddr, PK: pk}
	if totpVerified {
		next.TOTP, next.Step = true, now.Unix()
	}
	next.Groups = s.computeGroups(r.Context(), emailAddr, s.tierRole(&next, role))
	// The kind follows the role: a guest login is marked so /verify confines it
	// to routes that opt in, and renewal keeps it a guest. A member (signed in
	// by an app role) is marked so that a role guard decides it by its roles
	// and drops the staff-only lists from its groups at every request.
	kind := ""
	switch role {
	case authz.RoleGuest:
		kind = session.KindGuest
	case authz.RoleMember:
		kind = session.KindMember
	}
	// A guest never gets the remember-me lifetime, which bounds how long an
	// unwanted guest holds a session that nobody has ended.
	ttl := s.cfg.SessionTTL
	if remember && kind != session.KindGuest {
		ttl = s.cfg.SessionRememberTTL
	}
	next.Kind = kind
	if err := s.startSession(w, r, next, ttl, now); err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong", Redirect: rd})
		return
	}
	// The single success funnel for human logins (both code-only and
	// TOTP-completed); break-glass grants issue their session separately and are
	// audited in break_glass_events instead.
	s.recordAuth(r, emailAddr, store.AuthEventLogin, store.AuthOutcomeOK)
	s.sessions.ClearState(w)
	s.sessions.ClearPending(w)
	// On a phone, after an email code, offer to add a passkey before going on.
	// An administrator is offered one at the admin door instead, where the
	// authenticator code makes it a passkey that can open the admin pages.
	if !(role == authz.RoleAdmin && s.cfg.TOTPEnabled) && s.shouldOfferPasskey(r, role, pk) && s.offerPasskey(w, r, emailAddr, rd) {
		return
	}
	http.Redirect(w, r, s.loginRedirect(rd), http.StatusFound)
}
