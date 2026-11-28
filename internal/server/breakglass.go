// Break-glass card sign-in: scanning a card and activating its session.

package server

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/breakglass"
	"github.com/uppertoe/vps-scaffold-auth/internal/otp"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// handleBreakGlass grants emergency access from a card, once the person has
// pressed the button on the scan's page. It is public (the token in the form
// is the only credential, by design), instant (no second factor), rate-limited
// per IP, audited synchronously, and notifies admins asynchronously. The
// granted session is short-lived and never renewed. The same-origin check
// keeps a sibling app on the domain, which might hold a card's token, from
// posting it into a visitor's browser.
func (s *Server) handleBreakGlass(w http.ResponseWriter, r *http.Request) {
	if !s.requireSameOrigin(w, r) {
		return
	}
	now := s.now()
	ip := clientIP(r)
	ua := clampUserAgent(r.UserAgent())
	// Break-glass scans use their own, more permissive per-IP limiter: the token's
	// 128-bit entropy is the brute-force boundary here, so this only guards against
	// abuse and must not throttle many staff scanning from behind one shared IP
	// during an emergency.
	if !s.breakLimiter.Allow(ip) {
		s.breakTooMany(w)
		return
	}
	code, ok := s.activeCard(w, r, r.PostFormValue("token"), ip, ua)
	if !ok {
		return
	}
	// A card made for a group opens nothing. grantBreakGlass checks again
	// for the one-tap activation; checking here as well keeps the denial
	// page from offering such a card.
	if s.refuseGroupCard(w, r, code, ip, ua) {
		return
	}

	// If the scanner already holds a normal (non-break-glass) session, don't
	// clobber it with a scoped, short-lived emergency one. Send them to the
	// resource on their own identity and let its own /verify decide — that is the
	// only place that knows the resource's full policy (its domain gate lives in
	// the app's Caddy snippet, invisible here). Carry a short-lived signed offer
	// so that, if their identity is refused there, the denial page can grant
	// emergency access in one tap without a re-scan. An existing break-glass
	// session has no richer identity worth preserving, so it falls through to a
	// fresh grant. A guest session is treated the same way: the denial page never
	// offers a guest the one-tap grant (see handleDenied), so deferring would
	// strand them, and a guest login is cheap to redo.
	if id, ok := s.readSession(r, now); ok && id.Kind == "" {
		rd := authz.SafeRedirect(code.Redirect, s.cfg.Domain, s.cfg.BreakGlassRedirect)
		if err := s.sessions.SetOffer(w, session.Offer{CodeID: code.ID, Label: code.Label, Gen: cardGeneration(code)}, s.cfg.OTPTTL, now); err != nil {
			// Non-fatal: fall through to a normal grant rather than fail the scan.
			log.Printf("break-glass set offer: %v", err)
		} else {
			// Audit the deferred scan so the trail still shows the card was used,
			// then send them on with their existing session intact. Best-effort: no
			// access is granted here, so a failed write can't mask a privilege change
			// (unlike the grant path, which fails closed), but log it rather than
			// swallow it so a persistently failing store is visible.
			if err := s.store.RecordBreakGlassEvent(r.Context(), store.BreakGlassEvent{
				CodeID: code.ID, Label: code.Label, ClientIP: ip,
				UserAgent: ua, Outcome: store.OutcomeRedirected,
			}); err != nil {
				log.Printf("break-glass record redirected event for %q: %v", code.Label, err)
			}
			log.Printf("break-glass redirect (existing session) for %q from %s", code.Label, ip)
			http.Redirect(w, r, s.loginRedirect(rd), http.StatusFound)
			return
		}
	}

	s.grantBreakGlass(w, r, code, ip, ua, now)
}

func (s *Server) breakTooMany(w http.ResponseWriter) {
	s.render(w, http.StatusTooManyRequests, "message", pageData{
		Title:   "Too many requests",
		Message: "Please wait a little while and try again.",
	})
}

// activeCard looks up the card a token names. An unknown or revoked card
// gets the same neutral page either way, and a revoked one is audited; ok is
// false once a response has been written.
func (s *Server) activeCard(w http.ResponseWriter, r *http.Request, token, ip, ua string) (store.BreakGlassCode, bool) {
	if token == "" {
		s.cardNotAvailable(w)
		return store.BreakGlassCode{}, false
	}
	code, ok, err := s.store.LookupBreakGlassByTokenHash(r.Context(), otp.Hash(token))
	if err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong"})
		return store.BreakGlassCode{}, false
	}
	if !ok || code.Status != store.BreakGlassActive {
		outcome := store.OutcomeUnknown
		if ok {
			outcome = store.OutcomeRevoked
			// Audit a stale-card scan against the known code.
			_ = s.store.RecordBreakGlassEvent(r.Context(), store.BreakGlassEvent{
				CodeID: code.ID, Label: code.Label, ClientIP: ip,
				UserAgent: ua, Outcome: outcome,
			})
		}
		log.Printf("break-glass denied (%s) from %s", outcome, ip)
		s.cardNotAvailable(w)
		return store.BreakGlassCode{}, false
	}
	return code, true
}

func (s *Server) cardNotAvailable(w http.ResponseWriter) {
	s.render(w, http.StatusNotFound, "message", pageData{
		Title: msgCardUnknownTitle, Message: msgCardUnknownBody, LinkText: msgCardUnknownLink,
	})
}

// refuseGroupCard refuses a card made for a group before app roles, which
// names no app. Such a card opens nothing, since every site is guarded by
// app roles; it stays listed until an administrator withdraws it. The scan
// is audited, and the person scanning sees the same neutral page as for a
// withdrawn card. A card for any role other than User is refused the same
// way, although none can be made. It reports whether it refused.
func (s *Server) refuseGroupCard(w http.ResponseWriter, r *http.Request, code store.BreakGlassCode, ip, ua string) bool {
	if code.App != "" && code.Role == store.RoleUser {
		return false
	}
	if err := s.store.RecordBreakGlassEvent(r.Context(), store.BreakGlassEvent{
		CodeID: code.ID, Label: code.Label, ClientIP: ip,
		UserAgent: ua, Outcome: store.OutcomeRefusedTarget,
	}); err != nil {
		log.Printf("break-glass record refused event for %q: %v", code.Label, err)
	}
	log.Printf("break-glass refused (the card names no app) for %q from %s", code.Label, ip)
	s.cardNotAvailable(w)
	return true
}

// grantBreakGlass mints an emergency session for an active code: it writes the
// source-of-truth audit row (before granting), notifies admins out of band, and
// issues the short-lived, never-renewed break-glass session, then redirects to
// the code's resource. Shared by a direct scan (handleBreakGlass, when there is
// no existing login) and the one-tap activation from the denial page
// (handleBreakGlassActivate).
func (s *Server) grantBreakGlass(w http.ResponseWriter, r *http.Request, code store.BreakGlassCode, ip, ua string, now time.Time) {
	if s.refuseGroupCard(w, r, code, ip, ua) {
		return
	}
	// Source-of-truth audit, written before granting.
	if err := s.store.RecordBreakGlassEvent(r.Context(), store.BreakGlassEvent{
		CodeID: code.ID, Label: code.Label, ClientIP: ip,
		UserAgent: ua, Outcome: store.OutcomeGranted,
	}); err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong"})
		return
	}

	// Resolve runtime settings (admin overrides, else env defaults).
	ttl, notifyEmails, webhookURL := s.effectiveSettings(r.Context())

	// Notify admins out of band so a slow mail server or webhook never delays
	// the emergency grant.
	breakglass.NewNotifier(s.sender, notifyEmails, webhookURL, s.cfg.BreakGlassWebhookTimeout).
		Notify(breakglass.UseEvent{
			Label: code.Label, Outcome: store.OutcomeGranted,
			ClientIP: ip, UserAgent: ua, Time: now,
		})

	// A card's session carries no groups: it holds only the card's app role
	// (roles.Held), and a session that carries a group is one an earlier
	// release started from a group card, which holds nothing (cardIssuedAsNow).
	principal := "breakglass:" + code.Label
	if err := s.startSession(w, r, session.Identity{Email: principal, Kind: session.KindBreakGlass, Card: code.ID, CardCode: code.TokenHash}, ttl, now); errors.Is(err, errGrantGone) {
		// Withdrawn or replaced while this scan was under way.
		s.cardNotAvailable(w)
		return
	} else if err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong"})
		return
	}
	rd := authz.SafeRedirect(code.Redirect, s.cfg.Domain, s.cfg.BreakGlassRedirect)
	http.Redirect(w, r, s.loginRedirect(rd), http.StatusFound)
}

// handleBreakGlassActivate mints the emergency session from a pending offer: the
// one-tap follow-through when someone scanned a card while already signed in and
// their normal identity was then refused at the resource (see handleBreakGlass).
// POST-only + CSRF-checked: the offer cookie alone is NOT sufficient authority,
// because SameSite=Lax is site- not origin-scoped — a sibling app on the same
// registrable domain (planka., handbook., …) is same-site with the auth host, so
// Lax would send the offer cookie on a cross-origin POST it forged. The
// double-submit CSRF token (minted into the denial-page form, unreadable
// cross-origin) is the real defense; without it a malicious sibling could force a
// session downgrade + a spoofed "granted" audit row against a signed-in user. The
// code id from the offer is re-looked-up and re-checked active, so a card revoked
// between scan and tap grants nothing, and neither does a card RE-MINTED in that
// window: the offer names the code it was made from (cardGeneration), and a
// re-mint ends the card's sessions, so it ends a pending offer too.
func (s *Server) handleBreakGlassActivate(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	ip := clientIP(r)
	ua := clampUserAgent(r.UserAgent())
	if !s.breakLimiter.Allow(ip) {
		s.render(w, http.StatusTooManyRequests, "message", pageData{
			Title:   "Too many requests",
			Message: "Please wait a little while and try again.",
		})
		return
	}
	if !s.sessions.VerifyCSRF(r, r.PostFormValue("csrf"), now) {
		s.render(w, http.StatusForbidden, "message", pageData{
			Title:   "Request rejected",
			Message: "This emergency-access request could not be verified. Please scan the code again.",
		})
		return
	}

	offer, ok := s.sessions.ReadOffer(r, now)
	if !ok {
		// No/expired offer: nothing to activate. Send them to sign in.
		s.restartLogin(w, r, "")
		return
	}
	// Consume the offer regardless of the outcome below, so a dead or single-use
	// offer can't be re-submitted.
	s.sessions.ClearOffer(w)

	// Require a live normal session to activate. The offer flow exists only to
	// preserve an existing normal session; if it is gone (expired since the scan)
	// or is itself break-glass, there is nothing to preserve. This also closes the
	// one case where the session-bound CSRF token degrades to the empty subject: a
	// session-less browser, into which a same-site sibling holding a card token
	// could otherwise force emergency access (and a spoofed grant audit row). A
	// session-less user should re-scan the physical code, which grants directly.
	if id, ok := s.readSession(r, now); !ok || id.Kind != "" {
		s.render(w, http.StatusForbidden, "message", pageData{
			Title:   "Please scan the code again",
			Message: "Your sign-in is no longer active. Scan the emergency code again to get access.",
		})
		return
	}

	code, ok, err := s.store.GetBreakGlassCode(r.Context(), offer.CodeID)
	if err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong"})
		return
	}
	// A re-mint replaces the card's code and ends its sessions, so an offer
	// made from the old code is refused like a revoked card.
	if !ok || code.Status != store.BreakGlassActive || offer.Gen != cardGeneration(code) {
		log.Printf("break-glass activate denied (inactive, unknown or re-minted code %d) from %s", offer.CodeID, ip)
		s.cardNotAvailable(w)
		return
	}

	s.grantBreakGlass(w, r, code, ip, ua, now)
}
