package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/breakglass"
	"github.com/uppertoe/vps-scaffold-auth/internal/otp"
	"github.com/uppertoe/vps-scaffold-auth/internal/secretbox"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
	"github.com/uppertoe/vps-scaffold-auth/internal/totp"
)

// handleVerify is the forward_auth target. Caddy calls it on every request to a
// protected app. A valid session yields 200 + identity headers; otherwise the
// user is redirected to the login page.
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	if id, ok := s.sessions.ReadSession(r, now); ok {
		// Fail closed on a kind this build does not know. The kind is inside the
		// signed envelope, so only this service can mint one, but a cookie left by
		// a newer build (a rollback, or two versions sharing SESSION_SECRET) must
		// not be read as a normal session and waved through a bare `protected`:
		// CanAccessApp treats anything that is neither break-glass nor guest as
		// a department login. Such a session is cleared and sent to sign in.
		if !knownSessionKind(id.Kind) {
			s.sessions.ClearSession(w)
			s.redirectToLogin(w, r)
			return
		}
		if s.sessions.NeedsRenew(id, now) {
			// Re-check policy at renewal so access revocation actually takes
			// effect: a principal who is no longer permitted (removed from the
			// admin list, or whose domain was de-listed) has their session
			// cleared instead of silently extended. Recomputing groups also
			// picks up membership and demotion changes. Break-glass sessions
			// never reach here (NeedsRenew is false for them).
			role := s.renewalRole(id)
			if role == authz.RoleDeny {
				s.sessions.ClearSession(w)
				s.redirectToLogin(w, r)
				return
			}
			// Re-challenge for the admin second factor before extending the
			// session: an admin whose cookie predates TOTP being enabled — or a
			// principal only just promoted to admin — carries totp=false and must
			// complete the TOTP step rather than sliding forward on the email code
			// alone. Clearing + redirecting sends them through the normal login,
			// which runs startTOTP for an admin when TOTP is enabled.
			if s.needsAdminStepUp(role == authz.RoleAdmin, id.TOTP) {
				s.sessions.ClearSession(w)
				s.redirectToLogin(w, r)
				return
			}
			groups := s.computeGroups(r.Context(), id.Email, role)
			// id.Kind is passed through, so a guest stays a guest across renewals
			// (and so stays confined to guests=allow routes).
			_ = s.sessions.IssueSessionTTL(w, id.Email, groups, id.Kind, id.TOTP, s.sessions.SessionTTL(id), now)
			// Reflect the freshly computed set in this response too, not just
			// the renewed cookie, so a demotion takes effect immediately.
			id.Groups = groups
		} else if s.needsAdminStepUp(isAdminSession(id), id.TOTP) {
			// Not yet due for renewal, but an existing admin session that lacks the
			// second factor (TOTP was enabled after it was minted) must step up now
			// rather than riding a first-factor-only cookie for up to
			// SESSION_RENEW_AFTER. Break-glass and guest sessions are excluded
			// (never admin).
			s.sessions.ClearSession(w)
			s.redirectToLogin(w, r)
			return
		}
		// Per-app authorization. The app's Caddy snippet declares who may reach it
		// in a single X-Auth-Policy header set with header_up (replace semantics),
		// so a client can't inject or widen it; the gateway enforces the union. An
		// authenticated-but-unallowed principal is sent to a denial page, NOT back
		// to login — they are already signed in; logging in again wouldn't help and
		// would clobber a working (e.g. break-glass) session. Their cookie is left
		// untouched, so access to apps they *are* allowed on keeps working.
		policy := r.Header.Get(headerPolicy)
		s.warnLegacyPolicy(r)
		reqDomains, reqGroups, allowGuests, ok := parsePolicy(policy)
		if !ok {
			// Fail closed: every shipped guard declares a policy in the exact
			// grammar (the plain `protected` door sends the explicit "any"
			// sentinel). A /verify with no X-Auth-Policy, an empty allow-list or
			// a misspelled field is a misconfigured or hand-rolled guard. Denying
			// is the only safe reading: "domains=" or "gruops=admin" must never
			// collapse into "any signed-in user".
			log.Printf("warning: refusing malformed X-Auth-Policy %q for %q", policy, r.Header.Get("X-Forwarded-Host"))
			s.redirectToDenied(w, r)
			return
		}
		if !authz.CanAccessApp(id.Email, id.Groups, id.Kind == session.KindBreakGlass, id.Kind == session.KindGuest,
			reqDomains, reqGroups, allowGuests) {
			s.redirectToDenied(w, r)
			return
		}
		// Audit that this principal reached this app, deduplicated to one row per
		// hour so the per-request hot path stays a memory lookup (see accessAudit).
		s.access.record(r.Context(), id.Email, r.Header.Get("X-Forwarded-Host"), id.Kind, now)
		// These headers are the identity passed to the upstream app. Caddy
		// strips any client-supplied copies before re-adding ours.
		w.Header().Set("Remote-User", id.Email)
		w.Header().Set("Remote-Email", id.Email)
		w.Header().Set("Remote-Groups", id.Groups)
		w.WriteHeader(http.StatusOK)
		return
	}

	// A single session cookie that is present but unreadable (expired, or
	// minted by an earlier build) is cleared on the way to login. Otherwise it
	// lingers, and an app route that treats "has a session cookie" as "signed
	// in" (p.stonn.org sends such visitors from / to the gated schedule) keeps
	// bouncing a returning visitor to login instead of showing them the
	// landing page. The clearing Set-Cookie rides on this 302, which the Caddy
	// gate copies to the browser unchanged. Two cookies by this name (one
	// planted by a sibling host) are left alone: the clear carries the shared
	// Domain, so it would delete the visitor's real cookie and leave the
	// planted one, turning a one-app nuisance into a sign-out everywhere.
	n := 0
	for _, ck := range r.Cookies() {
		if ck.Name == session.SessionCookie {
			n++
		}
	}
	if n == 1 {
		s.sessions.ClearSession(w)
	}
	s.redirectToLogin(w, r)
}

// redirectToLogin sends an unauthenticated request to the login page,
// preserving the originally-requested URL as a validated redirect target.
func (s *Server) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	orig := s.reconstructOriginalURL(r)
	rd := authz.SafeRedirect(orig, s.cfg.Domain, s.cfg.DefaultRedirect)
	loginURL := s.cfg.PublicURL + "/login?rd=" + url.QueryEscape(rd)
	// Carry the app's required domain(s) (from the X-Auth-Policy header its Caddy
	// snippet set on this /verify subrequest) into the login URL, so the login
	// page can hint the expected domain and /request can decline a non-matching
	// address early. UX only — see the note in handleRequest; enforcement remains
	// in handleVerify. A group-only route (admin/collaborator door) declares no
	// domain, so nothing is carried and it neither hints nor declines.
	reqDomains, reqGroups, _, _ := parsePolicy(r.Header.Get(headerPolicy))
	if v := clampHint(reqDomains); v != "" {
		loginURL += "&rqd=" + url.QueryEscape(v)
		// Optional friendly label to display instead of enumerating domains.
		if lbl := clampHint(r.Header.Get(headerDomainLabel)); lbl != "" {
			loginURL += "&dlabel=" + url.QueryEscape(lbl)
		}
	} else if g := clampHint(reqGroups); g != "" {
		// Group-only route (admin/collaborator door): no domain to hint, but carry
		// that this IS a gated route so the login page suppresses the configured-
		// domain fallback hint/placeholder — this door is deliberately for people
		// who can't match the domain.
		loginURL += "&rqg=" + url.QueryEscape(g)
	}
	// Optional alternate-entrance link (set by the app's snippet). Validated to
	// be within the server domain before it is carried, so it can't become an
	// off-domain link on the login page.
	if alt, ok := authz.ValidateRedirect(clampHint(r.Header.Get(headerAltLogin)), s.cfg.Domain); ok {
		loginURL += "&alt=" + url.QueryEscape(alt)
		if label := clampHint(r.Header.Get(headerAltLabel)); label != "" {
			loginURL += "&altlabel=" + url.QueryEscape(label)
		}
	}
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// redirectToDenied sends an authenticated-but-unauthorized request to the
// gateway-hosted denial page (on the auth host, so its logo, styles, and the
// sign-in link all resolve correctly), carrying the app they were trying to
// reach so the page's sign-in button returns them there afterwards.
func (s *Server) redirectToDenied(w http.ResponseWriter, r *http.Request) {
	orig := s.reconstructOriginalURL(r)
	rd := authz.SafeRedirect(orig, s.cfg.Domain, s.cfg.DefaultRedirect)
	http.Redirect(w, r, s.cfg.PublicURL+"/denied?rd="+url.QueryEscape(rd), http.StatusFound)
}

// handleDenied renders the "signed in, but no access to this app" page. It is
// served on the auth host (reached via the redirect from /verify), reads the
// session only to tailor the message, and always offers a prominent sign-in
// link — essential for non-technical users who would otherwise be stuck. It
// never clears the session, so the user keeps access to apps they are allowed
// on.
func (s *Server) handleDenied(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	rd := authz.SafeRedirect(r.URL.Query().Get("rd"), s.cfg.Domain, s.cfg.DefaultRedirect)
	data := pageData{
		Redirect: rd,
		LoginURL: s.cfg.PublicURL + "/login?rd=" + url.QueryEscape(rd),
	}
	normalSession := false
	if id, ok := s.sessions.ReadSession(r, now); ok {
		switch id.Kind {
		case session.KindBreakGlass:
			data.BreakGlass = true
			// principal is "breakglass:<label>"; show the human label.
			data.Identity = strings.TrimPrefix(id.Email, "breakglass:")
		case session.KindGuest:
			// A guest is told plainly what they are signed in as and that this page
			// wants an approved address. The way forward is to sign out and back in
			// with that address, so the button is sign-out (carrying rd, so the
			// login page returns them here). No emergency offer: the one-tap grant
			// exists to spare a department login, which a guest session is not.
			data.Guest = true
			data.Identity = id.Email
			data.LogoutURL = s.logoutURL(rd)
		default:
			data.Identity = id.Email
			normalSession = true
		}
	}
	// Surface the one-tap emergency-access button only to someone who arrived with
	// a pending offer AND still holds a normal session — the session the offer flow
	// exists to preserve, and the (non-empty) subject the activation's CSRF token
	// binds to. A session-less visitor (e.g. their session expired since the scan)
	// is not offered it: they should re-scan the physical code, which grants
	// directly. This keeps activation off the empty-subject CSRF path.
	if normalSession {
		if offer, ok := s.sessions.ReadOffer(r, now); ok {
			data.EmergencyOffer = true
			data.EmergencyLabel = offer.Label
			// Mint/return the CSRF token for the activation form. Must run before
			// render writes the status line (EnsureCSRF sets a cookie). A failure
			// here just leaves CSRF empty, so the POST is rejected — fail closed.
			if tok, err := s.sessions.EnsureCSRF(w, r, csrfTTL, now); err == nil {
				data.CSRF = tok
			}
		}
	}
	s.render(w, http.StatusForbidden, "denied", data)
}

// handleLogin renders the email-entry page.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Empty fallback (not DEFAULT_REDIRECT): a direct visit with no app rd must
	// stay empty so completeLogin can land on the auth-host signed-in page rather
	// than bouncing to a default that may be unservable (see loginRedirect).
	rd := authz.SafeRedirect(r.URL.Query().Get("rd"), s.cfg.Domain, "")
	data := pageData{Redirect: rd, RequireGroups: clampHint(r.URL.Query().Get("rqg"))}
	applyAccessHint(&data, r.URL.Query().Get("rqd"), r.URL.Query().Get("dlabel"))
	s.applyAltLogin(&data, r.URL.Query().Get("alt"), r.URL.Query().Get("altlabel"))
	s.render(w, http.StatusOK, "login", data)
}

// applyAccessHint records the app's required domain(s) and optional display
// label (carried from the /verify redirect) on the page so they survive to
// /request as hidden fields, and sets the human hint string. It fires whenever a
// domain is declared — a group-only route (admin/collaborator door) carries
// none, so it gets no hint and no early decline.
func applyAccessHint(d *pageData, rqd, label string) {
	rqd, label = clampHint(rqd), clampHint(label)
	d.RequireDomains = rqd
	d.RequireDomainLabel = label
	if rqd != "" {
		d.HintDomains = domainLabel(rqd, label)
	}
}

// applyLoginBranding fills the domain-derived UX fields on the login page from
// the configured ALLOWED_EMAIL_DOMAINS, so a DIRECT visit (no route rqd) still
// tells the user which domain to use. It runs after applyAccessHint, so a
// route-supplied requirement (HintDomains/RequireDomains) always wins; this only
// fills the gaps:
//   - HintDomains: the "This page is for <domains> email addresses" line, from
//     the allow-list when no route set one.
//   - EmailPlaceholder: you@<first effective domain> — the route requirement if
//     present, else the first allow-list domain — so the example matches who may
//     sign in. Left empty (→ generic placeholder) when no domain is configured.
func (s *Server) applyLoginBranding(d *pageData) {
	// A group-gated door declares no domain on purpose (it's the entrance for
	// people who can't match one), so never presume the allow-list here.
	if d.RequireGroups != "" {
		return
	}
	// Open registration accepts any domain, so there is no domain to advertise:
	// leave the hint empty and fall back to the generic placeholder. (A route may
	// still have set RequireDomains/HintDomains above; those win and are kept.)
	// The same holds for a login headed to an open-registration host, where a
	// stranger's address is welcome as a guest.
	if s.policy.OpenRegistration() || s.isOpenHost(d.Redirect) {
		if d.EmailPlaceholder == "" {
			if dom := firstDomain(d.RequireDomains); dom != "" {
				d.EmailPlaceholder = "you@" + dom
			}
		}
		return
	}
	if d.HintDomains == "" && len(s.cfg.AllowedDomains) > 0 {
		d.HintDomains = formatDomains(strings.Join(s.cfg.AllowedDomains, ","))
	}
	if d.EmailPlaceholder == "" {
		dom := firstDomain(d.RequireDomains)
		if dom == "" && len(s.cfg.AllowedDomains) > 0 {
			dom = s.cfg.AllowedDomains[0]
		}
		if dom != "" {
			d.EmailPlaceholder = "you@" + dom
		}
	}
}

// firstDomain returns the first domain from a comma/space/semicolon-separated
// list (the raw route requirement), lower-cased; "" when the list is empty.
func firstDomain(s string) string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';' || r == '\n' || r == '\r' || r == '\t'
	})
	if len(fields) == 0 {
		return ""
	}
	return strings.ToLower(fields[0])
}

// domainLabel is the human display of a route's domain requirement: the
// app-supplied label when set (e.g. "an approved Victorian health service"),
// otherwise the enumerated domain list. Keeps the long-list case readable while
// the precise list still governs the actual hint/decline logic.
func domainLabel(rqd, label string) string {
	if label != "" {
		return label
	}
	return formatDomains(rqd)
}

// clampHint trims and bounds a UX hint value carried in the login URL.
func clampHint(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 512 {
		return ""
	}
	return s
}

// applyAltLogin sets an optional "sign in another way" link on the page — for
// users who can't match the domain (e.g. admins routed to a separate door). The
// URL is carried in the (client-modifiable) login URL, so it is validated to be
// an https URL within the server domain before rendering; an external or
// malformed value is dropped, so this can never become a phishing link on the
// trusted login page. The label is shown verbatim (auto-escaped by the
// template) with a neutral default.
func (s *Server) applyAltLogin(d *pageData, rawURL, rawLabel string) {
	u, ok := authz.ValidateRedirect(clampHint(rawURL), s.cfg.Domain)
	if !ok {
		return
	}
	d.AltLoginURL = u
	d.AltLoginLabel = clampHint(rawLabel)
	if d.AltLoginLabel == "" {
		d.AltLoginLabel = "Sign in another way"
	}
}

// formatDomains renders a space/comma-separated domain list for display.
func formatDomains(s string) string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';' || r == '\n' || r == '\r' || r == '\t'
	})
	return strings.ToLower(strings.Join(fields, ", "))
}

// handleRoot handles a bare hit to the auth host. An already-signed-in visitor
// (no app destination — they just typed the host) is sent to the signed-in
// /welcome landing rather than the login form, which would be confusing to show
// to someone already authenticated; everyone else goes to /login. Anything other
// than "/" is a 404.
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if _, ok := s.sessions.ReadSession(r, s.now()); ok {
		http.Redirect(w, r, "/welcome", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

// requireSameOrigin refuses a login-flow POST that a browser reports as coming
// from another origin, and writes the refusal. The sign-in forms carry no CSRF
// token (there is no session to bind one to), and SameSite=Lax does not help
// against a sibling host on the same site: the session cookie is shared across
// *.DOMAIN precisely so that every app can use it, which also means any app on
// the domain could drive a visitor's browser through /request and /verify-code
// with a code the app's operator requested for an address of their choosing,
// leaving that browser signed in as someone else. Browsers send Origin on every
// cross-origin form POST and Sec-Fetch-Site on every request, so a value that
// is not this host is refused; a request carrying neither header (an old client,
// a script) is let through, since those are not the browsers this protects.
//
// Origin: null is NOT a foreign origin. Under the sign-in page's no-referrer
// policy, browsers (mobile Safari, Chrome and Firefox consistently) serialise
// the Origin of a same-origin navigation POST as the literal "null" rather than
// omitting it, so the literal must fall through to the Sec-Fetch-Site test,
// which is the reliable signal: same-origin and none pass, same-site and
// cross-site are refused. A sibling host's form post still arrives as
// same-site, so the protection holds. Refusing "null" took every mobile
// sign-in down on 2026-10-11.
//
// Accepted residual: a browser that sends Origin: null but no Sec-Fetch-Site
// at all (Safari and iOS WebKit up to 16.3, older WebViews) passes a
// cross-site top-level POST from a no-referrer page. Against /logout that
// forces a sign-out and nothing more; against /request it lands the visitor
// on a code page for the poster's address; /verify-code and /totp cannot
// complete because the host-only SameSite=Lax state and pending cookies are
// not sent on a cross-site POST in any browser that enforces SameSite.
func (s *Server) requireSameOrigin(w http.ResponseWriter, r *http.Request) bool {
	if origin := r.Header.Get("Origin"); origin != "" && origin != "null" && !strings.EqualFold(strings.TrimRight(origin, "/"), s.publicOrigin()) {
		s.refuseCrossOrigin(w)
		return false
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
		return true
	}
	s.refuseCrossOrigin(w)
	return false
}

// publicOrigin is scheme://host[:port] of AUTH_PUBLIC_URL, the only origin the
// sign-in forms are served from.
func (s *Server) publicOrigin() string {
	u, err := url.Parse(s.cfg.PublicURL)
	if err != nil || u.Host == "" {
		return s.cfg.PublicURL
	}
	// A browser's Origin omits the scheme's default port, so an explicit
	// ":443" or ":80" in AUTH_PUBLIC_URL must not make every sign-in post
	// look cross-origin.
	host := u.Host
	if p := u.Port(); (u.Scheme == "https" && p == "443") || (u.Scheme == "http" && p == "80") {
		host = strings.TrimSuffix(u.Host, ":"+p) // keeps an IPv6 literal's brackets
	}
	return u.Scheme + "://" + host
}

func (s *Server) refuseCrossOrigin(w http.ResponseWriter) {
	s.render(w, http.StatusForbidden, "message", pageData{
		Title:   "Please start from the sign-in page",
		Message: "This request did not come from the sign-in page, so it has not been acted on. Open the sign-in page and try again.",
	})
}

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
	dlabel := clampHint(r.PostFormValue("dlabel"))
	rqg := clampHint(r.PostFormValue("rqg"))
	alt, altLabel := r.PostFormValue("alt"), r.PostFormValue("altlabel")

	if !validEmail(emailAddr) {
		data := pageData{Error: "Please enter a valid email address.", Redirect: rd, Remember: remember, RequireGroups: rqg}
		applyAccessHint(&data, rqd, dlabel)
		s.applyAltLogin(&data, alt, altLabel)
		s.render(w, http.StatusBadRequest, "login", data)
		return
	}

	// UX-only early decline: when the route declares a required domain, an
	// address whose domain isn't accepted can never get in here, so say so now
	// instead of emailing a code that would be rejected after login. Users who
	// legitimately don't match the domain (admins, collaborators) belong on a
	// separate group-only route, which declares no domain and so never declines.
	// This is a courtesy, NOT a security boundary: rqd rides in the
	// (client-modifiable) login URL, so the authoritative check stays in
	// handleVerify with Caddy's trusted header_up.
	if rqd != "" && !authz.CanAccessApp(emailAddr, "", false, false, rqd, "", false) {
		data := pageData{
			Error:    "This app is only available to " + domainLabel(rqd, dlabel) + " email addresses. Please sign in with one of those.",
			Redirect: rd, Remember: remember, RequireGroups: rqg,
		}
		applyAccessHint(&data, rqd, dlabel)
		s.applyAltLogin(&data, alt, altLabel)
		s.render(w, http.StatusForbidden, "login", data)
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
	// attempt cap — a difference that leaks allow-list membership, and thus which
	// off-domain addresses are admins. Either branch falls through to the same
	// response. EnsureCode is insert-if-absent, so a rate-limited permitted user's
	// live code is never overwritten.
	//
	// "Permitted" includes a would-be guest: when rd points at an open-
	// registration host, any syntactically valid public address is sent a real
	// code (LoginRole returns RoleGuest). That leaks nothing, since on such a host
	// everyone is mailed; on every other host the decoy behaviour is unchanged.
	//
	// Both kinds of address go through the SAME cooldown, send-limit and
	// counter transitions; the only difference is whether mail is sent. A
	// decoy that kept its attempt counter across a re-request while a real
	// code's was reset (or that never spent a send token) would answer the
	// next wrong guess differently, and that difference is allow-list
	// membership.
	permitted := s.policy.LoginRole(emailAddr, s.isOpenHost(rd)) != authz.RoleDeny
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
	case recent:
		// No-op: a live code was issued within the cooldown. Don't mint, don't
		// email, don't spend a send token. The existing code's attempt counter
		// stays intact, so a re-request can't reset the brute-force cap — which
		// is the guard that survives back-button / refresh / new-tab.
	case s.emailLimiter.Allow(emailAddr):
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

	if err := s.sessions.SetState(w, session.State{Email: emailAddr, Redirect: rd, Remember: remember}, s.cfg.OTPTTL, now); err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong", Redirect: rd})
		return
	}
	s.render(w, http.StatusOK, "code", pageData{Email: emailAddr, Redirect: rd, Remember: remember})
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
	go func() {
		// Detached context: the originating request is already answered. The
		// message is built here too, not before the response: building it reads
		// branding from the store, and a read that only the permitted path
		// performed would be a (small) timing difference from the decoy path.
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		msg := s.buildCodeEmail(ctx, emailAddr, code)
		if err := s.sender.Send(ctx, msg); err != nil {
			log.Printf("send code to %s: %v", emailAddr, err)
		}
	}()
	return nil
}

// storeDecoyCode persists an unguessable, never-emailed code for an address we
// are deliberately not mailing (not permitted, or over its send limit). It uses
// insert-if-absent so a live code is never overwritten. This keeps /verify-code
// behaviourally identical for permitted and non-permitted addresses — see the
// rationale in handleRequest — so the verify step can't enumerate the allow-list.
func (s *Server) storeDecoyCode(ctx context.Context, emailAddr string, now time.Time) error {
	code, err := otp.Generate(s.cfg.OTPLength)
	if err != nil {
		return err
	}
	return s.store.EnsureCode(ctx, emailAddr, s.hashCode(code), now.Add(s.cfg.OTPTTL))
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
		if _, ok := s.sessions.ReadSession(r, now); ok {
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
	if !s.ipLimiter.Allow(clientIP(r)) {
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
		// Re-derive "open host" from the destination exactly as /request did. rd
		// is client-influenced (the posted copy wins), so this is not what keeps
		// strangers out: a guest session is the same whichever host minted it,
		// and the boundary is CanAccessApp admitting guests only on routes that
		// opt in. The host check only decides where a guest login is offered.
		role := s.policy.LoginRole(st.Email, s.isOpenHost(rd))
		if role == authz.RoleDeny {
			s.recordAuth(r, st.Email, store.AuthEventVerify, store.AuthOutcomeDenied)
			s.sessions.ClearState(w)
			s.render(w, http.StatusForbidden, "login", pageData{Error: "This account is not permitted.", Redirect: rd})
			return
		}
		if role == authz.RoleAdmin && s.cfg.TOTPEnabled {
			// First factor passed; the login itself is recorded once TOTP completes
			// (in completeLogin). Record the email step so a never-finished second
			// factor still shows the first one succeeded.
			s.recordAuth(r, st.Email, store.AuthEventVerify, store.AuthOutcomeOK)
			s.startTOTP(w, r, st.Email, role, rd, st.Remember, now)
			return
		}
		// Code-only completion: either a non-admin, or TOTP is disabled. No second
		// factor was presented, so the session records totp=false. A guest always
		// lands here (RoleGuest is never RoleAdmin), so it is never sent to TOTP.
		s.completeLogin(w, r, st.Email, role, rd, st.Remember, false, now)
	case store.ConsumeMismatch:
		s.recordAuth(r, st.Email, store.AuthEventVerify, store.AuthOutcomeWrongCode)
		s.render(w, http.StatusUnauthorized, "code", pageData{
			Error: "Incorrect code. Please try again.", Email: st.Email, Redirect: rd,
		})
	case store.ConsumeTooManyAttempts:
		s.recordAuth(r, st.Email, store.AuthEventVerify, store.AuthOutcomeLockedOut)
		s.sessions.ClearState(w)
		s.render(w, http.StatusUnauthorized, "login", pageData{
			Error: "Too many incorrect attempts. Please request a new code.", Redirect: rd,
		})
	default: // ConsumeExpired, ConsumeNoCode
		s.recordAuth(r, st.Email, store.AuthEventVerify, store.AuthOutcomeExpired)
		s.sessions.ClearState(w)
		s.render(w, http.StatusUnauthorized, "login", pageData{
			Error: "Your code has expired. Please request a new one.", Redirect: rd,
		})
	}
}

// startTOTP challenges an admin for their authenticator code. Secrets are
// provisioned out-of-band by an administrator (the admin UI or the -totp-enroll
// CLI), never self-enrolled here: letting a login bootstrap its own second
// factor would let someone who controls only the email inbox set up the factor
// that is supposed to backstop a compromised inbox. An admin with no provisioned
// secret is therefore denied, not enrolled.
func (s *Server) startTOTP(w http.ResponseWriter, r *http.Request, emailAddr, role, rd string, remember bool, now time.Time) {
	_, ok, err := s.getTOTPSecret(r.Context(), emailAddr)
	if err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong", Redirect: rd})
		return
	}
	if !ok {
		s.sessions.ClearState(w)
		s.render(w, http.StatusForbidden, "message", pageData{
			Title:    "Two-factor setup required",
			Message:  "Admin accounts require two-factor authentication, which has not been set up for this account yet. Please ask an administrator to enrol your account, then sign in again.",
			Redirect: rd,
		})
		return
	}
	if err := s.sessions.SetPending(w, session.Pending{Email: emailAddr, Role: role, Redirect: rd, Remember: remember}, s.cfg.OTPTTL, now); err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong", Redirect: rd})
		return
	}
	s.sessions.ClearState(w)
	s.render(w, http.StatusOK, "totp", pageData{Redirect: rd})
}

// handleTOTP verifies an admin's authenticator code and completes login.
func (s *Server) handleTOTP(w http.ResponseWriter, r *http.Request) {
	if !s.requireSameOrigin(w, r) {
		return
	}
	now := s.now()
	// Same dual-carrier scheme as handleVerifyCode: prefer the validated rd
	// posted by the TOTP form over the (clobberable, OTP_TTL-lived) pending
	// cookie, and keep the destination alive when the cookie is gone.
	postedRD := authz.SafeRedirect(r.PostFormValue("rd"), s.cfg.Domain, "")
	p, ok := s.sessions.ReadPending(r, now)
	if !ok {
		// Same double-submit race as handleVerifyCode: the first /totp already
		// consumed the pending state and issued the session, so a re-tap (or
		// autofill retry) finds no pending but a valid session. Forward the
		// already-authenticated user on instead of bouncing them to /login.
		if _, ok := s.sessions.ReadSession(r, now); ok {
			http.Redirect(w, r, s.loginRedirect(postedRD), http.StatusFound)
			return
		}
		s.restartLogin(w, r, postedRD)
		return
	}
	rd := postedRD
	if rd == "" {
		rd = p.Redirect
	}
	if !s.ipLimiter.Allow(clientIP(r)) {
		s.render(w, http.StatusTooManyRequests, "totp", pageData{
			Error: "Too many attempts. Please wait and try again.", Redirect: rd,
		})
		return
	}
	// Per-account cap: the shared per-IP limiter alone lets a distributed
	// attacker (who already controls the admin's inbox) grind the 10^6 TOTP
	// space. The attempt is reserved BEFORE the code is checked, so the cap
	// bounds how many codes are ever checked within the window no matter how
	// many submissions arrive together; a successful login clears it. If the
	// attempt cannot be recorded, the code is NOT checked: an unrecorded check
	// would be an uncounted guess, so a store outage would otherwise switch
	// the cap off exactly when guesses cannot be bounded. The admin is asked
	// to try again shortly instead.
	n, err := s.store.ReserveTOTPAttempt(r.Context(), p.Email, totpLockoutWindow, now)
	if err != nil {
		log.Printf("reserve totp attempt for %s: %v", p.Email, err)
		s.render(w, http.StatusServiceUnavailable, "totp", pageData{
			Error: "The code could not be checked just now. Please try again in a moment.", Redirect: rd,
		})
		return
	}
	if n > s.cfg.OTPMaxAttempts {
		s.recordAuth(r, p.Email, store.AuthEventTOTP, store.AuthOutcomeLockedOut)
		s.render(w, http.StatusTooManyRequests, "totp", pageData{
			Error: "Too many incorrect codes. This account is temporarily locked; try again shortly.", Redirect: rd,
		})
		return
	}
	secret, ok, err := s.getTOTPSecret(r.Context(), p.Email)
	if err != nil || !ok {
		if err == nil {
			s.recordAuth(r, p.Email, store.AuthEventTOTP, store.AuthOutcomeNoSecret)
		}
		s.restartLogin(w, r, rd)
		return
	}
	code := strings.TrimSpace(r.PostFormValue("code"))
	if !totp.Validate(code, secret) {
		// The attempt was already counted by the reservation above.
		s.recordAuth(r, p.Email, store.AuthEventTOTP, store.AuthOutcomeWrongCode)
		s.render(w, http.StatusUnauthorized, "totp", pageData{
			Error: "Incorrect code. Please try again.", Redirect: rd,
		})
		return
	}
	// A TOTP code stays valid for its whole ~30s step; reject a second use of the
	// same code so a sniffed/phished code can't be replayed within that window.
	if !s.totpReplay.use(p.Email, code) {
		s.recordAuth(r, p.Email, store.AuthEventTOTP, store.AuthOutcomeReplayed)
		s.render(w, http.StatusUnauthorized, "totp", pageData{
			Error: "That code has already been used. Wait for your authenticator to show a new one.", Redirect: rd,
		})
		return
	}
	// TOTP satisfied: clear the failure counter and issue the session.
	if err := s.store.ClearTOTPFailures(r.Context(), p.Email); err != nil {
		log.Printf("clear totp failures for %s: %v", p.Email, err)
	}
	// The role is re-derived from the CURRENT policy, not the one saved in the
	// pending cookie at the email step: an admin removed or demoted between
	// the two factors must not be issued an admin session that downstream
	// admin-only routes would then honour until renewal. A principal the
	// policy no longer permits at all is refused and sent to sign in again.
	role := s.policy.LoginRole(p.Email, s.isOpenHost(rd))
	if role == authz.RoleDeny {
		s.recordAuth(r, p.Email, store.AuthEventTOTP, store.AuthOutcomeDenied)
		s.sessions.ClearPending(w)
		s.restartLogin(w, r, rd)
		return
	}
	s.completeLogin(w, r, p.Email, role, rd, p.Remember, true, now)
}

// totpLockoutWindow is the rolling window over which TOTP verification attempts
// are counted toward the per-account lockout (cap = OTP_MAX_ATTEMPTS).
const totpLockoutWindow = 15 * time.Minute

// servedTarget validates rawURL as a post-login destination the gateway can
// actually serve: an absolute https URL on a SUBDOMAIN of the server domain.
// The bare apex is rejected by default — this gateway usually serves
// subdomains (auth.<domain>, app.<domain>), and a bare apex commonly has no
// TLS certificate, so sending a freshly signed-in user there strands them on
// a browser security error. Deployments whose apex IS a real gated site opt
// in with ALLOW_APEX_REDIRECT=true. Returns the normalised URL and true when
// usable.
func (s *Server) servedTarget(rawURL string) (string, bool) {
	target, ok := authz.ValidateRedirect(rawURL, s.cfg.Domain)
	if !ok {
		return "", false
	}
	u, err := url.Parse(target)
	if err != nil {
		return "", false
	}
	if !s.cfg.AllowApexRedirect &&
		strings.EqualFold(u.Hostname(), strings.TrimPrefix(s.cfg.Domain, ".")) {
		return "", false // bare apex: not a host this gateway serves
	}
	return target, true
}

// loginRedirect is where to send a user after a successful login or break-glass
// grant: the requested destination when it is a servable subdomain URL, otherwise
// the auth host's own signed-in page — which always has a valid certificate,
// since it just served the login page. This makes a missing or misconfigured
// destination land safely instead of on a TLS error.
func (s *Server) loginRedirect(rd string) string {
	if target, ok := s.servedTarget(rd); ok {
		return target
	}
	return s.cfg.PublicURL + "/welcome"
}

// handleWelcome is the signed-in landing page on the auth host, shown after a
// login that has no specific app destination (e.g. a direct visit to the login
// page). Because it is served on auth.<domain> — which always has a valid
// certificate — it can never strand the user the way an unservable
// DEFAULT_REDIRECT could. It offers sign-out and, when configured, a "Continue"
// link to the operator's default destination.
func (s *Server) handleWelcome(w http.ResponseWriter, r *http.Request) {
	id, ok := s.sessions.ReadSession(r, s.now())
	if !ok {
		http.Redirect(w, r, s.cfg.PublicURL+"/login", http.StatusFound)
		return
	}
	data := pageData{}
	if id.Kind == session.KindBreakGlass {
		data.BreakGlass = true
		data.Identity = strings.TrimPrefix(id.Email, "breakglass:")
	} else {
		data.Identity = id.Email
		// A real admin session gets an Admin link here; a break-glass or guest
		// session never does (neither can reach the admin UI — see requireAdmin).
		data.IsAdmin = isAdminSession(id) && s.policy.Role(id.Email) == authz.RoleAdmin
	}
	if target, ok := s.servedTarget(s.cfg.DefaultRedirect); ok {
		data.Redirect = target // rendered as a "Continue" link
	}
	s.render(w, http.StatusOK, "welcome", data)
}

// completeLogin bakes the group set, issues the session cookie (using the
// remember-me lifetime when requested), and redirects to the target. totpVerified
// records whether the admin second factor was satisfied for this login, so a
// later /verify can tell a fully-authenticated admin session from a
// first-factor-only one (see needsAdminStepUp).
func (s *Server) completeLogin(w http.ResponseWriter, r *http.Request, emailAddr, role, rd string, remember, totpVerified bool, now time.Time) {
	groups := s.computeGroups(r.Context(), emailAddr, role)
	// The kind follows the role: a guest login is marked so /verify confines it
	// to routes that opt in, and renewal keeps it a guest.
	kind := ""
	if role == authz.RoleGuest {
		kind = session.KindGuest
	}
	// A guest never gets the remember-me lifetime. Sessions are stateless, so
	// the only ways to end one guest's access are emptying
	// OPEN_REGISTRATION_HOSTS (every guest, at their next renewal) or rotating
	// SESSION_SECRET (everyone). Keeping a stranger on the short lifetime bounds
	// how long an unwanted guest can hold a cookie before renewal re-checks it.
	ttl := s.cfg.SessionTTL
	if remember && kind != session.KindGuest {
		ttl = s.cfg.SessionRememberTTL
	}
	if err := s.sessions.IssueSessionTTL(w, emailAddr, groups, kind, totpVerified, ttl, now); err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong", Redirect: rd})
		return
	}
	// The single success funnel for human logins (both code-only and
	// TOTP-completed); break-glass grants issue their session separately and are
	// audited in break_glass_events instead.
	s.recordAuth(r, emailAddr, store.AuthEventLogin, store.AuthOutcomeOK)
	s.sessions.ClearState(w)
	s.sessions.ClearPending(w)
	http.Redirect(w, r, s.loginRedirect(rd), http.StatusFound)
}

// needsAdminStepUp reports whether an admin session must re-authenticate through
// the TOTP step before it is honoured for admin access. It fires only when TOTP
// is enabled and the session carries no second-factor assurance (totp=false) —
// i.e. the session was minted before TOTP was turned on, or the principal has
// since become an admin. This closes the gap where enabling TOTP would otherwise
// leave already-issued first-factor-only admin sessions valid until they expire.
// Break-glass sessions are never admin, so callers pass isAdmin=false for them.
func (s *Server) needsAdminStepUp(isAdmin, totpVerified bool) bool {
	return s.cfg.TOTPEnabled && isAdmin && !totpVerified
}

// knownSessionKind reports whether kind is one this build understands: a
// normal login, a break-glass grant, or a guest. /verify refuses any other.
func knownSessionKind(kind string) bool {
	switch kind {
	case "", session.KindBreakGlass, session.KindGuest:
		return true
	}
	return false
}

// isAdminSession reports whether a session carries the admin tier. Only a normal
// email-OTP login (kind "") can: break-glass is a bearer QR scan and a guest is a
// stranger, so neither is admin whatever its groups say. Testing for the normal
// kind rather than excluding the known exceptions means a future session kind is
// non-admin until someone decides otherwise.
func isAdminSession(id *session.Identity) bool {
	return id.Kind == "" && authz.HasGroup(id.Groups, authz.RoleAdmin)
}

// renewalRole re-derives a session's base role at sliding renewal. A normal
// session is re-checked against the allow-list, which is where revocation takes
// effect. A guest is, by definition, NOT on the allow-list, so asking Role would
// end every guest session at its first renewal; instead the guest's address is
// re-checked only for plausibility and it stays RoleGuest. It never steps up to
// admin here: even if the address has since been made an admin, the guest
// session keeps its kind and must sign in again to become one.
func (s *Server) renewalRole(id *session.Identity) string {
	if id.Kind == session.KindGuest {
		// A guest stays a guest at renewal, but only while some host still
		// admits guests: emptying OPEN_REGISTRATION_HOSTS ends every guest
		// session at its next renewal, the same way de-listing a domain ends
		// a user's. The address is re-checked for plausibility, nothing more.
		if len(s.cfg.OpenRegistrationHosts) > 0 && authz.GuestEligible(id.Email) {
			return authz.RoleGuest
		}
		return authz.RoleDeny
	}
	return s.policy.Role(id.Email)
}

// isOpenHost reports whether a (validated) post-login destination is on a host
// listed in OPEN_REGISTRATION_HOSTS, where an address the allow-list does not
// permit may sign in as a guest. An empty or unparsable rd is never open.
func (s *Server) isOpenHost(rd string) bool {
	if rd == "" || len(s.cfg.OpenRegistrationHosts) == 0 {
		return false
	}
	u, err := url.Parse(rd)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, h := range s.cfg.OpenRegistrationHosts {
		if host == h {
			return true
		}
	}
	return false
}

// computeGroups returns the comma-separated Remote-Groups value for an email:
// the base role plus any DB-managed group memberships.
func (s *Server) computeGroups(ctx context.Context, emailAddr, role string) string {
	dbGroups, err := s.store.GroupsForEmail(ctx, emailAddr)
	if err != nil {
		log.Printf("groups for %s: %v", emailAddr, err)
	}
	return authz.BuildGroups(role, dbGroups)
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

// loginURL is the login page, carrying rd when there is one so the person
// returns to the app they came from after signing in.
func (s *Server) loginURL(rd string) string {
	if rd == "" {
		return s.cfg.PublicURL + "/login"
	}
	return s.cfg.PublicURL + "/login?rd=" + url.QueryEscape(rd)
}

// logoutURL is the sign-out confirmation page, carrying rd so that after signing
// out the person lands on the login page for the app they were trying to reach.
func (s *Server) logoutURL(rd string) string {
	if rd == "" {
		return s.cfg.PublicURL + "/logout"
	}
	return s.cfg.PublicURL + "/logout?rd=" + url.QueryEscape(rd)
}

// handleLogoutConfirm renders a sign-out confirmation for GET /logout (a typed
// or clicked URL). The logout itself is POST-only (handleLogout), so it can't be
// triggered by a cross-site GET, link, or redirect; this page just gives that
// POST a button instead of a 404. A request without a session has nothing to
// confirm, so it's sent to the login page.
//
// An app may pass rd, validated like the login page's, so that after signing
// out the person lands back on that app's login rather than the bare login
// page: an applicant who wrote from one address and wants to sign in with
// another goes straight back to where they were.
func (s *Server) handleLogoutConfirm(w http.ResponseWriter, r *http.Request) {
	rd := authz.SafeRedirect(r.URL.Query().Get("rd"), s.cfg.Domain, "")
	id, ok := s.sessions.ReadSession(r, s.now())
	if !ok {
		http.Redirect(w, r, s.loginURL(rd), http.StatusFound)
		return
	}
	data := pageData{Redirect: rd}
	if id.Kind == session.KindBreakGlass {
		data.BreakGlass = true
		data.Identity = strings.TrimPrefix(id.Email, "breakglass:")
	} else {
		data.Identity = id.Email
	}
	s.render(w, http.StatusOK, "logout", data)
}

// handleLogout clears the session. POST-only (see handleLogoutConfirm) so a
// cross-site GET cannot force a logout. The confirmation form re-carries rd,
// so the login page it lands on knows where to return to.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !s.requireSameOrigin(w, r) {
		return
	}
	rd := authz.SafeRedirect(r.PostFormValue("rd"), s.cfg.Domain, "")
	s.sessions.ClearSession(w)
	http.Redirect(w, r, s.loginURL(rd), http.StatusFound)
}

// handleBreakGlass grants emergency access from a scanned QR code. It is public
// (the token in the URL is the only credential, by design), instant (no second
// factor), rate-limited per IP, audited synchronously, and notifies admins
// asynchronously. The granted session is short-lived and never renewed.
func (s *Server) handleBreakGlass(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	ip := clientIP(r)
	ua := clampUserAgent(r.UserAgent())
	// Break-glass scans use their own, more permissive per-IP limiter: the token's
	// 128-bit entropy is the brute-force boundary here, so this only guards against
	// abuse and must not throttle many staff scanning from behind one shared IP
	// during an emergency.
	if !s.breakLimiter.Allow(ip) {
		s.render(w, http.StatusTooManyRequests, "message", pageData{
			Title:   "Too many requests",
			Message: "Please wait a little while and try again.",
		})
		return
	}

	token := r.PathValue("token")
	code, ok, err := s.store.LookupBreakGlassByTokenHash(r.Context(), otp.Hash(token))
	if err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong"})
		return
	}

	// Unknown or revoked codes look identical to the scanner: a neutral page.
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
		s.render(w, http.StatusNotFound, "message", pageData{
			Title:   "Access code not available",
			Message: "This emergency access code is not active. Please contact an administrator.",
		})
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
	if id, ok := s.sessions.ReadSession(r, now); ok && id.Kind == "" {
		rd := authz.SafeRedirect(code.Redirect, s.cfg.Domain, s.cfg.BreakGlassRedirect)
		if err := s.sessions.SetOffer(w, session.Offer{CodeID: code.ID, Label: code.Label}, s.cfg.OTPTTL, now); err != nil {
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

// grantBreakGlass mints an emergency session for an active code: it writes the
// source-of-truth audit row (before granting), notifies admins out of band, and
// issues the short-lived, never-renewed break-glass session, then redirects to
// the code's resource. Shared by a direct scan (handleBreakGlass, when there is
// no existing login) and the one-tap activation from the denial page
// (handleBreakGlassActivate).
func (s *Server) grantBreakGlass(w http.ResponseWriter, r *http.Request, code store.BreakGlassCode, ip, ua string, now time.Time) {
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
			Label: code.Label, TargetGroup: code.TargetGroup, Outcome: store.OutcomeGranted,
			ClientIP: ip, UserAgent: ua, Time: now,
		})

	groups := authz.BuildGroups(code.TargetGroup, nil)
	principal := "breakglass:" + code.Label
	if err := s.sessions.IssueSessionTTL(w, principal, groups, session.KindBreakGlass, false, ttl, now); err != nil {
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
// between scan and tap grants nothing. A card RE-MINTED (token rotated, still
// active) in that window still activates — re-mint keeps the card live, so
// honouring an in-flight offer for the same scope is intended; only revoke cuts a
// pending offer off.
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
	if id, ok := s.sessions.ReadSession(r, now); !ok || id.Kind != "" {
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
	if !ok || code.Status != store.BreakGlassActive {
		log.Printf("break-glass activate denied (inactive/unknown code %d) from %s", offer.CodeID, ip)
		s.render(w, http.StatusNotFound, "message", pageData{
			Title:   "Access code not available",
			Message: "This emergency access code is not active. Please contact an administrator.",
		})
		return
	}

	s.grantBreakGlass(w, r, code, ip, ua, now)
}

// handleLogo serves the global branding logo for the public login pages.
// Returns 404 when no logo is configured.
func (s *Server) handleLogo(w http.ResponseWriter, r *http.Request) {
	b, ok, err := s.store.GetBranding(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok || len(b.Logo) == 0 {
		http.NotFound(w, r)
		return
	}
	// The sign-in pages link the logo as /logo.img?v=<version of its bytes>,
	// so that URL names one exact image and can be cached for a year without a
	// round trip. Any other request (no v, or a v from a replaced logo)
	// revalidates by ETag, so an out-of-date or invented v can never pin a
	// stale logo. The logo is shown to anyone on the public sign-in pages, so
	// shared caches may keep it.
	v := logoVersion(b.Logo)
	etag := `"` + v + `"`
	w.Header().Set("ETag", etag)
	if r.URL.Query().Get("v") == v {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeImage(w, b.LogoType, b.Logo)
}

// logoVersion names one exact logo: the first 16 hex digits of its SHA-256.
func logoVersion(logo []byte) string {
	sum := sha256.Sum256(logo)
	return hex.EncodeToString(sum[:8])
}

// writeImage serves stored image bytes (logos, glyphs, QR PNGs). It overrides
// the page CSP with a locked-down, sandboxed policy so that an admin-uploaded
// SVG served inline can never execute script or act as an active document,
// independent of its declared content type.
func writeImage(w http.ResponseWriter, mime string, data []byte) {
	if mime == "" {
		mime = "application/octet-stream"
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("Content-Disposition", "inline")
	w.Write(data)
}

// handleHealthz is a liveness probe. It never touches the mail backend so a
// transient email outage can't fail the container healthcheck.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "ok")
}

// reconstructOriginalURL rebuilds the URL the user was trying to reach from the
// forward_auth headers Caddy sets.
func (s *Server) reconstructOriginalURL(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		proto = "https"
	}
	host := r.Header.Get("X-Forwarded-Host")
	uri := r.Header.Get("X-Forwarded-Uri")
	if host == "" {
		return s.cfg.DefaultRedirect
	}
	return proto + "://" + host + uri
}

// Headers Caddy's guard snippets set on the /verify subrequest. The per-app
// authorization requirement rides in a SINGLE header, X-Auth-Policy, which every
// guard sets via `header_up` (replace semantics) so a client can neither inject
// nor widen it. Carrying it in one always-set header — rather than a set of
// headers each guard must remember to delete — removes the fail-open risk of a
// forgotten strip, and lets new policy fields be added without touching every
// guard. The UX hints below are not a privilege boundary (the alt link is
// re-validated server-side to be within the domain; the label is cosmetic), so
// they stay as separate plain headers.
const (
	headerPolicy      = "X-Auth-Policy"
	headerDomainLabel = "X-Auth-Domain-Label"
	headerAltLogin    = "X-Auth-Alt-Login"
	headerAltLabel    = "X-Auth-Alt-Label"
)

// parsePolicy parses the X-Auth-Policy header against its exact grammar and
// reports whether the value is well formed. The value is a ";"-separated set
// of fields: the bare sentinel "any" (a plain `protected` guard: any signed-in
// user), "domains=<list>" and "groups=<list>" each holding a non-empty
// space/comma-separated allow-list (both safe charsets, so no escaping is
// needed), and "guests=allow", which admits open-registration guest sessions.
//
// Anything else makes the whole value invalid and ok is false: an empty or
// absent header, an empty allow-list ("domains="), a misspelled or unknown
// field ("gruops=admin", "mode=any"), a guests value other than exactly
// "allow", or "any" combined with an allow-list. The caller denies on !ok.
// This is deliberate: a lenient parser that skipped what it did not
// understand would turn a typo in a guard into "any signed-in user", which
// is the one outcome a per-app policy exists to prevent.
func parsePolicy(h string) (domains, groups string, allowGuests, ok bool) {
	sawAny := false
	for _, field := range strings.Split(h, ";") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		if field == "any" {
			sawAny = true
			continue
		}
		k, v, found := strings.Cut(field, "=")
		if !found {
			return "", "", false, false
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "domains":
			if v == "" {
				return "", "", false, false
			}
			domains = v
		case "groups":
			if v == "" {
				return "", "", false, false
			}
			groups = v
		case "guests":
			if v != "allow" {
				return "", "", false, false
			}
			allowGuests = true
		default:
			return "", "", false, false
		}
	}
	hasList := domains != "" || groups != ""
	if sawAny == hasList { // neither, or both
		return "", "", false, false
	}
	return domains, groups, allowGuests, true
}

// warnLegacyPolicy flags a guard that still sends the old X-Auth-Require-*
// headers but no X-Auth-Policy: its per-app narrowing is now ignored (the app
// falls back to "any signed-in user"), so the Caddy snippet must be migrated.
// Logged so an unmigrated custom guard is caught loudly rather than silently
// failing open.
func (s *Server) warnLegacyPolicy(r *http.Request) {
	if r.Header.Get(headerPolicy) != "" {
		return
	}
	if r.Header.Get("X-Auth-Require-Domains") != "" || r.Header.Get("X-Auth-Require-Groups") != "" {
		log.Printf("warning: legacy X-Auth-Require-* ignored for %q; migrate its Caddy guard to set X-Auth-Policy",
			r.Header.Get("X-Forwarded-Host"))
	}
}

// clientIP returns the connecting client's IP, used as a rate-limit key. Caddy
// is the only host that can reach this service and it APPENDS the real peer
// address as the last X-Forwarded-For element, so the trustworthy value is the
// RIGHTMOST entry. Taking the leftmost would trust a client-supplied value
// (Caddy preserves any inbound X-Forwarded-For), letting an attacker rotate the
// header to mint a fresh "IP" per request and defeat every per-IP limit.
//
// This assumes a single trusted proxy — the scaffold's edge Caddy facing
// clients directly. The auth host's Caddy block also overwrites X-Forwarded-For
// with the true peer as defense-in-depth (see deploy/auth.caddy); if another
// proxy is ever placed in front of Caddy, configure trusted_proxies there.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		candidate := xff
		if i := strings.LastIndexByte(xff, ','); i >= 0 {
			candidate = xff[i+1:]
		}
		// Honor the forwarded value only when it is a well-formed IP. Caddy always
		// writes a bare peer address here; a malformed value means the trusted-proxy
		// contract was broken, so fall back to RemoteAddr rather than letting an
		// attacker-shaped string become its own rate-limit key (defeating per-IP
		// limits by rotating the header).
		if ip := net.ParseIP(strings.TrimSpace(candidate)); ip != nil {
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// maxUserAgentLen bounds the User-Agent we store in the audit log and carry into
// a break-glass notification, so an oversized header can't bloat either. The
// notification email is also protected from MIME injection by a random boundary
// (see email.buildMIME); this is defense-in-depth and storage hygiene.
const maxUserAgentLen = 512

func clampUserAgent(ua string) string {
	if len(ua) > maxUserAgentLen {
		return ua[:maxUserAgentLen]
	}
	return ua
}

func normalizeEmail(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func validEmail(s string) bool {
	if s == "" || len(s) > 254 {
		return false
	}
	addr, err := mail.ParseAddress(s)
	if err != nil {
		return false
	}
	// ParseAddress accepts display names; require the bare address to match.
	return strings.EqualFold(addr.Address, s) && strings.Contains(s, "@")
}
