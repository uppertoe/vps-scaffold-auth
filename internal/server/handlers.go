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
)

// renewSession re-checks policy and saves the session with freshly computed
// groups and a new expiry. It is the scheduled sliding renewal, and also runs
// when a group rule refuses a session whose groups have since changed. A
// principal no longer permitted has the session ended and is sent to sign in,
// and ok is false (the response has been written).
func (s *Server) renewSession(w http.ResponseWriter, r *http.Request, id *session.Identity, now time.Time) bool {
	return s.renewSessionWith(w, r, id, now, nil)
}

// renewSessionWith is renewSession with the person's current groups already
// read (the refusal path), so a renewal there costs one query, not two. A nil
// groups reads them here.
func (s *Server) renewSessionWith(w http.ResponseWriter, r *http.Request, id *session.Identity, now time.Time, groups *string) bool {
	// Without the allow-list, the domain groups decide who is staff; while
	// they have never been read, the session is left as it is.
	if s.rolesUnavailable(r.Context()) {
		s.renderUnavailable(w, s.reconstructOriginalURL(r))
		return false
	}
	role := s.renewalRole(id)
	if role == authz.RoleDeny {
		s.endThisSession(w, r, id)
		s.redirectToLogin(w, r)
		return false
	}
	if groups == nil {
		g := s.computeGroups(r.Context(), id.Email, s.tierRole(id, role))
		groups = &g
	}
	// id.Kind is passed through, so a guest stays a guest across renewals (and
	// so stays confined to roles held by guests). The one change is between a
	// person's own kinds: an address that now holds a role but is off the
	// allow-list becomes a member, and a member the allow-list now admits
	// becomes an ordinary session.
	kind := id.Kind
	if role == authz.RoleMember {
		kind = session.KindMember
	} else if kind == session.KindMember {
		kind = ""
	}
	if !s.renewSessionRow(w, r, id, kind, *groups, now) {
		s.sessions.ClearSession(w)
		s.redirectToLogin(w, r)
		return false
	}
	// Reflect the freshly computed set in this response too, not just the
	// renewed cookie, so a demotion takes effect immediately.
	id.Groups = *groups
	id.Kind = kind
	return true
}

// currentGroups reads the principal's groups from the database for the
// refusal path. ok is false when they cannot be read reliably; the caller then
// refuses without renewing, rather than mistaking a database error for a
// change of groups.
func (s *Server) currentGroups(r *http.Request, id *session.Identity) (groups string, ok bool) {
	role := s.renewalRole(id)
	if role == authz.RoleDeny {
		return "", true // renewSessionWith ends the session
	}
	dbGroups, err := s.store.GroupsForEmail(r.Context(), id.Email)
	if err != nil {
		log.Printf("refusal-path groups for %s: %v", id.Email, err)
		return "", false
	}
	tier := s.tierRole(id, role)
	return authz.BuildGroups(tier, s.withoutStaffOnlyListsForOutsider(r.Context(), id.Email, tier, dbGroups)), true
}

// handleVerify is the forward_auth target. Caddy calls it on every request to a
// protected app. A valid session yields 200 + identity headers; otherwise the
// user is redirected to the login page.
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	x, token, legacy, err := s.resolveSession(r, now)
	if err != nil {
		// An old cookie could not be converted because the database could
		// not be reached: the person is asked to try again, not signed out.
		s.renderUnavailable(w, s.reconstructOriginalURL(r))
		return
	}
	if x != nil {
		id := identityOf(x)
		// Fail closed on a kind this build does not know. Only this service
		// writes a session, but a row left by a newer build (a rollback) must
		// not be read as a normal session: anything that is neither
		// break-glass nor guest would pass for a department login. Such a
		// session is ended and sent to sign in.
		if !knownSessionKind(id.Kind) {
			s.endThisSession(w, r, id)
			s.redirectToLogin(w, r)
			return
		}
		// An old cookie has just become a session: the browser is given the
		// new cookie now (renewal below would send it too).
		if legacy {
			s.sessions.SetSession(w, token, x.Expires, now)
		}
		// Without the allow-list and before the domain groups have ever been
		// read, the gateway cannot tell staff from strangers: it answers 503
		// and keeps the session, rather than end it or treat staff as
		// outsiders (see rolesUnavailable).
		if s.rolesUnavailable(r.Context()) {
			s.renderUnavailable(w, s.reconstructOriginalURL(r))
			return
		}
		renewed := false
		// A session is renewed when it is due, at once when membership has
		// changed since its groups were worked out (so a person removed from a
		// group loses it at their next request), at once when its admin tier
		// has lapsed or been withdrawn (see tierStale), and at once when the
		// policy no longer admits its person (see policyWithdrawn), which the
		// renewal then refuses.
		if s.sessions.NeedsRenew(id, now) || s.groupsStale(id) || s.tierStale(id) || s.policyWithdrawn(id) {
			if !s.renewSession(w, r, id, now) {
				return
			}
			renewed = true
		}
		// Per-app authorization, by app roles (app_roles.go). Every guard names
		// its app in X-Auth-App; a request that names none is refused, since
		// it comes from a hand-rolled or misconfigured guard. An authenticated
		// but unallowed principal is sent to a denial page, not back to login:
		// they are already signed in, and their cookie is left untouched, so
		// access to the apps they are allowed on keeps working.
		if !wantsRoles(r) {
			log.Printf("warning: refusing a guard that names no app for %q", r.Header.Get("X-Forwarded-Host"))
			s.redirectToDenied(w, r)
			return
		}
		s.verifyByRole(w, r, id, now, renewed)
		return
	}

	// A single session cookie that is present but names no session (expired,
	// ended, or minted by an earlier build) is cleared on the way to login. Otherwise it
	// lingers, and an app route that treats "has a session cookie" as "signed
	// in" (p.stonn.org sends such visitors from / to the gated schedule) keeps
	// bouncing a returning visitor to login instead of showing them the
	// landing page. The clearing Set-Cookie rides on this 302, which the Caddy
	// gate copies to the browser unchanged. Two cookies by this name (one
	// planted by a sibling host) are left alone: the clear carries the shared
	// Domain, so it would delete the visitor's real cookie and leave the
	// planted one, turning a one-app nuisance into a sign-out everywhere.
	// A guard that names an app may admit a request with no session from a
	// network its role is given to.
	if wantsRoles(r) && s.verifyByNetwork(w, r) {
		return
	}
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
	// A role guard's hint comes from who holds the role (roleLoginHint).
	// UX only; /verify decides.
	if wantsRoles(r) {
		loginURL += s.roleLoginHint(r)
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
	if id, ok := s.readSession(r, now); ok {
		switch id.Kind {
		case session.KindBreakGlass:
			// A card that opens an app names that app.
			if v, ok := s.wrongAppPage(r.Context(), id, rd); ok {
				s.render(w, http.StatusForbidden, "break_confirm", pageData{Scan: v})
				return
			}
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
			// Group lists, and the feeds behind them, hold firstname.lastname
			// addresses, so someone signed in with a username address at the
			// same domain (upperteam@, 646332@) holds none of the groups.
			if local, domain, ok := strings.Cut(id.Email, "@"); ok && !strings.Contains(local, ".") && domain != "" {
				data.NameAddressExample = "joe.bloggs@" + domain
			}
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
	data := pageData{Redirect: rd}
	applyAccessHint(&data, r.URL.Query().Get("rqd"))
	applyRoleHint(&data, r.URL.Query().Get("rqr"), r.URL.Query().Get("rhd"))
	s.renderLogin(w, r, http.StatusOK, data)
}

// applyAccessHint records the domains a role guard carries as rqd (see
// roleLoginHint) on the page, so they survive to /request as a hidden field,
// and sets the human hint string.
func applyAccessHint(d *pageData, rqd string) {
	rqd = clampHint(rqd)
	d.RequireDomains = rqd
	if rqd != "" {
		d.HintDomains = formatDomains(rqd)
	}
}

// applyRoleHint records a role guard's hint (see roleLoginHint) on the page,
// so it survives to /request as hidden fields. rhd is hinted and never
// declined on. A role guard whose holders are all domain groups carries rqd
// instead, which applyAccessHint handles and which wins here.
func applyRoleHint(d *pageData, rqr, rhd string) {
	if clampHint(rqr) == "" || d.RequireDomains != "" {
		return
	}
	d.RoleGuard = true
	if rhd = clampHint(rhd); rhd != "" {
		d.RoleHintDomains = rhd
		d.RoleHint = fmt.Sprintf(msgRoleHint, withArticle(formatDomains(rhd)))
	}
}

// applyLoginBranding fills the domain-derived UX fields on the login page from
// the staff domains (ALLOWED_EMAIL_DOMAINS, or without it the domain groups'
// domains; see staffDomains), so a DIRECT visit (no route rqd) still tells
// the user which domain to use. It runs after applyAccessHint, so a
// route-supplied requirement (HintDomains/RequireDomains) always wins; this only
// fills the gaps:
//   - HintDomains: the "This page is for <domains> email addresses" line, from
//     the allow-list when no route set one.
//   - EmailPlaceholder: you@<first effective domain> — the route requirement if
//     present, else the first allow-list domain — so the example matches who may
//     sign in. Left empty (→ generic placeholder) when no domain is configured.
func (s *Server) applyLoginBranding(ctx context.Context, d *pageData) {
	// Not at a role guard, where the allow-list says nothing about who holds
	// the role; only the domains of its domain groups are suggested.
	if d.RoleGuard {
		if dom := firstDomain(d.RoleHintDomains); dom != "" && d.EmailPlaceholder == "" {
			d.EmailPlaceholder = "you@" + dom
		}
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
	staff := s.staffDomains(ctx)
	if d.HintDomains == "" && len(staff) > 0 {
		d.HintDomains = formatDomains(strings.Join(staff, ","))
	}
	if d.EmailPlaceholder == "" {
		dom := firstDomain(d.RequireDomains)
		if dom == "" && len(staff) > 0 {
			dom = staff[0]
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

// clampHint trims and bounds a UX hint value carried in the login URL.
func clampHint(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 512 {
		return ""
	}
	return s
}

// formatDomains renders a space/comma-separated domain list for display.
func formatDomains(s string) string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';' || r == '\n' || r == '\r' || r == '\t'
	})
	return strings.ToLower(joinOr(fields))
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
	if _, ok := s.readSession(r, s.now()); ok {
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
	// Lower case, as a browser writes an origin: the passkey check compares
	// origins exactly, so a capital in AUTH_PUBLIC_URL would otherwise refuse
	// every passkey.
	return strings.ToLower(u.Scheme + "://" + host)
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
	// While the gateway cannot tell who is staff, nobody is sent a code or a
	// decoy: a member of staff would otherwise be refused, or made a guest.
	if s.rolesUnavailable(r.Context()) {
		s.renderUnavailable(w, rd)
		return
	}
	permitted := s.loginRole(r.Context(), emailAddr, s.isOpenHost(rd)) != authz.RoleDeny
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
		// time (so the flood cannot be seen, and through it the allow-list),
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
// rationale in handleRequest — so the verify step can't enumerate the allow-list.
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
		role := s.loginRole(r.Context(), st.Email, s.isOpenHost(rd))
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
	next := session.Identity{Email: id.Email, TOTP: true, Step: now.Unix(), PK: id.PK, Auth: id.Auth}
	next.Groups = s.computeGroups(r.Context(), id.Email, authz.RoleAdmin)
	if err := s.startSession(w, r, next, s.sessions.SessionTTL(id), now); err != nil {
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
	// An invitation's code step ends on the auth host's own page for it.
	if strings.HasPrefix(rd, s.cfg.PublicURL+inviteDonePath) {
		return rd
	}
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
	id, ok := s.readSession(r, s.now())
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
		data.IsAdmin = id.Kind == "" && s.policy.Role(id.Email) == authz.RoleAdmin
		if _, _, ok := s.passkeySession(r); ok && s.cfg.PasskeysEnabled {
			data.Passkey = &passkeyPage{Next: s.passkeysURL()}
		}
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

// tierRole is the role a session's groups are built from. An administrator
// who has not passed the second step recently is an ordinary user: every
// site that admits staff admits them at once, and only the admin pages and
// admin-only routes send them to the admin door.
//
// A member's groups carry the guest tier token, since a member is someone
// outside the department, and so are built as an outsider's.
func (s *Server) tierRole(id *session.Identity, role string) string {
	if role == authz.RoleAdmin && !s.adminStepFresh(id) {
		return authz.RoleUser
	}
	if role == authz.RoleMember {
		return authz.RoleGuest
	}
	return role
}

// tierStale reports whether a normal session's admin tier no longer matches
// what it should be now: an administrator's second step has aged out, or the
// address has been removed from ADMIN_EMAILS (or, the other way, a session
// with a recent second step lacks the admin group it should carry). Each
// renews the session at once, so the admin group leaves or reaches the apps'
// headers at the next request rather than at the next scheduled renewal.
//
// A person's sign-in whose kind no longer matches knownRole is stale too: a
// normal session whose address is no longer known (it has left the
// allow-list, or without one every domain group) but holds an app role
// becomes a member at once, and a member whose address is now known becomes
// an ordinary session at once.
func (s *Server) tierStale(id *session.Identity) bool {
	switch id.Kind {
	case "":
		role := s.renewalRole(id)
		if role == authz.RoleMember {
			return true
		}
		return authz.HasGroup(id.Groups, authz.RoleAdmin) != (s.tierRole(id, role) == authz.RoleAdmin)
	case session.KindMember:
		return s.known(context.Background(), id.Email)
	}
	return false
}

// policyWithdrawn reports whether the current policy refuses a normal or
// guest session's person: their domain has been taken off the allow-list
// (or, without one, off every domain group) and they hold no app role and are
// not listed as an administrator, or no host admits guests any longer. The
// allow-list is read from the configuration at start, and the domain groups
// and roles from the cached role data, so this is a lookup in memory.
// Break-glass sessions are not policy logins and end at their own short
// lifetime or when their card is revoked.
func (s *Server) policyWithdrawn(id *session.Identity) bool {
	if !personSession(id) && id.Kind != session.KindGuest {
		return false
	}
	return s.renewalRole(id) == authz.RoleDeny
}

func (s *Server) stepUpURL(rd string) string {
	return s.cfg.PublicURL + "/totp?rd=" + url.QueryEscape(rd)
}

// knownSessionKind reports whether kind is one this build understands: a
// normal login, a break-glass grant, or a guest. /verify refuses any other.
func knownSessionKind(kind string) bool {
	switch kind {
	case "", session.KindBreakGlass, session.KindGuest, session.KindMember:
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
		// session at its next request (see policyWithdrawn), the same way
		// de-listing a domain ends a user's. The address is re-checked for plausibility, nothing more.
		if len(s.cfg.OpenRegistrationHosts) > 0 && authz.GuestEligible(id.Email) {
			return authz.RoleGuest
		}
		return authz.RoleDeny
	}
	// A member who is now known (the allow-list, or without one a domain
	// group, admits the address) renews as an ordinary user or administrator
	// (renewSessionWith changes its kind).
	role := s.knownRole(context.Background(), id.Email)
	if role == authz.RoleDeny && personSession(id) && s.mayHoldRoleSnapshot(context.Background(), id) {
		// Not known, but holds an app role through a domain group, a list or
		// a current person assignment (app_roles.go): a member.
		return authz.RoleMember
	}
	return role
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

// computeGroups returns a session's comma-separated groups for an email: the
// base role plus the lists the address belongs to, less any staff-only list for
// an outsider.
func (s *Server) computeGroups(ctx context.Context, emailAddr, role string) string {
	dbGroups, err := s.store.GroupsForEmail(ctx, emailAddr)
	if err != nil {
		log.Printf("groups for %s: %v", emailAddr, err)
	}
	return authz.BuildGroups(role, s.withoutStaffOnlyListsForOutsider(ctx, emailAddr, role, dbGroups))
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
	id, ok := s.readSession(r, s.now())
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

// handleLogout ends the session. POST-only (see handleLogoutConfirm) so a
// cross-site GET cannot force a logout. The confirmation form re-carries rd,
// so the login page it lands on knows where to return to.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !s.requireSameOrigin(w, r) {
		return
	}
	rd := authz.SafeRedirect(r.PostFormValue("rd"), s.cfg.Domain, "")
	// "Sign out on every device" ends every session this person has, here
	// and on any other device, including one someone else may hold. A
	// break-glass session belongs to a card, not a person, and only signs
	// out here.
	now := s.now()
	id, ok := s.readSession(r, now)
	if ok && r.PostFormValue("everywhere") == "1" && id.Kind != session.KindBreakGlass {
		if err := s.endSessions(r.Context(), id.Email, now); err != nil {
			log.Printf("sign out everywhere for %s: %v", id.Email, err)
			s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong"})
			return
		}
		s.recordAuth(r, id.Email, store.AuthEventSessionsEnd, store.AuthOutcomeOK)
	}
	// Signing out ends this session on the gateway, not only in this
	// browser.
	if ok {
		s.endThisSession(w, r, id)
	}
	s.sessions.ClearSession(w)
	// A pending admin notice belongs to the person signing out; on a shared
	// browser the next admin must not see it.
	s.clearNotice(w)
	http.Redirect(w, r, s.loginURL(rd), http.StatusFound)
}

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
	// A card whose group has become staff only since it was made must not
	// grant a session. grantBreakGlass checks again for the one-tap activation;
	// checking here as well keeps the denial page from offering such a card.
	if s.refuseRetargetedCard(w, r, code, ip, ua, now) {
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

// refuseRetargetedCard refuses a card whose group has become a staff-only list
// (or one filled from a feed) since the card was made. A card is refused such
// a target when it is made, but a list becomes staff only as soon as it is given an app
// role other than User, and a card is a credential that anyone who
// photographs it can use. The scan is audited and the administrators are
// told, so that they replace the card; the person scanning sees the same
// neutral page as for a revoked card. It reports whether it refused.
func (s *Server) refuseRetargetedCard(w http.ResponseWriter, r *http.Request, code store.BreakGlassCode, ip, ua string, now time.Time) bool {
	if _, refused := s.targetRefusal(r.Context(), code.TargetGroup); !refused {
		return false
	}
	if err := s.store.RecordBreakGlassEvent(r.Context(), store.BreakGlassEvent{
		CodeID: code.ID, Label: code.Label, ClientIP: ip,
		UserAgent: ua, Outcome: store.OutcomeRefusedTarget,
	}); err != nil {
		log.Printf("break-glass record refused event for %q: %v", code.Label, err)
	}
	// Anyone holding a photo of the card can post it again and again, so the
	// administrators are told about a refused card once an hour at most; each
	// refusal is still recorded above.
	if s.refusedNotices.due(code.ID, now) {
		_, notifyEmails, webhookURL := s.effectiveSettings(r.Context())
		breakglass.NewNotifier(s.sender, notifyEmails, webhookURL, s.cfg.BreakGlassWebhookTimeout).
			Notify(breakglass.UseEvent{
				Label: code.Label, TargetGroup: code.TargetGroup, Outcome: store.OutcomeRefusedTarget,
				ClientIP: ip, UserAgent: ua, Time: now,
			})
	}
	log.Printf("break-glass refused (target %q is now refused) for %q from %s", code.TargetGroup, code.Label, ip)
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
	if s.refuseRetargetedCard(w, r, code, ip, ua, now) {
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
			Label: code.Label, TargetGroup: code.TargetGroup, Outcome: store.OutcomeGranted,
			ClientIP: ip, UserAgent: ua, Time: now,
		})

	groups := authz.BuildGroups(code.TargetGroup, nil)
	principal := "breakglass:" + code.Label
	if err := s.startSession(w, r, session.Identity{Email: principal, Groups: groups, Kind: session.KindBreakGlass, Card: code.ID}, ttl, now); err != nil {
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

// handleLogo serves the global branding logo for the public login pages, at
// /logo.img and as the favicon at /favicon.ico. Returns 404 when no logo is
// configured, so a browser shows its default icon rather than an empty one.
func (s *Server) handleLogo(w http.ResponseWriter, r *http.Request) {
	logo, mime, v, err := s.siteLogo(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if len(logo) == 0 {
		http.NotFound(w, r)
		return
	}
	// The sign-in pages link the logo as /logo.img?v=<version of its bytes>,
	// so that URL names one exact image and can be cached for a year without a
	// round trip. Any other request (no v, or a v from a replaced logo)
	// revalidates by ETag, so an out-of-date or invented v can never pin a
	// stale logo. The logo is shown to anyone on the public sign-in pages, so
	// shared caches may keep it.
	etag := `"` + v + `"`
	w.Header().Set("ETag", etag)
	if r.URL.Query().Get("v") == v {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	// The image headers go on the 304 too: a browser refreshes its stored
	// copy's headers from a 304, which must not drop the sandbox policy.
	setImageHeaders(w, mime)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Write(logo)
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
	setImageHeaders(w, mime)
	w.Write(data)
}

// setImageHeaders sets the headers writeImage sends, for a handler that may
// answer 304 instead of writing the bytes.
func setImageHeaders(w http.ResponseWriter, mime string) {
	if mime == "" {
		mime = "application/octet-stream"
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("Content-Disposition", "inline")
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
