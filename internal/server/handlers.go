package server

import (
	"context"
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
		if s.sessions.NeedsRenew(id, now) {
			// Re-check policy at renewal so access revocation actually takes
			// effect: a principal who is no longer permitted (removed from the
			// admin list, or whose domain was de-listed) has their session
			// cleared instead of silently extended. Recomputing groups also
			// picks up membership and demotion changes. Break-glass sessions
			// never reach here (NeedsRenew is false for them).
			role := s.policy.Role(id.Email)
			if role == authz.RoleDeny {
				s.sessions.ClearSession(w)
				s.redirectToLogin(w, r)
				return
			}
			groups := s.computeGroups(r.Context(), id.Email, role)
			_ = s.sessions.IssueSessionTTL(w, id.Email, groups, id.Kind, s.sessions.SessionTTL(id), now)
			// Reflect the freshly computed set in this response too, not just
			// the renewed cookie, so a demotion takes effect immediately.
			id.Groups = groups
		}
		// Per-app authorization. The app's Caddy snippet declares who may reach it
		// in a single X-Auth-Policy header set with header_up (replace semantics),
		// so a client can't inject or widen it; the gateway enforces the union. An
		// authenticated-but-unallowed principal is sent to a denial page, NOT back
		// to login — they are already signed in; logging in again wouldn't help and
		// would clobber a working (e.g. break-glass) session. Their cookie is left
		// untouched, so access to apps they *are* allowed on keeps working.
		reqDomains, reqGroups := parsePolicy(r.Header.Get(headerPolicy))
		s.warnLegacyPolicy(r)
		if !authz.CanAccessApp(id.Email, id.Groups, id.Kind == session.KindBreakGlass,
			reqDomains, reqGroups) {
			s.redirectToDenied(w, r)
			return
		}
		// These headers are the identity passed to the upstream app. Caddy
		// strips any client-supplied copies before re-adding ours.
		w.Header().Set("Remote-User", id.Email)
		w.Header().Set("Remote-Email", id.Email)
		w.Header().Set("Remote-Groups", id.Groups)
		w.WriteHeader(http.StatusOK)
		return
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
	reqDomains, _ := parsePolicy(r.Header.Get(headerPolicy))
	if v := clampHint(reqDomains); v != "" {
		loginURL += "&rqd=" + url.QueryEscape(v)
		// Optional friendly label to display instead of enumerating domains.
		if lbl := clampHint(r.Header.Get(headerDomainLabel)); lbl != "" {
			loginURL += "&dlabel=" + url.QueryEscape(lbl)
		}
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
	if id, ok := s.sessions.ReadSession(r, now); ok {
		if id.Kind == session.KindBreakGlass {
			data.BreakGlass = true
			// principal is "breakglass:<label>"; show the human label.
			data.Identity = strings.TrimPrefix(id.Email, "breakglass:")
		} else {
			data.Identity = id.Email
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

// handleRequest sends an OTP code. To avoid leaking which addresses are
// permitted, it always responds with the enter-code page regardless of whether
// the email is allowed.
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
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
	alt, altLabel := r.PostFormValue("alt"), r.PostFormValue("altlabel")

	if !validEmail(emailAddr) {
		data := pageData{Error: "Please enter a valid email address.", Redirect: rd, Remember: remember}
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
	if rqd != "" && !authz.CanAccessApp(emailAddr, "", false, rqd, "") {
		data := pageData{
			Error:    "This app is only available to " + domainLabel(rqd, dlabel) + " email addresses. Please sign in with one of those.",
			Redirect: rd, Remember: remember,
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
	if s.policy.Allowed(emailAddr) && s.emailLimiter.Allow(emailAddr) {
		if err := s.sendCode(r, emailAddr, now); err != nil {
			log.Printf("send code to %s: %v", emailAddr, err)
		}
	} else if err := s.storeDecoyCode(r.Context(), emailAddr, now); err != nil {
		log.Printf("store decoy code for %s: %v", emailAddr, err)
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
	msg := s.buildCodeEmail(r.Context(), emailAddr, code)
	go func() {
		// Detached context: the originating request is already answered.
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
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

// handleVerifyCode checks the submitted OTP code and, on success, issues a
// session (or starts the admin TOTP step).
func (s *Server) handleVerifyCode(w http.ResponseWriter, r *http.Request) {
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
	res, err := s.store.ConsumeCode(r.Context(), st.Email, s.hashCode(code), s.cfg.OTPMaxAttempts, now)
	if err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong", Redirect: rd})
		return
	}

	switch res {
	case store.ConsumeOK:
		role := s.policy.Role(st.Email)
		if role == authz.RoleDeny {
			s.sessions.ClearState(w)
			s.render(w, http.StatusForbidden, "login", pageData{Error: "This account is not permitted.", Redirect: rd})
			return
		}
		if role == authz.RoleAdmin && s.cfg.TOTPEnabled {
			s.startTOTP(w, r, st.Email, role, rd, st.Remember, now)
			return
		}
		s.completeLogin(w, r, st.Email, role, rd, st.Remember, now)
	case store.ConsumeMismatch:
		s.render(w, http.StatusUnauthorized, "code", pageData{
			Error: "Incorrect code. Please try again.", Email: st.Email, Redirect: rd,
		})
	case store.ConsumeTooManyAttempts:
		s.sessions.ClearState(w)
		s.render(w, http.StatusUnauthorized, "login", pageData{
			Error: "Too many incorrect attempts. Please request a new code.", Redirect: rd,
		})
	default: // ConsumeExpired, ConsumeNoCode
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
	now := s.now()
	// Same dual-carrier scheme as handleVerifyCode: prefer the validated rd
	// posted by the TOTP form over the (clobberable, OTP_TTL-lived) pending
	// cookie, and keep the destination alive when the cookie is gone.
	postedRD := authz.SafeRedirect(r.PostFormValue("rd"), s.cfg.Domain, "")
	p, ok := s.sessions.ReadPending(r, now)
	if !ok {
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
	secret, ok, err := s.getTOTPSecret(r.Context(), p.Email)
	if err != nil || !ok {
		s.restartLogin(w, r, rd)
		return
	}
	code := strings.TrimSpace(r.PostFormValue("code"))
	if !totp.Validate(code, secret) {
		s.render(w, http.StatusUnauthorized, "totp", pageData{
			Error: "Incorrect code. Please try again.", Redirect: rd,
		})
		return
	}
	// A TOTP code stays valid for its whole ~30s step; reject a second use of the
	// same code so a sniffed/phished code can't be replayed within that window.
	if !s.totpReplay.use(p.Email, code) {
		s.render(w, http.StatusUnauthorized, "totp", pageData{
			Error: "That code has already been used. Wait for your authenticator to show a new one.", Redirect: rd,
		})
		return
	}
	s.completeLogin(w, r, p.Email, p.Role, rd, p.Remember, now)
}

// servedTarget validates rawURL as a post-login destination the gateway can
// actually serve: an absolute https URL on a SUBDOMAIN of the server domain. The
// bare apex is rejected on purpose — this gateway serves subdomains
// (auth.<domain>, app.<domain>), and a bare apex commonly has no TLS certificate,
// so sending a freshly signed-in user there strands them on a browser security
// error. Returns the normalised URL and true when usable.
func (s *Server) servedTarget(rawURL string) (string, bool) {
	target, ok := authz.ValidateRedirect(rawURL, s.cfg.Domain)
	if !ok {
		return "", false
	}
	u, err := url.Parse(target)
	if err != nil {
		return "", false
	}
	if strings.EqualFold(u.Hostname(), strings.TrimPrefix(s.cfg.Domain, ".")) {
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
		// A real admin session gets an Admin link here; a break-glass session
		// never does (it can't reach the admin UI anyway — see requireAdmin).
		data.IsAdmin = authz.HasGroup(id.Groups, authz.RoleAdmin)
	}
	if target, ok := s.servedTarget(s.cfg.DefaultRedirect); ok {
		data.Redirect = target // rendered as a "Continue" link
	}
	s.render(w, http.StatusOK, "welcome", data)
}

// completeLogin bakes the group set, issues the session cookie (using the
// remember-me lifetime when requested), and redirects to the target.
func (s *Server) completeLogin(w http.ResponseWriter, r *http.Request, emailAddr, role, rd string, remember bool, now time.Time) {
	groups := s.computeGroups(r.Context(), emailAddr, role)
	ttl := s.cfg.SessionTTL
	if remember {
		ttl = s.cfg.SessionRememberTTL
	}
	if err := s.sessions.IssueSessionTTL(w, emailAddr, groups, "", ttl, now); err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong", Redirect: rd})
		return
	}
	s.sessions.ClearState(w)
	s.sessions.ClearPending(w)
	http.Redirect(w, r, s.loginRedirect(rd), http.StatusFound)
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

// handleLogoutConfirm renders a sign-out confirmation for GET /logout (a typed
// or clicked URL). The logout itself is POST-only (handleLogout), so it can't be
// triggered by a cross-site GET, link, or redirect; this page just gives that
// POST a button instead of a 404. A request without a session has nothing to
// confirm, so it's sent to the login page.
func (s *Server) handleLogoutConfirm(w http.ResponseWriter, r *http.Request) {
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
	}
	s.render(w, http.StatusOK, "logout", data)
}

// handleLogout clears the session. POST-only (see handleLogoutConfirm) so a
// cross-site GET cannot force a logout.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.sessions.ClearSession(w)
	http.Redirect(w, r, s.cfg.PublicURL+"/login", http.StatusFound)
}

// handleBreakGlass grants emergency access from a scanned QR code. It is public
// (the token in the URL is the only credential, by design), instant (no second
// factor), rate-limited per IP, audited synchronously, and notifies admins
// asynchronously. The granted session is short-lived and never renewed.
func (s *Server) handleBreakGlass(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	ip := clientIP(r)
	ua := clampUserAgent(r.UserAgent())
	if !s.ipLimiter.Allow(ip) {
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
	if err := s.sessions.IssueSessionTTL(w, principal, groups, session.KindBreakGlass, ttl, now); err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong"})
		return
	}
	rd := authz.SafeRedirect(code.Redirect, s.cfg.Domain, s.cfg.BreakGlassRedirect)
	http.Redirect(w, r, s.loginRedirect(rd), http.StatusFound)
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
	writeImage(w, b.LogoType, b.Logo)
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

// parsePolicy extracts the per-app requirement from the X-Auth-Policy header. The
// value is a ";"-separated set of key=value fields; "domains" and "groups" each
// hold a space/comma-separated allow-list (both safe charsets, so no escaping is
// needed). Unknown fields (a future flag, or the "any" sentinel a plain
// `protected` guard sets) are ignored. An absent header yields empty
// requirements — i.e. bare `protected` semantics (any signed-in user, break-glass
// denied).
func parsePolicy(h string) (domains, groups string) {
	for _, field := range strings.Split(h, ";") {
		k, v, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "domains":
			domains = strings.TrimSpace(v)
		case "groups":
			groups = strings.TrimSpace(v)
		}
	}
	return
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
