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

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

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

// authHost is the gateway's own host, from AUTH_PUBLIC_URL.
func (s *Server) authHost() string {
	u, err := url.Parse(s.cfg.PublicURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
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
