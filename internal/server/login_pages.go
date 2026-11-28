// The sign-in, welcome and denied pages, and the hints and branding they show.

package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
)

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
// the staff domains (see staffDomains), so a DIRECT visit (no route rqd) still
// tells the user which domain to use. It runs after applyAccessHint, so a
// route-supplied requirement (HintDomains/RequireDomains) always wins; this only
// fills the gaps:
//   - HintDomains: the "This page is for <domains> email addresses" line, from
//     the staff domains when no route set one.
//   - EmailPlaceholder: you@<first effective domain> — the route requirement if
//     present, else the first staff domain — so the example matches who may
//     sign in. Left empty (→ generic placeholder) when there is no domain.
func (s *Server) applyLoginBranding(ctx context.Context, d *pageData) {
	// Not at a role guard, where the staff domains say nothing about who
	// holds the role; only the domains of its domain groups are suggested.
	if d.RoleGuard {
		if dom := firstDomain(d.RoleHintDomains); dom != "" && d.EmailPlaceholder == "" {
			d.EmailPlaceholder = "you@" + dom
		}
		return
	}
	// A login headed to a host open to guests welcomes a stranger's address,
	// so there is no domain to advertise: leave the hint empty and fall back
	// to the generic placeholder. (A route may still have set
	// RequireDomains/HintDomains above; those win and are kept.)
	if s.isOpenHost(ctx, d.Redirect) {
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
		if _, ok := s.ownSession(r); ok {
			data.SessionsLink = true
			if s.cfg.PasskeysEnabled {
				data.Passkey = &passkeyPage{Next: s.passkeysURL()}
			}
		}
	}
	if target, ok := s.servedTarget(s.cfg.DefaultRedirect); ok {
		data.Redirect = target // rendered as a "Continue" link
	}
	s.render(w, http.StatusOK, "welcome", data)
}

// isOpenHost reports whether a sign-in's destination is on a host open to
// guests (openToGuests), where an address that is not staff and holds no
// role may sign in as a guest. The destination is rd, and must be on the
// domain. A sign-in that names none (a direct visit to the sign-in page), or
// names one of the gateway's own pages (Your sessions, Your passkeys, the
// links in its emails), is decided as one to DEFAULT_REDIRECT, so a guest
// signed out there can sign in again where a direct visit could. The auth
// host itself is never an app's host (the manifest is refused at start if it
// names it). The host decides only where a stranger may start, never what a
// guest reaches.
func (s *Server) isOpenHost(ctx context.Context, rd string) bool {
	host := s.destinationHost(rd)
	if host == "" || host == s.authHost() {
		host = s.destinationHost(s.cfg.DefaultRedirect)
	}
	if host == s.authHost() {
		return false
	}
	return s.openToGuests(ctx, host)
}

// destinationHost is the lower-case host of a destination on the domain, or
// "" for one that ValidateRedirect refuses.
func (s *Server) destinationHost(rd string) string {
	target, ok := authz.ValidateRedirect(rd, s.cfg.Domain)
	if !ok {
		return ""
	}
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
