// The forward-auth check (/verify) and the scheduled renewal of a session.

package server

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
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
	// The domain groups decide who is staff; while they have never been
	// read, the session is left as it is.
	if s.rolesUnavailable(r.Context()) {
		s.renderUnavailable(w, s.reconstructOriginalURL(r))
		return false
	}
	role := s.renewalRole(id)
	if role == authz.RoleDeny && s.guestsStranded(r.Context()) && s.keptOnlyByGuests(id) {
		// The manifest has lost the app whose role guests hold: a fault in
		// the configuration, not a decision to close guest sign-in. A
		// session only guests would keep is left as it is, as while the
		// role data cannot be read.
		s.renderUnavailable(w, s.reconstructOriginalURL(r))
		return false
	}
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
	// so stays confined to roles held by guests). The changes are between a
	// person's own kinds: an address that now holds a role but is not staff
	// becomes a member, and a member who is now staff becomes an ordinary
	// session. A staff session becomes a guest's only under the transitional
	// rule in renewalRole.
	kind := id.Kind
	switch {
	case role == authz.RoleMember:
		kind = session.KindMember
	case role == authz.RoleGuest:
		kind = session.KindGuest
	case kind == session.KindMember:
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
		return "", true // renewSessionWith ends the session, or answers 503
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
		// Before the domain groups have ever been read, the gateway cannot
		// tell staff from strangers: it answers 503 and keeps the session,
		// rather than end it or treat staff as outsiders (see
		// rolesUnavailable).
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
// normal session whose address is no longer known (its domain has left every
// domain group that holds a role) but holds an app role becomes a member at
// once, one carried over as a guest's (renewalRole) does so at once, and a
// member whose address is now known becomes an ordinary session at once.
func (s *Server) tierStale(id *session.Identity) bool {
	switch id.Kind {
	case "":
		role := s.renewalRole(id)
		if role == authz.RoleMember || role == authz.RoleGuest {
			return true
		}
		return authz.HasGroup(id.Groups, authz.RoleAdmin) != (s.tierRole(id, role) == authz.RoleAdmin)
	case session.KindMember:
		return s.known(context.Background(), id.Email)
	}
	return false
}

// policyWithdrawn reports whether the current policy refuses a normal or
// guest session's person: their domain has been taken off every domain group
// that holds a role and they hold no app role and are not listed as an
// administrator, or no app's role is held by guests any longer. The domain
// groups and roles come from the cached role data, so this is a lookup in
// memory.
// Break-glass sessions are not policy logins and end at their own short
// lifetime or when their card is revoked.
func (s *Server) policyWithdrawn(id *session.Identity) bool {
	if !personSession(id) && id.Kind != session.KindGuest {
		return false
	}
	return s.renewalRole(id) == authz.RoleDeny
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
// session is re-checked against knownRole, which is where revocation takes
// effect. A guest is, by definition, not staff, so asking knownRole would end
// every guest session at its first renewal; instead the guest's address is
// re-checked only for plausibility and it stays RoleGuest while some app's
// role is held by guests. It never steps up to admin here: even if the
// address has since been made an admin, the guest session keeps its kind and
// must sign in again to become one.
func (s *Server) renewalRole(id *session.Identity) string {
	ctx := context.Background()
	if id.Kind == session.KindGuest {
		// Taking guests off every app ends every guest session at its next
		// request (see policyWithdrawn), the same way taking a domain off
		// every domain group ends a staff session.
		if s.guestsAnywhere(ctx) && authz.GuestEligible(id.Email) {
			return authz.RoleGuest
		}
		return authz.RoleDeny
	}
	// A member who is now known renews as an ordinary user or administrator
	// (renewSessionWith changes its kind).
	role := s.knownRole(ctx, id.Email)
	if role == authz.RoleDeny && personSession(id) && s.mayHoldRoleSnapshot(ctx, id) {
		// Not known, but holds an app role through a domain group, a list or
		// a current person assignment (app_roles.go): a member.
		return authz.RoleMember
	}
	if role == authz.RoleDeny && s.carriedOverAsGuest(ctx, id) {
		return authz.RoleGuest
	}
	return role
}

// guestsFromRolesRelease names the release that retired ALLOWED_EMAIL_DOMAINS
// and OPEN_REGISTRATION_HOSTS. The time it first ran on a server is recorded
// in the database (Server.guestsReleasedAt), so every session from before it
// can be told apart from one it started.
const guestsFromRolesRelease = "guests-from-roles"

// carriedOverAsGuest is a transitional rule, to be removed 90 days after the
// release first ran on the last server (SESSION_MAX_AGE on markbot; remove
// it, and guestsReleasedAt, after 1 March 2027). Under ALLOWED_EMAIL_DOMAINS,
// an address at any listed domain, or with "*" any address, signed in as
// staff. Without the setting, such a session would end at its next request,
// signing out every p.stonn user. Instead, a staff session that began before
// the release (an old signed cookie keeps its sign-in time when it is
// converted, so it counts too), whose address is no longer staff and holds no
// role through a list or a person assignment, becomes a guest's while some
// app's role is held by guests. A session started by this release never
// does: removing a domain from a domain group still ends its sessions, and a
// member is never made a guest.
func (s *Server) carriedOverAsGuest(ctx context.Context, id *session.Identity) bool {
	return s.mayCarryOver(id) && s.guestsAnywhere(ctx)
}

// mayCarryOver is carriedOverAsGuest without asking whether guests hold a
// role anywhere: a staff session from before the release with a plausible
// address.
func (s *Server) mayCarryOver(id *session.Identity) bool {
	return id.Kind == "" && id.Auth > 1 && !s.guestsReleasedAt.IsZero() && id.Auth <= s.guestsReleasedAt.Unix() &&
		authz.GuestEligible(id.Email)
}

// keptOnlyByGuests reports whether, of all the reasons a session could go
// on, only guests holding a role could keep it: it is a guest's, or a staff
// session that would carry over as one. Asked only once renewalRole has
// refused the session.
func (s *Server) keptOnlyByGuests(id *session.Identity) bool {
	return (id.Kind == session.KindGuest && authz.GuestEligible(id.Email)) || s.mayCarryOver(id)
}
