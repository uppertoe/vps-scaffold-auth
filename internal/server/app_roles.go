package server

import (
	"context"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/roles"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// The app-roles guard. A guard that names an app sends X-Auth-App, and the
// role its path needs in X-Auth-Role (the user role when absent), both with
// header_up so a client's copies are replaced. /verify then decides by who
// holds that role (roles.Held), not by X-Auth-Policy. A request carrying both
// X-Auth-App (or X-Auth-Role) and X-Auth-Policy is refused: no shipped guard
// sends both, so it is a misconfigured guard or a client adding a header.
const (
	headerApp   = "X-Auth-App"
	headerRole  = "X-Auth-Role"
	headerRoles = "Remote-Roles"
)

// roleCacheTTL is how long /verify trusts its in-memory copy of the role
// assignments, domain rules and cards before reading them again. Changes made
// through the admin pages call forgetRoles, so they apply at once.
const roleCacheTTL = 15 * time.Second

// roleState is the store's role data as /verify reads it.
type roleState struct {
	assignments []store.RoleAssignment
	domains     map[string][]string
	cards       map[int64]store.BreakGlassCode
	// invited are the addresses with an open invitation, who may sign in.
	invited map[string]bool
	// invitedRoles are the app roles with an open invitation, keyed by
	// roleKey.
	invitedRoles map[string]bool
}

func roleKey(app, role string) string { return app + "\x00" + role }

type roleCache struct {
	mu    sync.Mutex
	at    time.Time
	state roleState
	ok    bool
}

// loadAppRoles reads APP_ROLES_FILE once at start. A missing or unreadable
// file leaves the manifest empty, so every guard that names an app is refused
// until it is fixed; an empty setting turns the model off.
func loadAppRoles(path, domain string) roles.Manifest {
	if path == "" {
		return roles.Manifest{}
	}
	f, err := os.Open(path)
	if err != nil {
		log.Printf("app roles: %v; every guard that names an app will be refused", err)
		return roles.Manifest{}
	}
	defer f.Close()
	return roles.ParseManifest(f, domain, log.Printf)
}

// rolesOn reports whether the app-roles model is configured.
func (s *Server) rolesOn() bool { return s.cfg.AppRolesFile != "" }

// forgetRoles drops the cached role data, so the next decision reads it again.
func (s *Server) forgetRoles() {
	s.roleCache.mu.Lock()
	s.roleCache.ok = false
	s.roleCache.mu.Unlock()
}

// roleData returns the role assignments, domain rules and cards, from memory
// when the copy is recent. A failed read keeps the last good copy; with none,
// it returns an empty state, which admits nobody through a role.
func (s *Server) roleData(ctx context.Context) roleState {
	now := s.now()
	s.roleCache.mu.Lock()
	defer s.roleCache.mu.Unlock()
	if s.roleCache.ok && now.Sub(s.roleCache.at) < roleCacheTTL && !now.Before(s.roleCache.at) {
		return s.roleCache.state
	}
	as, err := s.store.ListRoleAssignments(ctx, "")
	if err != nil {
		log.Printf("app roles: reading assignments: %v", err)
		return s.roleCache.state
	}
	domains, err := s.store.ListGroupDomains(ctx)
	if err != nil {
		log.Printf("app roles: reading domain rules: %v", err)
		return s.roleCache.state
	}
	codes, err := s.store.ListBreakGlassCodes(ctx)
	if err != nil {
		log.Printf("app roles: reading cards: %v", err)
		return s.roleCache.state
	}
	cards := make(map[int64]store.BreakGlassCode, len(codes))
	for _, c := range codes {
		cards[c.ID] = store.BreakGlassCode{ID: c.ID, App: c.App, Role: c.Role, Status: c.Status}
	}
	invites, err := s.store.ListInvitations(ctx)
	if err != nil {
		log.Printf("app roles: reading invitations: %v", err)
		return s.roleCache.state
	}
	invited, invitedRoles := map[string]bool{}, map[string]bool{}
	for _, v := range invites {
		if v.Open(now) {
			invited[v.Email] = true
			invitedRoles[roleKey(v.App, v.Role)] = true
		}
	}
	s.roleCache.state = roleState{assignments: as, domains: domains, cards: cards, invited: invited, invitedRoles: invitedRoles}
	s.roleCache.at = now
	s.roleCache.ok = true
	return s.roleCache.state
}

// roleEnv is the decision environment for the current role data.
func (s *Server) roleEnv(st roleState) roles.Env {
	return roles.Env{Networks: s.cfg.NetworkRanges, Domains: st.domains, Now: s.now()}
}

// wantsRoles reports whether the guard named an app (or a role).
func wantsRoles(r *http.Request) bool {
	return r.Header.Get(headerApp) != "" || r.Header.Get(headerRole) != ""
}

// roleRequest reads and checks the app and role a guard asks for. It logs and
// returns ok=false for a guard that also sends X-Auth-Policy, or that names an
// app or role the manifest does not declare.
func (s *Server) roleRequest(r *http.Request) (app, role string, ok bool) {
	app = strings.TrimSpace(r.Header.Get(headerApp))
	role = strings.TrimSpace(r.Header.Get(headerRole))
	if role == "" {
		role = roles.UserRole
	}
	host := r.Header.Get("X-Forwarded-Host")
	if r.Header.Get(headerPolicy) != "" {
		log.Printf("warning: refusing a guard that sends both X-Auth-App and X-Auth-Policy for %q", host)
		return "", "", false
	}
	if !s.appRoles.Has(app, role) {
		log.Printf("warning: refusing a guard for app %q role %q on %q: not in the app roles manifest", app, role, host)
		return "", "", false
	}
	return app, role, true
}

// clientAddr is the client address the gateway trusts, as a netip.Addr.
func clientAddr(r *http.Request) netip.Addr {
	a, err := netip.ParseAddr(clientIP(r))
	if err != nil {
		return netip.Addr{}
	}
	return a
}

// heldRoles returns the roles a session holds in app. Lists come from the
// session's groups, which are kept current by renewal (see groupsStale).
func (s *Server) heldRoles(r *http.Request, id *session.Identity, app string) []string {
	st := s.roleData(r.Context())
	sub := roles.Subject{
		Session:    true,
		Email:      id.Email,
		Guest:      id.Kind == session.KindGuest,
		BreakGlass: id.Kind == session.KindBreakGlass,
		Lists:      listSet(id.Groups),
		Addr:       clientAddr(r),
	}
	if sub.BreakGlass {
		if c, ok := st.cards[id.Card]; ok && c.Status == store.BreakGlassActive {
			sub.CardApp, sub.CardRole = c.App, c.Role
		}
	}
	return roles.Held(app, sub, st.assignments, s.roleEnv(st))
}

func listSet(groups string) map[string]bool {
	out := map[string]bool{}
	for _, g := range strings.Split(groups, ",") {
		if g = strings.TrimSpace(g); g != "" {
			out[g] = true
		}
	}
	return out
}

// verifyByRole decides a signed-in request whose guard names an app. It
// mirrors the legacy path: a refusal re-reads the person's groups once, in
// case an administrator has just added them to a list.
func (s *Server) verifyByRole(w http.ResponseWriter, r *http.Request, id *session.Identity, now time.Time, renewed bool) {
	app, role, ok := s.roleRequest(r)
	if !ok {
		s.redirectToDenied(w, r)
		return
	}
	if id.Kind == session.KindGuest {
		id.Groups = s.guestGroupsNow(id)
	}
	held := s.heldRoles(r, id, app)
	if !roles.Admits(held, role) {
		if renewed || (id.Kind != "" && id.Kind != session.KindGuest) || s.groupRecheck.fresh(id.Email, id.Groups, now) {
			s.redirectToDenied(w, r)
			return
		}
		gen := s.groupRecheck.generation()
		current, ok := s.currentGroups(r, id)
		if !ok {
			s.redirectToDenied(w, r)
			return
		}
		if current == id.Groups {
			s.groupRecheck.confirm(id.Email, id.Groups, now, gen)
			s.redirectToDenied(w, r)
			return
		}
		var groups *string
		if current != "" {
			groups = &current
		}
		if !s.renewSessionWith(w, r, id, now, groups) {
			return
		}
		if held = s.heldRoles(r, id, app); !roles.Admits(held, role) {
			s.redirectToDenied(w, r)
			return
		}
	}
	if s.roleWantsAdminStep(id) {
		// A gateway administrator without a recent second step holds no
		// role above user, as the older guards gave them no admin tier
		// (tierRole): a route that needs such a role sends them to the
		// admin door, and elsewhere the app sees only the user role.
		if role != roles.UserRole {
			s.redirectToStepUp(w, r)
			return
		}
		held = []string{roles.UserRole}
	}
	s.access.record(r.Context(), id.Email, r.Header.Get("X-Forwarded-Host"), id.Kind, now)
	w.Header().Set("Remote-User", id.Email)
	w.Header().Set("Remote-Email", id.Email)
	w.Header().Set("Remote-Groups", id.Groups)
	w.Header().Set(headerRoles, strings.Join(held, ","))
	w.WriteHeader(http.StatusOK)
}

// roleWantsAdminStep reports whether a session is a gateway administrator's
// whose second step is not recent. Such a session holds no app role above
// user until the step is taken, so an app's admin pages keep the protection
// the older groups=admin guard gave them.
func (s *Server) roleWantsAdminStep(id *session.Identity) bool {
	return id.Kind == "" && s.renewalRole(id) == authz.RoleAdmin && !s.adminStepFresh(id)
}

// verifyByNetwork admits a request with no session when its guard names an
// app role that is given to a network the client is inside. It reports
// whether it wrote a response; when it did not, the caller sends the request
// to sign in as before.
func (s *Server) verifyByNetwork(w http.ResponseWriter, r *http.Request) bool {
	app, role, ok := s.roleRequest(r)
	if !ok {
		s.redirectToDenied(w, r)
		return true
	}
	st := s.roleData(r.Context())
	held := roles.Held(app, roles.Subject{Addr: clientAddr(r)}, st.assignments, s.roleEnv(st))
	if !roles.Admits(held, role) {
		return false
	}
	// No identity: the app sees an empty Remote-User and the roles the
	// network holds.
	w.Header().Set(headerRoles, strings.Join(held, ","))
	w.WriteHeader(http.StatusOK)
	return true
}

// roleLoginHint is what a role guard adds to the login URL, in the parameters
// a domain guard uses (see redirectToLogin). When the role is held only by
// domain groups, it carries their domains as rqd, so the sign-in page hints
// them and /request declines an address at none of them, exactly as for
// protected_domains. Otherwise it carries rqr=1, which marks a role guard so
// the page does not fall back to the allow-list's domains, and rhd, the
// domains of any domain groups among the holders, which the page hints but
// never declines on: an address that holds no role is then sent no code and
// sees the ordinary "check your email" page, so the page does not reveal who
// holds the role. Like the domain guard's hint, this is a courtesy and not a
// boundary: /verify decides.
func (s *Server) roleLoginHint(r *http.Request) string {
	app := strings.TrimSpace(r.Header.Get(headerApp))
	role := strings.TrimSpace(r.Header.Get(headerRole))
	if role == "" {
		role = roles.UserRole
	}
	if r.Header.Get(headerPolicy) != "" || !s.appRoles.Has(app, role) {
		return ""
	}
	st := s.roleData(r.Context())
	domains, only := roles.SignInDomains(app, role, st.assignments, s.roleEnv(st))
	if only {
		// A card or an open invitation for the role admits someone outside
		// the domains too.
		for _, c := range st.cards {
			if c.App == app && c.Status == store.BreakGlassActive && (role == roles.UserRole || c.Role == role) {
				only = false
			}
		}
		for _, rl := range s.appRoles.Apps[app].RoleOrder {
			if (rl == role || role == roles.UserRole) && st.invitedRoles[roleKey(app, rl)] {
				only = false
			}
		}
	}
	hint := clampHint(strings.Join(domains, " "))
	if hint != "" && only {
		return "&rqd=" + url.QueryEscape(hint)
	}
	out := "&rqr=1"
	if hint != "" {
		out += "&rhd=" + url.QueryEscape(hint)
	}
	return out
}

// mayHoldRoleNow reports whether email holds a role through a domain group,
// a list or a current person assignment, or has an open invitation, reading
// its lists from the store. It is used when a person signs in. Signing in
// does not accept an invitation: only its link and code do.
func (s *Server) mayHoldRoleNow(ctx context.Context, email string) bool {
	if !s.rolesOn() {
		return false
	}
	lists, err := s.store.GroupsForEmail(ctx, email)
	if err != nil {
		log.Printf("app roles: reading groups for sign-in: %v", err)
		return false
	}
	set := make(map[string]bool, len(lists))
	for _, l := range lists {
		set[l] = true
	}
	st := s.roleData(ctx)
	return st.invited[email] || roles.MaySignIn(email, set, st.assignments, s.roleEnv(st))
}

// mayHoldRoleSnapshot is mayHoldRoleNow from the session's own groups, with
// no store read, for the check made on every request (policyWithdrawn).
func (s *Server) mayHoldRoleSnapshot(ctx context.Context, id *session.Identity) bool {
	if !s.rolesOn() {
		return false
	}
	st := s.roleData(ctx)
	return st.invited[id.Email] || roles.MaySignIn(id.Email, listSet(id.Groups), st.assignments, s.roleEnv(st))
}

// loginRole is the sign-in decision: the allow-list and administrators as
// before, and also an address that holds an app role, which signs in as an
// ordinary user (and not as a guest, even on an open host).
func (s *Server) loginRole(ctx context.Context, email string, openHost bool) string {
	role := s.policy.LoginRole(email, openHost)
	if role == authz.RoleUser || role == authz.RoleAdmin {
		return role
	}
	if s.mayHoldRoleNow(ctx, email) {
		return authz.RoleUser
	}
	return role
}

// currentRole is policy.Role made role-aware the way loginRole is: an address
// the allow-list refuses but that holds an app role through a domain group, a
// list or a current person assignment counts as an ordinary user. With the
// app-roles model off it is exactly policy.Role.
func (s *Server) currentRole(ctx context.Context, email string) string {
	role := s.policy.Role(email)
	if role == authz.RoleDeny && s.mayHoldRoleNow(ctx, email) {
		return authz.RoleUser
	}
	return role
}
