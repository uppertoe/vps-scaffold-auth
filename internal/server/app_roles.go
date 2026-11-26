package server

import (
	"context"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
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
// holds that role (roles.Held). A request that names no app is refused.
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
	// staff are the domains of the domain groups that hold at least one app
	// role, in staffOrder: the order of their groups' creation (oldest
	// first), and within a group the group's own order. With the
	// allow-list empty, an address at one of them is staff (knownRole).
	staff      map[string]bool
	staffOrder []string
	// domainRank orders every domain group's domains the same way, for the
	// hints a role guard gives.
	domainRank map[string]int
}

func roleKey(app, role string) string { return app + "\x00" + role }

type roleCache struct {
	mu    sync.Mutex
	at    time.Time
	state roleState
	ok    bool
	// have reports that state is a good copy: the role data has been read
	// at least once. Until then the gateway cannot tell who is staff.
	have bool
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
		cards[c.ID] = store.BreakGlassCode{ID: c.ID, App: c.App, Role: c.Role, Status: c.Status, TargetGroup: c.TargetGroup}
	}
	invites, err := s.store.ListInvitations(ctx)
	if err != nil {
		log.Printf("app roles: reading invitations: %v", err)
		return s.roleCache.state
	}
	groups, err := s.store.ListGroups(ctx)
	if err != nil {
		log.Printf("app roles: reading groups: %v", err)
		return s.roleCache.state
	}
	invited, invitedRoles := map[string]bool{}, map[string]bool{}
	for _, v := range invites {
		if v.Open(now) {
			invited[v.Email] = true
			invitedRoles[roleKey(v.App, v.Role)] = true
		}
	}
	st := roleState{assignments: as, domains: domains, cards: cards, invited: invited, invitedRoles: invitedRoles}
	st.staff, st.staffOrder, st.domainRank = staffFromGroups(groups, domains, as, s.appRoles.Has)
	s.roleCache.state = st
	s.roleCache.at = now
	s.roleCache.ok = true
	s.roleCache.have = true
	return s.roleCache.state
}

// roleDataLoaded is roleData, with ok false while the role data has never
// been read: the store failed at every attempt so far.
func (s *Server) roleDataLoaded(ctx context.Context) (roleState, bool) {
	st := s.roleData(ctx)
	s.roleCache.mu.Lock()
	defer s.roleCache.mu.Unlock()
	return st, s.roleCache.have
}

// staffFromGroups works out the staff domains: those of the domain groups
// that hold at least one app role the manifest declares (declared reports
// whether it does), ordered by their groups' creation, oldest first. An
// assignment left behind for an app or role the manifest no longer declares
// makes nobody staff. A domain-group assignment has no end date (the store
// refuses one), so holding a role is simply having an assignment. rank
// orders every domain group's domains the same way, whether or not the group
// holds a role.
func staffFromGroups(groups []store.Group, domains map[string][]string, as []store.RoleAssignment, declared func(app, role string) bool) (staff map[string]bool, order []string, rank map[string]int) {
	var dg []store.Group
	for _, g := range groups {
		if g.Kind == store.GroupKindDomain {
			dg = append(dg, g)
		}
	}
	sort.SliceStable(dg, func(i, j int) bool {
		if !dg[i].CreatedAt.Equal(dg[j].CreatedAt) {
			return dg[i].CreatedAt.Before(dg[j].CreatedAt)
		}
		return dg[i].Name < dg[j].Name
	})
	held := map[string]bool{}
	for _, a := range as {
		if a.Kind == store.AssignDomainGroup && declared(a.App, a.Role) {
			held[a.Ref] = true
		}
	}
	staff, rank = map[string]bool{}, map[string]int{}
	for _, g := range dg {
		for _, d := range domains[g.Name] {
			if _, seen := rank[d]; !seen {
				rank[d] = len(rank)
			}
			if held[g.Name] && !staff[d] {
				staff[d] = true
				order = append(order, d)
			}
		}
	}
	return staff, order, rank
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
// returns ok=false for a guard that names an app or role the manifest does not declare, or that guards a host the
// manifest does not give the app (see roleRequestProblem).
func (s *Server) roleRequest(r *http.Request) (app, role string, ok bool) {
	app, role, problem := s.roleRequestProblem(r)
	if problem != "" {
		log.Printf("warning: refusing a guard for app %q role %q on %q: %s", app, role, r.Header.Get("X-Forwarded-Host"), problem)
		return "", "", false
	}
	return app, role, true
}

// roleRequestProblem is roleRequest's check without the log: the app and
// role asked for, and why the request is refused, or "" when it is not. A
// guard's host must be one of the app's hosts in the manifest, so a guard
// copied onto another site cannot borrow an app's roles.
func (s *Server) roleRequestProblem(r *http.Request) (app, role, problem string) {
	app = strings.TrimSpace(r.Header.Get(headerApp))
	role = strings.TrimSpace(r.Header.Get(headerRole))
	if role == "" {
		role = roles.UserRole
	}
	switch {
	case !s.appRoles.Has(app, role):
		return app, role, "not in the app roles manifest"
	case !s.appRoles.Apps[app].ServesHost(forwardedHost(r)):
		return app, role, "the host is not one of the app's hosts in the app roles manifest"
	}
	return app, role, ""
}

// forwardedHost is the host the guard runs on, as Caddy sets it, lower-case
// and without a port.
func forwardedHost(r *http.Request) string {
	h := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(h)
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
		Lists:      sessionLists(id),
		Addr:       clientAddr(r),
	}
	if sub.BreakGlass {
		if c, ok := st.cards[id.Card]; ok && c.Status == store.BreakGlassActive && cardIssuedAsNow(id, c) {
			sub.CardApp, sub.CardRole = c.App, c.Role
		}
	}
	return roles.Held(app, sub, st.assignments, s.roleEnv(st))
}

// cardIssuedAsNow reports whether a break-glass session carries the groups
// its card grants today. A session started before its card was moved from a
// group onto an app carries the group, and keeps only the group's sites
// until it ends: the card's app is read for it only once a new scan has
// issued a session without the group. The same holds when a scan read the
// card just before a move and issued the session just after it.
func cardIssuedAsNow(id *session.Identity, c store.BreakGlassCode) bool {
	return id.Groups == authz.BuildGroups(c.TargetGroup, nil)
}

// sessionLists are the lists a session's person belongs to: its groups
// without the tier token (user, admin or guest) and any other reserved name,
// which BuildGroups never takes from a stored group, so a list assignment
// matches real membership only.
func sessionLists(id *session.Identity) map[string]bool {
	out := map[string]bool{}
	for _, g := range strings.Split(id.Groups, ",") {
		if g = strings.TrimSpace(g); g != "" && !authz.IsReservedGroup(g) {
			out[g] = true
		}
	}
	return out
}

// verifyByRole decides a signed-in request whose guard names an app. A
// refusal re-reads the person's groups once, in case an administrator has
// just added them to a list.
func (s *Server) verifyByRole(w http.ResponseWriter, r *http.Request, id *session.Identity, now time.Time, renewed bool) {
	app, role, ok := s.roleRequest(r)
	if !ok {
		s.redirectToDenied(w, r)
		return
	}
	if id.Kind == session.KindGuest {
		id.Groups = s.guestGroupsNow(r.Context(), id)
	}
	held := s.heldRoles(r, id, app)
	if !roles.Admits(held, role) {
		if renewed || (!personSession(id) && id.Kind != session.KindGuest) || s.groupRecheck.fresh(id.Email, id.Groups, now) {
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
	s.access.record(r.Context(), id.Email, r.Header.Get("X-Forwarded-Host"), id.Kind, now)
	w.Header().Set("Remote-User", id.Email)
	w.Header().Set("Remote-Email", id.Email)
	w.Header().Set(headerRoles, strings.Join(held, ","))
	blankIdentity(w, "Remote-Groups")
	w.WriteHeader(http.StatusOK)
}

// blankIdentity sends each named identity header with an empty value. Apps
// decide by Remote-Roles, and the gateway sends no groups. A server's copy of
// auth.caddy may still copy a header the gateway does not send, and Caddy
// then hands the app its placeholder text, "{http.reverse_proxy.header.…}",
// rather than nothing; an empty header makes the copy empty too.
func blankIdentity(w http.ResponseWriter, names ...string) {
	for _, n := range names {
		w.Header()[n] = []string{""}
	}
}

// verifyByNetwork admits a request with no session when its guard names an
// app role that is given to a network the client is inside. It reports
// whether it wrote a response; when it did not, the caller sends the request
// to sign in as before.
//
// A guard naming an app or role the manifest does not declare, or guarding a host that is not the
// app's, admits nobody through a network and is sent to sign in like any
// other (see roleLoginHint), so a visitor with no session cannot tell
// declared names from undeclared ones; once signed in, it is refused.
func (s *Server) verifyByNetwork(w http.ResponseWriter, r *http.Request) bool {
	app, role, ok := s.roleRequest(r)
	if !ok {
		return false
	}
	st := s.roleData(r.Context())
	held := roles.Held(app, roles.Subject{Addr: clientAddr(r)}, st.assignments, s.roleEnv(st))
	if !roles.Admits(held, role) {
		return false
	}
	// No identity: the app sees an empty Remote-User and the roles the
	// network holds.
	w.Header().Set(headerRoles, strings.Join(held, ","))
	blankIdentity(w, "Remote-User", "Remote-Email", "Remote-Groups")
	w.WriteHeader(http.StatusOK)
	return true
}

// roleLoginHint is what a role guard adds to the login URL, in the parameters
// a domain guard uses (see redirectToLogin). When the role is held only by
// domain groups, it carries their domains as rqd, so the sign-in page hints
// them and /request declines an address at none of them. Otherwise it carries rqr=1, which marks a role guard so
// the page does not fall back to the allow-list's domains. When the role's
// assignments are domain groups only and a card or an open invitation also
// admits someone, it adds rhd, those domains, which the page hints but never
// declines on; the domains are the ones rqd would otherwise carry. Any other
// holder adds nothing, so an anonymous visitor learns of it no more than
// rqr=1 says. An address that holds no role is sent no code and sees the
// ordinary "check your email" page, so the page does not reveal who holds
// the role. An app or role the manifest does not declare is answered as a
// declared role with no hint, so names cannot be tried out. Like the domain
// guard's hint, this is a courtesy and not a boundary: /verify decides.
func (s *Server) roleLoginHint(r *http.Request) string {
	app := strings.TrimSpace(r.Header.Get(headerApp))
	role := strings.TrimSpace(r.Header.Get(headerRole))
	if role == "" {
		role = roles.UserRole
	}
	if _, _, problem := s.roleRequestProblem(r); problem != "" {
		return "&rqr=1"
	}
	st := s.roleData(r.Context())
	domains, only := roles.SignInDomains(app, role, st.assignments, s.roleEnv(st))
	domainsOnly := only
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
	sort.SliceStable(domains, func(i, j int) bool { return rankOf(st.domainRank, domains[i]) < rankOf(st.domainRank, domains[j]) })
	hint := clampHint(strings.Join(domains, " "))
	if hint != "" && only {
		return "&rqd=" + url.QueryEscape(hint)
	}
	out := "&rqr=1"
	if hint != "" && domainsOnly {
		out += "&rhd=" + url.QueryEscape(hint)
	}
	return out
}

// rankOf is a domain's place in domainRank; a domain it lacks goes last.
func rankOf(rank map[string]int, d string) int {
	if r, ok := rank[d]; ok {
		return r
	}
	return len(rank)
}

// mayHoldRoleNow reports whether email holds a role through a domain group,
// a list or a current person assignment, reading its lists from the store.
// With invitations, an open invitation counts too; sign-in never passes it,
// since an invitation lets its address in only through its own code step,
// which accepts it (and so gives the role) before the session is made.
func (s *Server) mayHoldRoleNow(ctx context.Context, email string, invitations bool) bool {
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
	return (invitations && st.invited[email]) || roles.MaySignIn(email, set, st.assignments, s.roleEnv(st))
}

// mayHoldRoleSnapshot is mayHoldRoleNow from the session's own groups, with
// no store read and without invitations, for the check made on every request
// (policyWithdrawn).
func (s *Server) mayHoldRoleSnapshot(ctx context.Context, id *session.Identity) bool {
	if !s.rolesOn() {
		return false
	}
	st := s.roleData(ctx)
	return roles.MaySignIn(id.Email, sessionLists(id), st.assignments, s.roleEnv(st))
}

// staffFromDomainGroups reports whether the domain groups' domains stand in
// for the allow-list: the app-roles model is on and ALLOWED_EMAIL_DOMAINS is
// empty. While the allow-list is set it alone decides, exactly as before.
func (s *Server) staffFromDomainGroups() bool {
	return s.rolesOn() && !s.policy.HasAllowList()
}

// knownRole is policy.Role with the domain groups in place of an empty
// allow-list: an administrator, an address the allow-list admits, or (with
// no allow-list) an address at a domain of a domain group that holds at
// least one app role is known, and signs in as staff. A domain group that
// holds no role makes nobody staff. Nothing else makes an address known: not
// a list, a person assignment, an invitation, a card or an open-registration
// host, so a member or a guest is never known by this test. While the role
// data has never been read, an address that only a domain group could admit
// is not known; knownRoleChecked tells that case apart.
func (s *Server) knownRole(ctx context.Context, email string) string {
	role, _ := s.knownRoleChecked(ctx, email)
	return role
}

// knownRoleChecked is knownRole, with ok false when the answer depends on
// role data that has never been read, so the caller can refuse for now
// rather than treat a member of staff as a stranger.
func (s *Server) knownRoleChecked(ctx context.Context, email string) (role string, ok bool) {
	role = s.policy.Role(email)
	if role != authz.RoleDeny || !s.staffFromDomainGroups() {
		return role, true
	}
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return authz.RoleDeny, true
	}
	st, loaded := s.roleDataLoaded(ctx)
	if !loaded {
		return authz.RoleDeny, false
	}
	if st.staff[email[at+1:]] {
		return authz.RoleUser, true
	}
	return authz.RoleDeny, true
}

// known reports whether an address is one of the department's: knownRole
// admits it. It replaces the allow-list wherever the gateway asks whether an
// address belongs to staff (feeds, the members endpoint, the lists closed to
// outsiders, and the Groups page).
func (s *Server) known(ctx context.Context, email string) bool {
	return s.knownRole(ctx, email) != authz.RoleDeny
}

// rolesUnavailable reports whether the gateway cannot tell who is staff just
// now: the allow-list is empty, so the domain groups decide, and the role
// data has never been read. Sign-in and session checks then answer with
// renderUnavailable and leave every session as it is.
func (s *Server) rolesUnavailable(ctx context.Context) bool {
	if !s.staffFromDomainGroups() {
		return false
	}
	_, ok := s.roleDataLoaded(ctx)
	return !ok
}

// renderUnavailable answers a request the gateway cannot decide while
// rolesUnavailable, with a 503 and without touching the session cookie.
func (s *Server) renderUnavailable(w http.ResponseWriter, rd string) {
	w.Header().Set("Retry-After", "60")
	s.render(w, http.StatusServiceUnavailable, "message", pageData{Title: msgUnavailableTitle, Message: msgUnavailable, Redirect: rd,
		LinkHref: s.cfg.PublicURL + "/login?rd=" + url.QueryEscape(rd)})
}

// The page shown while rolesUnavailable.
const (
	msgUnavailableTitle = "Sign-in is unavailable for now"
	msgUnavailable      = "The gateway has not been able to read who may sign in. Please try again in a few minutes."
)

// staffDomains are the domains the sign-in page suggests on a direct visit:
// the allow-list's, or, without one, the staff domains (see roleState.staff),
// so a domain group that holds no role is never shown.
func (s *Server) staffDomains(ctx context.Context) []string {
	if len(s.cfg.AllowedDomains) > 0 || !s.staffFromDomainGroups() {
		return s.cfg.AllowedDomains
	}
	return s.roleData(ctx).staffOrder
}

// logWhoSignsIn says at start who can sign in when ALLOWED_EMAIL_DOMAINS is
// empty, so a server that has removed it can see whether staff can still
// sign in. Config.Validate already refuses to start with neither
// ALLOWED_EMAIL_DOMAINS nor ADMIN_EMAILS, so an administrator can always sign
// in. It reads the domain groups once and then forgets them, so the first
// decision reads them afresh.
func (s *Server) logWhoSignsIn(ctx context.Context) {
	if s.policy.HasAllowList() {
		return
	}
	defer s.forgetRoles()
	if !s.rolesOn() {
		log.Printf("authz: ALLOWED_EMAIL_DOMAINS and APP_ROLES_FILE are not set: only the administrators in ADMIN_EMAILS can sign in")
		return
	}
	st, ok := s.roleDataLoaded(ctx)
	switch {
	case !ok:
		log.Printf("warning: authz: ALLOWED_EMAIL_DOMAINS is not set and the domain groups could not be read: sign-in and session checks answer 503, and no session is ended, until they can be read")
	case len(st.staffOrder) == 0:
		log.Printf("warning: authz: ALLOWED_EMAIL_DOMAINS is not set and no domain group with a domain holds an app role: only the administrators in ADMIN_EMAILS and people who hold an app role through a list or a person assignment can sign in")
	default:
		log.Printf("authz: ALLOWED_EMAIL_DOMAINS is not set: addresses at the domains of the domain groups that hold an app role (%s) sign in as staff, as do the administrators in ADMIN_EMAILS; others who hold an app role sign in as members", strings.Join(st.staffOrder, ", "))
	}
}

// loginRole is the sign-in decision: a known address (knownRole) as staff or
// an administrator, and also an address that holds an app role, which signs
// in as a member (and not as a guest, even on an open host). A member is
// decided by its roles on a role guard, and is admitted by an older guard
// only where a guest would be (see session.KindMember).
//
// While the role data has never been read and only a domain group could
// admit the address, the answer is RoleDeny, never a guest; the sign-in
// handlers refuse for now before asking (rolesUnavailable).
func (s *Server) loginRole(ctx context.Context, email string, openHost bool) string {
	role, ok := s.knownRoleChecked(ctx, email)
	if !ok {
		return authz.RoleDeny
	}
	if role != authz.RoleDeny {
		return role
	}
	if s.mayHoldRoleNow(ctx, email, false) {
		return authz.RoleMember
	}
	return s.policy.LoginRole(email, openHost)
}

// currentRole is knownRole made role-aware: an address that is not known but
// holds an app role through a domain group, a list or a current person
// assignment, or has an open invitation, is a member. With the app-roles
// model off it is exactly policy.Role.
func (s *Server) currentRole(ctx context.Context, email string) string {
	role := s.knownRole(ctx, email)
	if role == authz.RoleDeny && s.mayHoldRoleNow(ctx, email, true) {
		return authz.RoleMember
	}
	return role
}

// personSession reports whether a session is a person's own sign-in, by the
// allow-list (kind "") or by an app role (KindMember), rather than a card or
// a guest.
func personSession(id *session.Identity) bool {
	return id.Kind == "" || id.Kind == session.KindMember
}
