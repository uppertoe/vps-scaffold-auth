package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
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
	// first), and within a group the group's own order. An address at one
	// of them is staff (knownRole).
	staff      map[string]bool
	staffOrder []string
	// domainRank orders every domain group's domains the same way, for the
	// hints a role guard gives.
	domainRank map[string]int
	// staffOnly are the lists that hold an app role other than User, which
	// are staff only (staffOnlyLists).
	staffOnly map[string]bool
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

// loadAppRoles reads APP_ROLES_FILE once at start; the gateway never reads
// it again while it runs. A file that cannot be read, such as the directory
// Docker makes when a bind mount's source is missing, or that declares no
// app, is an error, and the gateway refuses to start: with no app, nobody
// would be staff or a guest, and every session but an administrator's would
// end at its next request. (config.Load refuses an empty setting; an empty
// path here is a hand-built configuration and gives an empty manifest.)
func loadAppRoles(path, domain string) (roles.Manifest, error) {
	if path == "" {
		return roles.Manifest{}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return roles.Manifest{}, fmt.Errorf("APP_ROLES_FILE: %w", err)
	}
	defer f.Close()
	m := roles.ParseManifest(f, domain, log.Printf)
	if len(m.Apps) == 0 {
		return m, fmt.Errorf("APP_ROLES_FILE: %s declares no app (is it a directory, or empty?)", path)
	}
	return m, nil
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
	st.staffOnly = staffOnlyByRoles(as)
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
	case r.Header.Get("X-Auth-Policy") != "":
		// Only an older guard sends a policy, and an older guard does not
		// delete a client's X-Auth-App or X-Auth-Role, so the app and role on
		// such a request may be the client's own. No server's auth.caddy
		// defines an older guard any longer; the refusal stays so that one
		// copied back by mistake fails closed.
		return app, role, "the guard sends X-Auth-Policy, which only an older guard sends"
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
		if c, ok := st.cards[id.Card]; ok && c.Status == store.BreakGlassActive && cardIssuedAsNow(id) {
			sub.CardApp, sub.CardRole = c.App, c.Role
		}
	}
	return roles.Held(app, sub, st.assignments, s.roleEnv(st))
}

// cardIssuedAsNow reports whether a break-glass session was issued as a scan
// issues one today, with no groups. A session that carries a group was
// started by an earlier release from a card made for a group, and it holds
// nothing until it ends, even if its card was later moved onto an app.
func cardIssuedAsNow(id *session.Identity) bool {
	return id.Groups == ""
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
	if id.Kind == session.KindGuest || id.Kind == session.KindMember {
		// A guest or a member is an outsider, so a list that has become
		// staff only since the session's groups were worked out is dropped
		// now.
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
// decide by Remote-Roles, and the gateway sends no groups. A guard that copies
// a header the gateway does not send hands the app Caddy's placeholder text,
// "{http.reverse_proxy.header.…}", rather than nothing; an empty header makes
// the copy empty too. Remote-Groups is still sent empty because one inline
// guard copies it (markbot's apps/pstonn/pstonn.caddy, November 2026); it can
// stop once no guard on any server copies it.
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
