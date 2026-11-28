// Who may hold an app role at sign-in: login hints, staff and guest rules, and the hosts open to guests.

package server

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/roles"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// roleLoginHint is what a role guard adds to the login URL, in the parameters
// a domain guard uses (see redirectToLogin). When the role is held only by
// domain groups, it carries their domains as rqd, so the sign-in page hints
// them and /request declines an address at none of them. Otherwise it carries rqr=1, which marks a role guard so
// the page does not fall back to the staff domains. When the role's
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
// It is asked only about an address that is not staff, so a staff-only list
// gives no reason to sign in (anyAddressListsOf).
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
	set = s.anyAddressListsOf(ctx, set)
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
	return roles.MaySignIn(id.Email, s.anyAddressListsOf(ctx, sessionLists(id)), st.assignments, s.roleEnv(st))
}

// anyAddressListsOf is lists without the staff-only ones, for an address that
// is not staff: an outsider is never counted as a staff-only list's member, so a
// role held only through one is no reason to sign in. While the role data has
// never been read, no list counts.
func (s *Server) anyAddressListsOf(ctx context.Context, lists map[string]bool) map[string]bool {
	staffOnly, loaded := s.staffOnlyLists(ctx)
	out := make(map[string]bool, len(lists))
	if !loaded {
		return out
	}
	for l := range lists {
		if !staffOnly[normalizeGroupName(l)] {
			out[l] = true
		}
	}
	return out
}

// knownRole is the gateway's one test of who is staff: an administrator in
// ADMIN_EMAILS, or an address at a domain of a domain group that holds at
// least one app role the manifest declares, signs in as staff. A domain
// group that holds no role makes nobody staff. Nothing else makes an address
// known: not a list, a person assignment, an invitation, a card or a host
// open to guests, so a member or a guest is never known by this test. While
// the role data has never been read, an address that only a domain group
// could admit is not known; knownRoleChecked tells that case apart.
func (s *Server) knownRole(ctx context.Context, email string) string {
	role, _ := s.knownRoleChecked(ctx, email)
	return role
}

// knownRoleChecked is knownRole, with ok false when the answer depends on
// role data that has never been read, so the caller can refuse for now
// rather than treat a member of staff as a stranger.
func (s *Server) knownRoleChecked(ctx context.Context, email string) (role string, ok bool) {
	if role = s.policy.Role(email); role != authz.RoleDeny || !s.rolesOn() {
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
// admits it. The gateway asks it wherever an address must belong to staff
// (feeds, the members endpoint, the staff-only lists, and the Groups page).
func (s *Server) known(ctx context.Context, email string) bool {
	return s.knownRole(ctx, email) != authz.RoleDeny
}

// rolesUnavailable reports whether the gateway cannot tell who is staff just
// now: the domain groups decide, and the role data has never been read.
// Sign-in and session checks then answer with renderUnavailable and leave
// every session as it is.
func (s *Server) rolesUnavailable(ctx context.Context) bool {
	if !s.rolesOn() {
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
// the staff domains (see roleState.staff), so a domain group that holds no
// role is never shown.
func (s *Server) staffDomains(ctx context.Context) []string {
	return s.roleData(ctx).staffOrder
}

// logWhoSignsIn says at start who can sign in, so a server can see whether
// staff can still sign in and where guests may. Config.Validate already
// refuses to start without ADMIN_EMAILS, so an administrator can always sign
// in. It reads the role data once and then forgets it, so the first decision
// reads it afresh.
func (s *Server) logWhoSignsIn(ctx context.Context) {
	if !s.rolesOn() {
		return
	}
	defer s.forgetRoles()
	st, ok := s.roleDataLoaded(ctx)
	switch {
	case !ok:
		log.Printf("warning: authz: the domain groups could not be read: sign-in and session checks answer 503, and no session is ended, until they can be read")
		return
	case len(st.staffOrder) == 0:
		log.Printf("authz: no domain group with a domain holds an app role: only the administrators in ADMIN_EMAILS and people who hold an app role through a list or a person assignment can sign in")
	default:
		log.Printf("authz: addresses at the domains of the domain groups that hold an app role (%s) sign in as staff, as do the administrators in ADMIN_EMAILS; others who hold an app role sign in as members", strings.Join(st.staffOrder, ", "))
	}
	if hosts := s.guestHosts(st); len(hosts) > 0 {
		log.Printf("authz: guest sign-in is open on %s, the hosts of the apps whose User role is held by guests: an address that is not staff and holds no app role signs in there as a guest", strings.Join(hosts, ", "))
	}
	if s.guestsStranded(ctx) {
		log.Printf("warning: authz: guests hold a role in an app that APP_ROLES_FILE no longer declares, and in no app it does: guest sessions are kept and answered 503 until the app is declared again")
	}
}

// guestsHold reports whether guests hold app's User role: a guest who has
// just signed in, on no list, would be admitted to the app. Only a declared
// app counts, and only a guests assignment can make it so.
func (s *Server) guestsHold(st roleState, app string) bool {
	if !s.appRoles.Has(app, roles.UserRole) {
		return false
	}
	held := roles.Held(app, roles.Subject{Session: true, Guest: true}, st.assignments, s.roleEnv(st))
	return roles.Admits(held, roles.UserRole)
}

// openToGuests reports whether host is a host of an app whose User role is
// held by guests, where a stranger who confirms an email address signs in as
// a guest. While the role data has never been read, no host is.
func (s *Server) openToGuests(ctx context.Context, host string) bool {
	if host == "" || !s.rolesOn() {
		return false
	}
	st, ok := s.roleDataLoaded(ctx)
	if !ok {
		return false
	}
	for name, a := range s.appRoles.Apps {
		if a.ServesHost(host) && s.guestsHold(st, name) {
			return true
		}
	}
	return false
}

// guestsAnywhere reports whether some app's User role is held by guests, so
// a guest session has somewhere to go. While it is false, every guest
// session ends at its next request.
func (s *Server) guestsAnywhere(ctx context.Context) bool {
	if !s.rolesOn() {
		return false
	}
	st, ok := s.roleDataLoaded(ctx)
	if !ok {
		return false
	}
	for name := range s.appRoles.Apps {
		if s.guestsHold(st, name) {
			return true
		}
	}
	return false
}

// recordDeclaredApps records the apps this start's manifest declares and
// returns those the previous start declared that this one does not.
func (s *Server) recordDeclaredApps(ctx context.Context) (map[string]bool, error) {
	now := make([]string, 0, len(s.appRoles.Apps))
	for name := range s.appRoles.Apps {
		now = append(now, name)
	}
	sort.Strings(now)
	previous, err := s.store.ReplaceDeclaredApps(ctx, now)
	if err != nil {
		return nil, err
	}
	lost := map[string]bool{}
	for _, a := range previous {
		if _, ok := s.appRoles.Apps[a]; !ok {
			lost[a] = true
		}
	}
	return lost, nil
}

// guestsStranded reports whether this start's manifest has lost the app
// guests hold a role in: a guests assignment names an app the previous
// start declared and this one does not, and no declared app's role is held
// by guests. Every guest session, and every session carried over as one,
// would then end. That is taken for a fault in the configuration (a snippet
// renamed or dropped by mistake), so renewSessionWith keeps those sessions
// and answers 503 until the app is declared again; each still ends at
// SESSION_MAX_AGE. The admin pages show only declared apps, so the
// assignment cannot be removed there meanwhile. A guests assignment for an
// app already gone at the previous start counts for nothing, so taking
// guests off a declared app on its admin page is a decision, and ends the
// sessions as before. The fault lasts until the next start, which records
// the manifest it starts with.
func (s *Server) guestsStranded(ctx context.Context) bool {
	if len(s.lostApps) == 0 {
		return false
	}
	st, ok := s.roleDataLoaded(ctx)
	if !ok || s.guestsAnywhere(ctx) {
		return false
	}
	for _, a := range st.assignments {
		if a.Kind == store.AssignGuests && s.lostApps[a.App] {
			return true
		}
	}
	return false
}

// guestHosts are the hosts open to guests, sorted, for the start-up log.
func (s *Server) guestHosts(st roleState) []string {
	var out []string
	for name, a := range s.appRoles.Apps {
		if s.guestsHold(st, name) {
			out = append(out, a.Hosts...)
		}
	}
	sort.Strings(out)
	return out
}

// loginRole is the sign-in decision: a known address (knownRole) as staff or
// an administrator, and also an address that holds an app role, which signs
// in as a member (and not as a guest, even on an open host). A member is
// decided by its roles, and is an outsider: staff-only lists are dropped from its
// groups (see withoutStaffOnlyListsForOutsider). Any other plausible address
// signs in as a guest when openHost (the destination is open to guests; see
// isOpenHost), and is refused otherwise. A passkey sign-in is decided here
// exactly as an emailed code is.
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
	if openHost && authz.GuestEligible(email) {
		return authz.RoleGuest
	}
	return authz.RoleDeny
}

// currentRole is knownRole made role-aware: an address that is not known but
// holds an app role through a domain group, a list or a current person
// assignment, or has an open invitation, is a member.
func (s *Server) currentRole(ctx context.Context, email string) string {
	role := s.knownRole(ctx, email)
	if role == authz.RoleDeny && s.mayHoldRoleNow(ctx, email, true) {
		return authz.RoleMember
	}
	return role
}

// personSession reports whether a session is a person's own sign-in, as staff
// (kind "") or by an app role (KindMember), rather than a card or a guest.
func personSession(id *session.Identity) bool {
	return id.Kind == "" || id.Kind == session.KindMember
}
