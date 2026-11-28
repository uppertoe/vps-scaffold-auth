package server

import (
	"context"
	"log"
	"sort"
	"strings"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/roles"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// Staff-only lists. A list that holds any app role other than User (an app's
// Administrator or Board owner, say) is staff only; any other list takes any
// address. An outsider is anyone the gateway does not count as staff (see
// known), such as a guest, a member who is not staff, or a card session. A
// outsider is never made a staff-only list's member by hand or by bulk add, an include that would bring an
// outsider into it is refused, and an outsider who is on it all the same
// (through an include, or because the list became staff only after they were
// added) is never counted as its member. The members endpoint returns only
// staff in any case.
//
// The rule is read from the role assignments at each decision (through the
// role cache, so a change on an app's page applies at once), so a list
// becomes staff only the moment it is given such a role and takes any address
// again when the last one is taken away. An assignment for an app or role the
// manifest no longer declares still makes its list staff only, so the rule
// fails closed.
//
// BREAKGLASS_REFUSED_GROUPS is deprecated and read for one release: the
// lists it names are staff only as well. A list filled from a feed is refused
// for a hand-added outsider for the same reason: a stranger would sit
// alongside the people the feed vouches for.
//
// Reserved roles (admin, user, guest) are refused before any of this, with
// their own message.

// Short reasons shown beside a refused group in the admin UI.
const (
	refusedAppRole    = "staff only"
	refusedFeed       = "filled from a feed"
	refusedIncluded   = "included in a staff-only list"
	refusedUnreadable = "staff only while the gateway cannot read the app roles"
)

// targetRefusals are the groups a stranger may not be made a member of, each
// with its short reason. (Break-glass cards once targeted groups, and the
// names come from then.) all is
// set while the gateway cannot tell which lists are staff only (the role data
// has never been read, or the includes cannot be read): every group is then
// refused with that reason, failing closed.
type targetRefusals struct {
	byGroup map[string]string
	all     string
}

// reason reports whether group is refused and why.
func (t targetRefusals) reason(group string) (string, bool) {
	if t.all != "" {
		return t.all, true
	}
	r, ok := t.byGroup[normalizeGroupName(group)]
	return r, ok
}

// refusedTargets works out the refused groups: the staff-only lists, every group
// a staff-only list includes, directly or through other groups (a stranger added
// there would be admitted through the include), and the groups filled from a
// feed.
func (s *Server) refusedTargets(ctx context.Context) targetRefusals {
	out := targetRefusals{byGroup: map[string]string{}}
	staffOnly, loaded := s.staffOnlyLists(ctx)
	includes, err := s.store.ListGroupIncludes(ctx)
	if !loaded || err != nil {
		out.all = refusedUnreadable
		return out
	}
	for g := range staffOnly {
		out.byGroup[g] = refusedAppRole
	}
	var walk func(string)
	walk = func(g string) {
		for _, inc := range includes[g] {
			inc = normalizeGroupName(inc)
			if _, done := out.byGroup[inc]; done {
				continue
			}
			out.byGroup[inc] = refusedIncluded
			walk(inc)
		}
	}
	for g := range staffOnly {
		walk(g)
	}
	for g := range s.feeds.feeds {
		out.byGroup[normalizeGroupName(g)] = refusedFeed
	}
	return out
}

// staffOnlyLists returns the staff-only lists: those holding an app
// role other than User, and those BREAKGLASS_REFUSED_GROUPS names. loaded is
// false while the role data has never been read, when the gateway cannot
// tell which lists are staff only; callers then treat every list as staff only.
func (s *Server) staffOnlyLists(ctx context.Context) (staffOnly map[string]bool, loaded bool) {
	st, loaded := s.roleDataLoaded(ctx)
	staffOnly = make(map[string]bool, len(st.staffOnly)+len(s.cfg.BreakGlassRefusedGroups))
	for g := range st.staffOnly {
		staffOnly[g] = true
	}
	for _, g := range s.cfg.BreakGlassRefusedGroups {
		if g = normalizeGroupName(g); g != "" && !authz.IsReservedGroup(g) {
			staffOnly[g] = true
		}
	}
	return staffOnly, loaded
}

// staffOnlyByRoles is the lists that hold an app role other than User, from the
// role assignments, declared by the manifest or not.
func staffOnlyByRoles(as []store.RoleAssignment) map[string]bool {
	out := map[string]bool{}
	for _, a := range as {
		if a.Kind == store.AssignList && a.Role != roles.UserRole {
			out[a.Ref] = true
		}
	}
	return out
}

// logRefusedGroupsDeprecated says at start that BREAKGLASS_REFUSED_GROUPS is
// deprecated, and names each list that only the setting makes staff only, so
// an operator can see which lists would take any address once it is removed.
func (s *Server) logRefusedGroupsDeprecated(ctx context.Context) {
	if len(s.cfg.BreakGlassRefusedGroups) == 0 {
		return
	}
	log.Printf("config: BREAKGLASS_REFUSED_GROUPS is deprecated and will be removed in the next release. A list that holds any app role other than User is staff only without it; the lists it names are staff only as well until then.")
	st, loaded := s.roleDataLoaded(ctx)
	if !loaded {
		return
	}
	var only []string
	for _, g := range s.cfg.BreakGlassRefusedGroups {
		if g = normalizeGroupName(g); g != "" && !authz.IsReservedGroup(g) && !st.staffOnly[g] {
			only = append(only, g)
		}
	}
	if len(only) > 0 {
		sort.Strings(only)
		log.Printf("config: BREAKGLASS_REFUSED_GROUPS alone makes %s staff only, since they hold no app role other than User; once the setting is removed, they will take any address.", strings.Join(only, ", "))
	}
}

// guestGroupsNow returns a guest or member session's groups without any
// list that has become staff only since the session's groups were worked out, so a role
// change reaches the session at its next request.
func (s *Server) guestGroupsNow(ctx context.Context, id *session.Identity) string {
	groups := strings.Split(id.Groups, ",")
	kept := s.withoutStaffOnlyListsForOutsider(ctx, id.Email, authz.RoleGuest, groups)
	if len(kept) == len(groups) {
		return id.Groups
	}
	return strings.Join(kept, ",")
}

// withoutStaffOnlyListsForOutsider removes every staff-only list from an address's
// groups when the session is built on the guest tier (a guest's or a
// member's) or the address is not staff (see knownRole: neither ADMIN_EMAILS nor a
// domain group admits it). Being on a list, holding a
// role or signing in on an open host never makes an address staff, and a
// guest session stays a stranger's even if its domain has since become a
// staff domain, until its person signs in again. A stranger is refused as a
// direct member of a staff-only list, but could still reach one through an
// include, or stay on one after it became staff only; filtering when the groups are
// worked out shuts every such path at once. A list filled from a feed is
// filtered the same way: a feed takes in only staff, but a person stays on it
// until its next sync after their domain has gone, so a staff-only feed list is
// kept only for staff on a tier other than the guest tier.
func (s *Server) withoutStaffOnlyListsForOutsider(ctx context.Context, email, tier string, groups []string) []string {
	if len(groups) == 0 || (tier != authz.RoleGuest && s.known(ctx, email)) {
		return groups
	}
	staffOnly, loaded := s.staffOnlyLists(ctx)
	if !loaded {
		log.Printf("role data unreadable: keeping none of the lists of %s", email)
	}
	out := groups[:0:0]
	for _, g := range groups {
		n := normalizeGroupName(g)
		if authz.IsReservedGroup(n) {
			out = append(out, g) // the base role (a guest's leading "guest") stays
			continue
		}
		// While the role data has never been read, a staff-only list cannot be
		// told from an any-address one, so every list, a feed's included, is
		// dropped for the outsider until it can be read.
		if staffOnly[n] || !loaded {
			continue
		}
		out = append(out, g)
	}
	return out
}

// targetRefusal reports whether group is refused and why. Reserved roles are
// not its concern; callers check authz.IsReservedGroup first.
func (s *Server) targetRefusal(ctx context.Context, group string) (string, bool) {
	return s.refusedTargets(ctx).reason(group)
}
