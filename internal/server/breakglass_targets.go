package server

import (
	"context"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/roles"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// Closed lists. A list that holds any app role other than User (an app's
// Administrator or Board owner, say) is closed to outsiders: anyone the
// gateway does not count as staff (see known), such as a guest, a member who
// is not staff, or a card session. A closed list cannot be a break-glass
// card's target, an outsider is never made its member by hand or by bulk
// add, an include that would bring an outsider into it is refused, and an
// outsider who is on it all the same (through an include, or because the
// list closed after they were added) is never counted as its member in a
// session. The members endpoint returns only staff in any case.
//
// The rule is read from the role assignments at each decision (through the
// role cache, so a change on an app's page applies at once), so a list closes
// the moment it is given such a role and opens again when the last one is
// taken away. An assignment for an app or role the manifest no longer
// declares still closes its list, so the rule fails closed.
//
// BREAKGLASS_REFUSED_GROUPS is deprecated and read for one release: the
// lists it names are closed as well. A list filled from a feed is refused as
// a card's target and for a hand-added outsider for the same reason: a card
// or a stranger would sit alongside the people the feed vouches for.
//
// Reserved roles (admin, user, guest) are refused before any of this, with
// their own message.

// Short reasons shown beside a refused group in the admin UI.
const (
	refusedAppRole = "used as an application role"
	refusedFeed    = "filled from a feed"
)

// refusedTargets returns every group a break-glass card may not target and a
// stranger may not be made a member of, mapped to its short reason.
func (s *Server) refusedTargets(ctx context.Context) map[string]string {
	out := map[string]string{}
	closed, _ := s.closedLists(ctx)
	for g := range closed {
		out[g] = refusedAppRole
	}
	for g := range s.feeds.feeds {
		out[normalizeGroupName(g)] = refusedFeed
	}
	return out
}

// closedLists returns the lists closed to outsiders: those holding an app
// role other than User, and those BREAKGLASS_REFUSED_GROUPS names. loaded is
// false while the role data has never been read, when the gateway cannot
// tell which lists are closed; callers then treat every list as closed.
func (s *Server) closedLists(ctx context.Context) (closed map[string]bool, loaded bool) {
	st, loaded := s.roleDataLoaded(ctx)
	closed = make(map[string]bool, len(st.closed)+len(s.cfg.BreakGlassRefusedGroups))
	for g := range st.closed {
		closed[g] = true
	}
	for _, g := range s.cfg.BreakGlassRefusedGroups {
		if g = normalizeGroupName(g); g != "" && !authz.IsReservedGroup(g) {
			closed[g] = true
		}
	}
	return closed, loaded
}

// closedByRoles is the lists that hold an app role other than User, from the
// role assignments, declared by the manifest or not.
func closedByRoles(as []store.RoleAssignment) map[string]bool {
	out := map[string]bool{}
	for _, a := range as {
		if a.Kind == store.AssignList && a.Role != roles.UserRole {
			out[a.Ref] = true
		}
	}
	return out
}

// logRefusedGroupsDeprecated says at start that BREAKGLASS_REFUSED_GROUPS is
// deprecated, and names each list it closes that the role rule does not, so
// an operator can see what removing the setting would open.
func (s *Server) logRefusedGroupsDeprecated(ctx context.Context) {
	if len(s.cfg.BreakGlassRefusedGroups) == 0 {
		return
	}
	log.Printf("config: BREAKGLASS_REFUSED_GROUPS is deprecated and will be removed in the next release. A list that holds any app role other than User is now closed to outsiders without it; the lists it names are closed as well until then.")
	st, loaded := s.roleDataLoaded(ctx)
	if !loaded {
		return
	}
	var only []string
	for _, g := range s.cfg.BreakGlassRefusedGroups {
		if g = normalizeGroupName(g); g != "" && !authz.IsReservedGroup(g) && !st.closed[g] {
			only = append(only, g)
		}
	}
	if len(only) > 0 {
		sort.Strings(only)
		log.Printf("config: BREAKGLASS_REFUSED_GROUPS alone closes %s, which hold no app role other than User; removing the setting would open them to outsiders.", strings.Join(only, ", "))
	}
}

// guestGroupsNow returns a guest or member session's groups without any
// list that has closed since the session's groups were worked out, so a role
// change reaches the session at its next request.
func (s *Server) guestGroupsNow(ctx context.Context, id *session.Identity) string {
	groups := strings.Split(id.Groups, ",")
	kept := s.withoutClosedListsForOutsider(ctx, id.Email, authz.RoleGuest, groups)
	if len(kept) == len(groups) {
		return id.Groups
	}
	return strings.Join(kept, ",")
}

// withoutClosedListsForOutsider removes every closed list from an address's
// groups when the session is built on the guest tier (a guest's or a
// member's) or the address is not staff (see knownRole: the allow-list, or
// without one a domain group, does not admit it). Being on a list, holding a
// role or signing in on an open host never makes an address staff, and a
// guest session stays a stranger's even if its domain has since become a
// staff domain, until its person signs in again. A stranger is refused as a
// direct member of a closed list, but could still reach one through an
// include, or stay on one after it closed; filtering when the groups are
// worked out closes every such path at once. A list filled from a feed is
// filtered the same way: a feed takes in only staff, but a person stays on it
// until its next sync after their domain has gone, so a closed feed list is
// kept only for staff on a tier other than the guest tier.
func (s *Server) withoutClosedListsForOutsider(ctx context.Context, email, tier string, groups []string) []string {
	if len(groups) == 0 || (tier != authz.RoleGuest && s.known(ctx, email)) {
		return groups
	}
	closed, loaded := s.closedLists(ctx)
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
		// While the role data has never been read, a closed list cannot be
		// told from an open one, so every list, a feed's included, is
		// dropped for the outsider until it can be read.
		if closed[n] || !loaded {
			continue
		}
		out = append(out, g)
	}
	return out
}

// targetRefusal reports whether group is refused and why. Reserved roles are
// not its concern; callers check authz.IsReservedGroup first.
func (s *Server) targetRefusal(ctx context.Context, group string) (string, bool) {
	reason, refused := s.refusedTargets(ctx)[normalizeGroupName(group)]
	return reason, refused
}

// targetOptionView is one group offered as a break-glass target on the codes
// page. A refused option is shown but cannot be chosen.
type targetOptionView struct {
	Name   string
	Reason string // empty when the group may be targeted
}

// targetOptions lists the groups an administrator may pick as a card's
// target: every group that exists, less the reserved roles, each marked with
// its refusal reason if it has one. Empty when the gateway knows no groups,
// in which case the form takes a typed name.
func (s *Server) targetOptions(ctx context.Context, groups []string) []targetOptionView {
	names := map[string]bool{}
	for _, g := range groups {
		names[normalizeGroupName(g)] = true
	}
	refused := s.refusedTargets(ctx)
	out := make([]targetOptionView, 0, len(names))
	for g := range names {
		if g == "" || authz.IsReservedGroup(g) {
			continue
		}
		out = append(out, targetOptionView{Name: g, Reason: refused[g]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// hourlyOnce says yes to a key at most once an hour.
type hourlyOnce struct {
	mu   sync.Mutex
	last map[int64]time.Time
}

func (h *hourlyOnce) due(key int64, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.last == nil {
		h.last = map[int64]time.Time{}
	}
	if t, ok := h.last[key]; ok && now.Sub(t) < time.Hour {
		return false
	}
	h.last[key] = now
	return true
}
