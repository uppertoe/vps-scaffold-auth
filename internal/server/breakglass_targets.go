package server

import (
	"sort"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
)

// Some groups are not doors into an app but roles inside it: an app reads
// Remote-Groups and treats "airdb_admin" or "planka-admins" as its own
// administrator. A break-glass card targeting such a group, or a stranger
// made a member of it, would admit a guest as an application administrator.
// The gateway therefore refuses those groups as a card's target and as a
// membership for an address the allow-list does not admit. It learns them
// from three places:
//
//   - a route whose group rule lists a group together with "admin" (the
//     renderer records each rule's group set in ROUTE_ACCESS_FILE): a guard
//     written "X admin" means X is the app's administrator role;
//   - a group an app declares it reads itself, flagged "declared" in
//     ROUTE_GROUPS_FILE from a "# scaffold-groups:" marker: the app decides
//     what the group means, so the gateway does not hand it to strangers;
//   - BREAKGLASS_REFUSED_GROUPS, for deployments without the manifests or
//     for a role the manifests cannot see.
//
// A group filled from a feed is refused for the same reasons: a card or a
// hand-added stranger would sit alongside the people the feed vouches for.
//
// Reserved roles (admin, user, guest) are refused before any of this, with
// their own message.

// Short reasons shown beside a refused group in the admin UI.
const (
	refusedAppRole = "used as an application role"
	refusedFeed    = "filled from a feed"
)

// refusedTargets returns every group a break-glass card may not target and a
// stranger may not be made a member of, mapped to its short reason. The map
// is rebuilt on each call from the manifests, so a routes change is honoured
// on the next request without a restart.
func (s *Server) refusedTargets() map[string]string {
	out := map[string]string{}
	for _, g := range s.cfg.BreakGlassRefusedGroups {
		if g = normalizeGroupName(g); g != "" && !authz.IsReservedGroup(g) {
			out[g] = refusedAppRole
		}
	}
	if m, ok := s.readRouteManifest(); ok {
		for g := range m.Declared {
			out[g] = refusedAppRole
		}
	}
	for _, site := range s.routeAccess() {
		for _, rule := range site.Rules {
			if rule.Kind != "groups" || !containsFold(rule.Values, authz.RoleAdmin) {
				continue
			}
			for _, g := range rule.Values {
				if g = normalizeGroupName(g); g != "" && !authz.IsReservedGroup(g) && authz.ValidGroupName(g) {
					out[g] = refusedAppRole
				}
			}
		}
	}
	for g := range s.feeds.feeds {
		out[normalizeGroupName(g)] = refusedFeed
	}
	return out
}

// targetRefusal reports whether group is refused and why. Reserved roles are
// not its concern; callers check authz.IsReservedGroup first.
func (s *Server) targetRefusal(group string) (string, bool) {
	reason, refused := s.refusedTargets()[normalizeGroupName(group)]
	return reason, refused
}

// targetOptionView is one group offered as a break-glass target on the codes
// page. A refused option is shown but cannot be chosen.
type targetOptionView struct {
	Name   string
	Reason string // empty when the group may be targeted
}

// targetOptions lists the groups an administrator may pick as a card's
// target: every group the routes use and every group that exists, less the
// reserved roles, each marked with its refusal reason if it has one. Empty
// when the gateway knows no groups, in which case the form takes a typed name.
func (s *Server) targetOptions(groups []string) []targetOptionView {
	names := map[string]bool{}
	for _, g := range groups {
		names[normalizeGroupName(g)] = true
	}
	if hosts, ok := s.routeGroups(); ok {
		for g := range hosts {
			names[g] = true
		}
	}
	refused := s.refusedTargets()
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

func containsFold(list []string, want string) bool {
	for _, v := range list {
		if normalizeGroupName(v) == want {
			return true
		}
	}
	return false
}
