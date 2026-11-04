package server

import (
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

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
	for g := range s.appRoleGroups() {
		out[g] = refusedAppRole
	}
	for g := range s.feeds.feeds {
		out[normalizeGroupName(g)] = refusedFeed
	}
	return out
}

// appRoleGroups returns the groups an application reads as one of its own
// roles, from the three sources described above.
func (s *Server) appRoleGroups() map[string]bool {
	out := map[string]bool{}
	for _, g := range s.cfg.BreakGlassRefusedGroups {
		if g = normalizeGroupName(g); g != "" && !authz.IsReservedGroup(g) {
			out[g] = true
		}
	}
	if m, ok := s.readRouteManifest(); ok {
		for g := range m.Declared {
			out[g] = true
		}
	}
	for _, site := range s.routeAccess() {
		for _, rule := range site.Rules {
			if rule.Kind != "groups" || !containsFold(rule.Values, authz.RoleAdmin) {
				continue
			}
			for _, g := range rule.Values {
				if g = normalizeGroupName(g); g != "" && !authz.IsReservedGroup(g) && authz.ValidGroupName(g) {
					out[g] = true
				}
			}
		}
	}
	return out
}

// routeFilesReadable reports whether every configured route file can be
// opened, so that appRoleGroups saw every application role.
func (s *Server) routeFilesReadable() bool {
	for _, p := range []string{s.cfg.RouteGroupsFile, s.cfg.RouteAccessFile} {
		if p == "" {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			return false
		}
		f.Close()
	}
	return true
}

// guestGroupsNow returns a guest session's groups without any group that has
// become an application role since the session's groups were worked out, so
// a routes change reaches a guest at their next request.
func (s *Server) guestGroupsNow(id *session.Identity) string {
	groups := strings.Split(id.Groups, ",")
	kept := s.withoutAppRolesForOutsider(id.Email, groups)
	if len(kept) == len(groups) {
		return id.Groups
	}
	return strings.Join(kept, ",")
}

// withoutAppRolesForOutsider removes from an address's groups every
// application role, when the allow-list does not admit the address. A
// stranger is refused as a direct member of such a group, but could still
// reach one through an include, or keep one after the group became a role;
// filtering when the groups are worked out closes every such path at once.
// A group filled from a feed is kept: the feed lists the address directly,
// and nothing can be included into a feed group.
func (s *Server) withoutAppRolesForOutsider(email string, groups []string) []string {
	if len(groups) == 0 || s.policy.Allowed(email) {
		return groups
	}
	roles := s.appRoleGroups()
	complete := s.routeFilesReadable()
	if !complete {
		log.Printf("route files unreadable: keeping only feed groups for %s", email)
	}
	out := groups[:0:0]
	for _, g := range groups {
		n := normalizeGroupName(g)
		// A role this gateway cannot see while the route files are
		// unreadable must not slip through, so then every hand-managed group
		// is dropped for the outsider until the files can be read again.
		if authz.IsReservedGroup(n) {
			out = append(out, g) // the base role (a guest's leading "guest") stays
			continue
		}
		if roles[n] || !complete {
			if _, feed := s.feedFor(n); !feed {
				continue
			}
		}
		out = append(out, g)
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
