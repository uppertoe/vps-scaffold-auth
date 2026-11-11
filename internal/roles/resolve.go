package roles

import (
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// UserRole is the role every app has. Holding any role in an app admits a
// request for its user role, and it is the only role a card can hold.
const UserRole = store.RoleUser

// Subject is who is asking, as /verify sees the request.
type Subject struct {
	// Session is false for a request with no session at all; such a request
	// can hold a role only through a network.
	Session bool
	Email   string
	// Guest and BreakGlass mark those session kinds. Neither is ever matched
	// by a domain rule.
	Guest      bool
	BreakGlass bool
	// CardApp and CardRole are the app role the scanned card names; both are
	// empty for a card that still targets a group.
	CardApp, CardRole string
	// Lists are the list groups the person belongs to.
	Lists map[string]bool
	// Addr is the client address the gateway trusts (see clientIP), used
	// only for network assignments.
	Addr netip.Addr
}

// Env is the gateway state a decision reads.
type Env struct {
	Networks map[string][]netip.Prefix // NETWORK_RANGES
	Domains  map[string][]string       // domain group -> its domains
	Now      time.Time
}

// Held returns the roles subject holds in app, sorted, from that app's
// assignments (assignments for other apps are ignored).
//
// The rules, which keep the old guards' invariants:
//   - a network assignment admits anyone inside the network, signed in or not;
//   - a request with no session holds nothing else;
//   - a break-glass session holds only the user role of the app its card
//     names, and nothing through groups, people, guests or domains;
//   - a domain rule never matches a guest or a break-glass session;
//   - a guests assignment admits any signed-in person who is not break-glass;
//   - a person assignment counts until its end, and a list by membership.
func Held(app string, s Subject, as []store.RoleAssignment, env Env) []string {
	held := map[string]bool{}
	email := strings.ToLower(strings.TrimSpace(s.Email))
	domain := ""
	if i := strings.LastIndexByte(email, '@'); i >= 0 {
		domain = email[i+1:]
	}
	if s.Session && s.BreakGlass && s.CardApp == app && s.CardRole == UserRole {
		held[UserRole] = true
	}
	for _, a := range as {
		if a.App != app || held[a.Role] {
			continue
		}
		switch a.Kind {
		case store.AssignNetwork:
			if inNetwork(s.Addr, env.Networks[a.Ref]) {
				held[a.Role] = true
			}
		case store.AssignGuests:
			if s.Session && !s.BreakGlass {
				held[a.Role] = true
			}
		case store.AssignDomainGroup:
			if s.Session && !s.BreakGlass && !s.Guest && domain != "" && contains(env.Domains[a.Ref], domain) {
				held[a.Role] = true
			}
		case store.AssignList:
			if s.Session && !s.BreakGlass && s.Lists[a.Ref] {
				held[a.Role] = true
			}
		case store.AssignPerson:
			if s.Session && !s.BreakGlass && email != "" && a.Ref == email && current(a, env.Now) {
				held[a.Role] = true
			}
		}
	}
	out := make([]string, 0, len(held))
	for r := range held {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// Admits reports whether the held roles satisfy a request for role: the role
// itself, or, for the user role, any role in the app.
func Admits(held []string, role string) bool {
	for _, h := range held {
		if h == role {
			return true
		}
	}
	return role == UserRole && len(held) > 0
}

// MaySignIn reports whether email holds a role in some app through a domain
// group, a list or a current person assignment. Networks and guests do not
// count: they admit people, but they are not a reason to let an address sign
// in. lists are the list groups the address belongs to.
func MaySignIn(email string, lists map[string]bool, as []store.RoleAssignment, env Env) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	i := strings.LastIndexByte(email, '@')
	if i < 0 {
		return false
	}
	domain := email[i+1:]
	for _, a := range as {
		switch a.Kind {
		case store.AssignDomainGroup:
			if contains(env.Domains[a.Ref], domain) {
				return true
			}
		case store.AssignList:
			if lists[a.Ref] {
				return true
			}
		case store.AssignPerson:
			if a.Ref == email && current(a, env.Now) {
				return true
			}
		}
	}
	return false
}

func current(a store.RoleAssignment, now time.Time) bool {
	return a.Until.IsZero() || now.Before(a.Until)
}

func inNetwork(addr netip.Addr, prefixes []netip.Prefix) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
