package server

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/roles"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// The shared pieces of the app-roles admin pages: what holds each role, drawn
// as tokens, and the widest access a role gives. Icons say what kind of thing
// holds a role; colour says how well the gateway knows the person (grey for
// signed-in staff, amber for strangers or people who have not signed in, red
// for the holder of a break-glass card).

// Token icons, the ids of the SVG symbols in admin_roles_parts.html.
const (
	iconNetwork = "k-net"
	iconGuests  = "k-guest"
	iconDomain  = "k-domain"
	iconList    = "k-list"
	iconPerson  = "k-person"
	iconCard    = "k-card"
	iconLock    = "k-lock"
	iconApp     = "k-app"
)

// accessStep is one step of the widest-access scale, widest first.
type accessStep struct {
	Level int
	Word  string
	Icon  string
	Who   string
}

// accessSteps is the six-step scale. Network's wording names the first
// configured network (see networkLabel).
func (s *Server) accessSteps() []accessStep {
	net := "Anyone on a named network"
	if names := s.networkNames(); len(names) > 0 {
		net = "Anyone on the " + s.networkLabel(names[0])
	}
	return []accessStep{
		{6, "Public", iconLock, "Anyone, without signing in"},
		{5, "Network", iconNetwork, net},
		{4, "Guests", iconGuests, "Anyone with an email address"},
		{3, "Domain", iconDomain, "Everyone at an email domain"},
		{2, "People", iconPerson, "People on a list or added"},
		{1, "Cards", iconCard, "Anyone carrying a break-glass card"},
	}
}

// networkNames are the networks in NETWORK_RANGES, sorted.
func (s *Server) networkNames() []string {
	out := make([]string, 0, len(s.cfg.NetworkRanges))
	for n := range s.cfg.NetworkRanges {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// networkLabel names a network for people, as NETWORK_RANGES writes its
// name: "RCH=…" is "RCH network", and "hospital=…" is "hospital network".
func (s *Server) networkLabel(name string) string {
	if n, ok := s.cfg.NetworkNames[name]; ok {
		name = n
	}
	return name + " network"
}

// holderOrder sorts holders as the pages list them: networks, guests, domain
// groups, then lists.
var holderOrder = map[string]int{store.AssignNetwork: 0, store.AssignGuests: 1, store.AssignDomainGroup: 2, store.AssignList: 3, store.AssignPerson: 4}

// holderLevel is each kind's step on the access scale.
var holderLevel = map[string]int{store.AssignNetwork: 5, store.AssignGuests: 4, store.AssignDomainGroup: 3, store.AssignList: 2, store.AssignPerson: 2}

// holderID is how a form names a holder: "kind:ref".
func holderID(kind, ref string) string { return kind + ":" + ref }

func parseHolderID(v string) (kind, ref string, ok bool) {
	kind, ref, ok = strings.Cut(v, ":")
	if !ok {
		return "", "", false
	}
	if _, known := holderOrder[kind]; !known {
		return "", "", false
	}
	return kind, ref, true
}

// rolesWorld is everything the app-roles pages read, loaded once per request.
type rolesWorld struct {
	m       roles.Manifest
	as      []store.RoleAssignment
	groups  map[string]store.Group
	domains map[string][]string
	members map[string]int
	feeds   map[string]bool
	cards   []store.BreakGlassCode // active cards that name an app role
	invites []store.Invitation     // every invitation, newest sent first
	now     time.Time
}

func (s *Server) loadRolesWorld(ctx context.Context) (*rolesWorld, error) {
	w := &rolesWorld{m: s.appRoles, groups: map[string]store.Group{}, members: map[string]int{}, feeds: map[string]bool{}, now: s.now()}
	var err error
	if w.as, err = s.store.ListRoleAssignments(ctx, ""); err != nil {
		return nil, err
	}
	if w.domains, err = s.store.ListGroupDomains(ctx); err != nil {
		return nil, err
	}
	gs, err := s.store.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	for _, g := range gs {
		w.groups[g.Name] = g
		if g.Kind == store.GroupKindList {
			ms, err := s.store.ListGroupMembers(ctx, g.Name)
			if err != nil {
				return nil, err
			}
			w.members[g.Name] = len(ms)
		}
		if _, fed := s.feedFor(g.Name); fed {
			w.feeds[g.Name] = true
		}
	}
	if w.invites, err = s.store.ListInvitations(ctx); err != nil {
		return nil, err
	}
	codes, err := s.store.ListBreakGlassCodes(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range codes {
		if c.Status == store.BreakGlassActive && c.App != "" {
			w.cards = append(w.cards, c)
		}
	}
	return w, nil
}

// groupLabel is a group's label, or its name when it has none.
func (w *rolesWorld) groupLabel(name string) string {
	if g, ok := w.groups[name]; ok && g.Label != "" {
		return g.Label
	}
	return name
}

// current reports whether an assignment gives its role now: a person's
// assignment ends at its Until, and a network or guests holding a role
// other than User give nothing (see roles.Honoured).
func (w *rolesWorld) current(a store.RoleAssignment) bool {
	if !roles.Honoured(a) {
		return false
	}
	return a.Kind != store.AssignPerson || a.Until.IsZero() || w.now.Before(a.Until)
}

// live returns the assignments of one app role that give it now, so a
// person whose end date has passed is left out.
func (w *rolesWorld) live(app, role string) []store.RoleAssignment {
	var out []store.RoleAssignment
	for _, a := range w.assigned(app, role) {
		if w.current(a) {
			out = append(out, a)
		}
	}
	return out
}

// assigned returns the assignments of one app role, people included, ended
// or not.
func (w *rolesWorld) assigned(app, role string) []store.RoleAssignment {
	var out []store.RoleAssignment
	for _, a := range w.as {
		if a.App == app && a.Role == role {
			out = append(out, a)
		}
	}
	return out
}

// cardsFor returns the labels of the active cards that hold an app role.
func (w *rolesWorld) cardsFor(app, role string) []string {
	var out []string
	for _, c := range w.cards {
		if c.App == app && c.Role == role {
			out = append(out, c.Label)
		}
	}
	return out
}

// tokenView is one token: a thing that holds a role.
type tokenView struct {
	Icon, Tone, Label, Count, Title string
	// Href makes the token a link. Field makes it a toggle: a checkbox named
	// Field with Value, ticked when Checked. Held marks a toggle for a holder
	// the store has now, so the page can count unsaved changes. Pending is
	// "add" for a holder about to be given the role.
	Href    string
	Field   string
	Value   string
	Checked bool
	Held    bool
	Pending string
	On      bool
	// Capped hides a token on the overview until the script fits the row,
	// so that a page without the script shows the first tokens and
	// "+N more" rather than tokens cut off at the row's edge.
	Capped bool
	// Widest marks the holder that sets the row's widest access, so a narrow
	// row keeps it in view.
	Widest bool
	// Level is the holder's step on the access scale, which the app page's
	// script reads to redraw a row's widest access as changes are made.
	Level int
}

// rank is how long a token stays when a row is too narrow for all of
// them: matched tokens longest, then the card token, then the holder that
// sets the widest access, then the others.
func (t tokenView) rank() int {
	switch {
	case t.On:
		return 4
	case t.Tone == "card":
		return 3
	case t.Widest:
		return 2
	}
	return 1
}

// tokenCap is how many tokens an overview row shows before the script has
// fitted it.
const tokenCap = 3

// holderToken draws one non-person holder.
func (s *Server) holderToken(w *rolesWorld, kind, ref string) tokenView {
	t := tokenView{}
	switch kind {
	case store.AssignNetwork:
		t.Icon, t.Tone, t.Label = iconNetwork, "wide", s.networkLabel(ref)
	case store.AssignGuests:
		t.Icon, t.Tone, t.Label = iconGuests, "wide", "Guests"
	case store.AssignDomainGroup:
		t.Icon, t.Label = iconDomain, w.groupLabel(ref)
	case store.AssignList:
		t.Icon, t.Label = iconList, w.groupLabel(ref)
		t.Count = fmt.Sprint(w.members[ref])
	}
	t.Title = t.Label + ": " + s.holderWho(w, kind, ref) + "."
	t.Level = holderLevel[kind]
	return t
}

// holderWho says whom a holder admits, as the app page says it.
func (s *Server) holderWho(w *rolesWorld, kind, ref string) string {
	switch kind {
	case store.AssignNetwork:
		return "Anyone on the " + s.networkLabel(ref) + ", without signing in"
	case store.AssignGuests:
		return "Anyone who confirms an email address"
	case store.AssignDomainGroup:
		return domainsWho(w.domains[ref])
	case store.AssignList:
		return fmt.Sprintf("%d %s, %s", w.members[ref], pluralWord(w.members[ref], "person", "people"), w.listKept(ref))
	}
	return ""
}

// listKept says how a list is kept.
func (w *rolesWorld) listKept(name string) string {
	if w.feeds[name] {
		return "filled from a feed"
	}
	return "kept by hand"
}

func domainsWho(ds []string) string {
	if len(ds) == 0 {
		return "Nobody yet, because the group has no domains"
	}
	at := make([]string, len(ds))
	for i, d := range ds {
		at[i] = "@" + d
	}
	return "Everyone at " + joinOr(at)
}

func joinOr(xs []string) string {
	if len(xs) <= 1 {
		return strings.Join(xs, "")
	}
	return strings.Join(xs[:len(xs)-1], ", ") + " or " + xs[len(xs)-1]
}

func joinAnd(xs []string) string {
	if len(xs) <= 1 {
		return strings.Join(xs, "")
	}
	return strings.Join(xs[:len(xs)-1], ", ") + " and " + xs[len(xs)-1]
}

var smallNumbers = []string{"no", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"}

// numberWord writes n in words up to ten, and in digits above.
func numberWord(n int) string {
	if n >= 0 && n < len(smallNumbers) {
		return smallNumbers[n]
	}
	return fmt.Sprint(n)
}

func pluralWord(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// countWords is "three people", "one card".
func countWords(n int, one, many string) string {
	return numberWord(n) + " " + pluralWord(n, one, many)
}

func capFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// reachView is the widest-access cell.
type reachView struct {
	Closed bool
	Step   accessStep
	Bars   []bool
	Title  string
}

// msgNobodyHolds and msgOnlyOtherRoles are the empty user row's wording. The
// second, approved on 13 November 2026, says that a user role with no holders
// of its own is still reached by the holders of the app's other roles.
const (
	msgNobodyHolds    = "Nobody holds this role."
	msgOnlyOtherRoles = "Only people with %s reach these paths."
)

// level is the step a reach cell shows, 0 when closed.
func (r reachView) level() int {
	n := 0
	for _, b := range r.Bars {
		if b {
			n++
		}
	}
	return n
}

func (s *Server) reach(level int) reachView {
	bars := make([]bool, 6)
	for i := range bars {
		bars[i] = i < level
	}
	if level == 0 {
		return reachView{Closed: true, Bars: bars, Title: "Nobody holds this role."}
	}
	for _, st := range s.accessSteps() {
		if st.Level == level {
			return reachView{Step: st, Bars: bars, Title: fmt.Sprintf("Step %d of 6: %s", level, st.Who)}
		}
	}
	return reachView{Bars: bars}
}

// pathsText is a role's paths as a role row shows them: the patterns, or
// "All paths" for an app with one line, or "Everything else".
func pathsText(a *roles.App, role string) (text string, mono bool) {
	var parts []string
	for _, p := range a.PathsFor(role) {
		switch {
		case p.Rest() && len(a.Paths) == 1:
			parts = append(parts, "All paths")
		case p.Rest():
			parts = append(parts, "Everything else")
		default:
			parts = append(parts, strings.Join(p.Patterns, " "))
		}
	}
	text = strings.Join(parts, " ")
	return text, strings.HasPrefix(text, "/")
}

// pathsPhrase is a role's paths inside a sentence: "/admin/*", "every path"
// or "every other path".
func pathsPhrase(a *roles.App, role string) string {
	var parts []string
	for _, p := range a.PathsFor(role) {
		switch {
		case p.Rest() && len(a.Paths) == 1:
			parts = append(parts, "every path")
		case p.Rest():
			parts = append(parts, "every other path")
		default:
			parts = append(parts, strings.Join(p.Patterns, ", "))
		}
	}
	if len(parts) == 0 {
		if role == roles.UserRole {
			return "every path"
		}
		return "the paths that need it"
	}
	return joinAnd(parts)
}
