// The rows and pickers of an app's roles block on the admin pages.

package server

import (
	"fmt"
	"html/template"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/roles"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// roleRowView is one row: an app role, who holds it, and its widest access.
type roleRowView struct {
	Role, Label string
	Paths       string
	PathsMono   bool
	Tokens      []tokenView
	Nobody      bool
	NobodyText  string
	Reach       reachView
	Mark        string // "hit" or "dim" while an address or holder is checked
	Editable    bool
	// More and MoreTitle are the "+N more" token of a capped row, and the
	// holders it stands for.
	More, MoreTitle string
	PickID, AddText string
	AddTitle        string
	Picker          *pickerView
}

// pickerView offers the holders a role does not have yet.
type pickerView struct {
	ID, Title string
	Role      string
	Sections  []pickerSection
	// InviteHref opens the invitation form with this role chosen. CardHref,
	// for the user role only, opens the new-card form with the app chosen.
	InviteHref string
	CardHref   string
	// Today is the earliest end date a person can be given, and the
	// Msg fields are the wording the picker's script shows.
	Today                                  string
	MsgPending, MsgNotAddress, MsgPastDate string
	MsgBadDate, MsgUntil, InviteText       string
	// NoGroups is the line shown when no domain group or list can be
	// chosen, with its link to the new-group form; otherwise NewGroup is
	// the quiet link to that form under the group sections.
	NoGroups               template.HTML
	NewGroup, NewGroupHref string
}

type pickerSection struct {
	Heading string
	Options []pickerOption
}

type pickerOption struct {
	Token        tokenView
	Who          string
	Field, Value string
	Checked      bool
}

// appBlockView is an app's header row and its role rows.
type appBlockView struct {
	Name, Label, Host string
	Open              string // "Two open by design", or ""
	OpenTitle         string
	Rows              []roleRowView
	Editable          bool
}

// rowFocus decides how a row is marked while something is checked.
type rowFocus struct {
	holderKind, holderRef string // a token clicked on the overview
	address               string // an address checked on the overview
	heldByAddress         map[string]bool
	// heldVia marks the holders through which the address holds each role,
	// as "app:role|kind:ref", so their tokens are marked too.
	heldVia map[string]bool
}

func (f *rowFocus) active() bool { return f != nil && (f.holderKind != "" || f.address != "") }

// pending is the unsaved state of an app page: holders about to be given or
// taken away, by role, as "kind:ref", and people about to be given a role
// (people) or to have it taken away (unpeople).
type pending struct {
	give, take       map[string]map[string]bool
	people, unpeople []store.RoleAssignment
}

// count is the number of unsaved changes.
func (p *pending) count() int {
	if p == nil {
		return 0
	}
	n := len(p.people) + len(p.unpeople)
	for _, m := range []map[string]map[string]bool{p.give, p.take} {
		for _, ids := range m {
			n += len(ids)
		}
	}
	return n
}

// any reports whether there is anything unsaved.
func (p *pending) any() bool {
	return p != nil && len(p.give)+len(p.take)+len(p.people)+len(p.unpeople) > 0
}

// taking reports whether the holder is about to be taken from the role.
func (p *pending) taking(role, id string) bool {
	return p != nil && p.take[role][id]
}

// appBlock builds an app's rows. editable adds the toggles and pickers of the
// app page; p is its unsaved state.
func (s *Server) appBlock(w *rolesWorld, a *roles.App, editable bool, f *rowFocus, p *pending) appBlockView {
	b := appBlockView{Name: a.Name, Label: a.Label, Editable: editable}
	if len(a.Hosts) > 0 {
		b.Host = a.Hosts[0]
	}
	if open := a.OpenPaths(); len(open) > 0 {
		b.Open = capFirst(numberWord(len(open))) + " open by design"
		var ps []string
		for _, o := range open {
			ps = append(ps, strings.Join(o.Patterns, " "))
		}
		b.OpenTitle = strings.Join(ps, "   ")
	}
	for _, role := range a.RoleOrder {
		b.Rows = append(b.Rows, s.roleRow(w, a, role, editable, f, p))
	}
	return b
}

func (s *Server) roleRow(w *rolesWorld, a *roles.App, role string, editable bool, f *rowFocus, p *pending) roleRowView {
	row := roleRowView{Role: role, Label: a.Roles[role], Editable: editable}
	row.Paths, row.PathsMono = pathsText(a, role)
	type held struct {
		kind, ref string
		isNew     bool
	}
	var hs []held
	var people []store.RoleAssignment
	inRow := map[string]bool{}
	for _, as := range w.live(a.Name, role) {
		if as.Kind == store.AssignPerson {
			people = append(people, as)
			continue
		}
		hs = append(hs, held{kind: as.Kind, ref: as.Ref})
		inRow[holderID(as.Kind, as.Ref)] = true
	}
	if p != nil {
		for id := range p.give[role] {
			if k, r, ok := parseHolderID(id); ok && !inRow[id] {
				hs = append(hs, held{kind: k, ref: r, isNew: true})
				inRow[id] = true
			}
		}
	}
	sort.Slice(hs, func(i, j int) bool {
		if holderOrder[hs[i].kind] != holderOrder[hs[j].kind] {
			return holderOrder[hs[i].kind] < holderOrder[hs[j].kind]
		}
		return strings.ToLower(s.holderToken(w, hs[i].kind, hs[i].ref).Label) < strings.ToLower(s.holderToken(w, hs[j].kind, hs[j].ref).Label)
	})
	level := 0
	tokLevel := map[int]int{} // token index -> its holder's step, when it counts
	for _, h := range hs {
		id := holderID(h.kind, h.ref)
		t := s.holderToken(w, h.kind, h.ref)
		removing := p.taking(role, id)
		if editable {
			t.Field, t.Value, t.Held = "r."+role, id, !h.isNew
			t.Checked = !removing
			if h.isNew {
				t.Pending = "add"
				t.Title = "Give the role to " + t.Label
			} else {
				t.Title = "Take the role from " + t.Label
			}
		} else {
			t.Href = "/admin/apps?holder=" + id
		}
		if f != nil && f.holderKind == h.kind && f.holderRef == h.ref {
			t.On = true
		}
		if f != nil && f.address != "" && f.heldVia[a.Name+":"+role+"|"+id] {
			t.On = true
		}
		if !removing {
			level = max(level, holderLevel[h.kind])
			tokLevel[len(row.Tokens)] = holderLevel[h.kind]
		}
		row.Tokens = append(row.Tokens, t)
	}
	if len(people) > 0 {
		t := tokenView{Icon: iconPerson, Label: capFirst(countWords(len(people), "person", "people")), Level: holderLevel[store.AssignPerson]}
		var lines []string
		for _, pa := range people {
			line := pa.Ref
			if !pa.Until.IsZero() {
				line += ", until " + s.longDate(pa.Until)
			}
			lines = append(lines, line)
			if f != nil && f.address == pa.Ref {
				t.On = true
			}
		}
		t.Title = strings.Join(lines, "\n")
		if editable {
			t.Href = "#people"
		}
		tokLevel[len(row.Tokens)] = holderLevel[store.AssignPerson]
		row.Tokens = append(row.Tokens, t)
		level = max(level, holderLevel[store.AssignPerson])
	}
	if editable && p != nil {
		// People about to be given the role, and people about to have it
		// taken away, each as their own token that can be undone.
		for _, pa := range p.people {
			if pa.Role != role {
				continue
			}
			t := tokenView{Icon: iconPerson, Label: pa.Ref, Field: "p." + role, Value: pa.Ref + "|" + s.lastDay(pa.Until),
				Checked: true, Pending: "add", Title: "Give the role to " + pa.Ref, Level: holderLevel[store.AssignPerson]}
			if !pa.Until.IsZero() {
				t.Count = fmt.Sprintf(msgPersonUntil, s.longDate(pa.Until.Add(-time.Second)))
				t.Title += ", " + t.Count
			}
			row.Tokens = append(row.Tokens, t)
			level = max(level, holderLevel[store.AssignPerson])
		}
		for _, pa := range p.unpeople {
			if pa.Role != role {
				continue
			}
			row.Tokens = append(row.Tokens, tokenView{Icon: iconPerson, Label: pa.Ref, Field: "take", Value: role + "|" + pa.Kind + "|" + pa.Ref,
				Checked: true, Pending: "take", Title: "Take the role from " + pa.Ref})
		}
	}
	if cards := w.cardsFor(a.Name, role); len(cards) > 0 {
		row.Tokens = append(row.Tokens, tokenView{Icon: iconCard, Tone: "card", Label: capFirst(countWords(len(cards), "card", "cards")), Title: strings.Join(cards, ", "), Level: 1})
		level = max(level, 1)
	}
	for i, l := range tokLevel {
		if l == level && l > 1 {
			row.Tokens[i].Widest = true
		}
	}
	row.Nobody = len(row.Tokens) == 0
	row.NobodyText = msgNobodyHolds
	if role == roles.UserRole {
		// Any role in an app admits its user paths, so the user row's widest
		// access is the widest of every role in the app, not only its own.
		var others []string
		for r := range a.Roles {
			if r == roles.UserRole {
				continue
			}
			if l := s.roleRow(w, a, r, false, nil, nil).Reach.level(); l > 0 {
				level = max(level, l)
				others = append(others, a.Roles[r])
			}
		}
		if row.Nobody && len(others) > 0 {
			sort.Strings(others)
			row.NobodyText = fmt.Sprintf(msgOnlyOtherRoles, joinAnd(others))
		}
	}
	row.Reach = s.reach(level)
	if !editable {
		capTokens(&row)
	}
	if f.active() {
		hit := false
		if f.address != "" {
			hit = f.heldByAddress[a.Name+":"+role]
		} else {
			for _, t := range row.Tokens {
				hit = hit || t.On
			}
		}
		row.Mark = "dim"
		if hit {
			row.Mark = "hit"
		}
	}
	if editable {
		row.PickID = "pick-" + role
		row.AddText = msgAddToken
		row.AddTitle = msgAddTokenTitle
		if row.Nobody {
			row.AddText = msgGiveToken
		}
		row.Picker = s.picker(w, a, role, inRow, p)
	}
	return row
}

// capTokens hides all but tokenCap of a row's tokens, the least important
// first and from the end, behind "+N more".
func capTokens(row *roleRowView) {
	n := len(row.Tokens) - tokenCap
	if n <= 0 {
		return
	}
	idx := make([]int, len(row.Tokens))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		ra, rb := row.Tokens[idx[a]].rank(), row.Tokens[idx[b]].rank()
		if ra != rb {
			return ra < rb
		}
		return idx[a] > idx[b]
	})
	for _, i := range idx[:n] {
		row.Tokens[i].Capped = true
	}
	var hidden []string
	for _, t := range row.Tokens {
		if t.Capped {
			hidden = append(hidden, t.Label)
		}
	}
	row.More, row.MoreTitle = fmt.Sprintf("+%d more", n), strings.Join(hidden, ", ")
}

// picker lists the networks, guests, domain groups and lists that do not
// hold the role yet, under the prototype's headings.
func (s *Server) picker(w *rolesWorld, a *roles.App, role string, inRow map[string]bool, p *pending) *pickerView {
	pv := &pickerView{ID: "pick-" + role, Role: role, Title: a.Label + ": " + a.Roles[role],
		InviteHref: "/admin/invitations/new?role=" + url.QueryEscape(a.Name+":"+role),
		Today:      s.now().In(s.tzloc()).Format("2006-01-02"),
		MsgPending: msgPersonPending, MsgNotAddress: msgPersonNotAddress, MsgPastDate: msgPersonPastDate,
		MsgBadDate: msgPersonBadDate, MsgUntil: msgPersonUntil, InviteText: msgPickerInvite}
	if role == roles.UserRole && len(a.CardPages) > 0 {
		pv.CardHref = "/admin/break/new?app=" + a.Name
	}
	// A network or guests identify nobody, so they are offered for the user
	// role only.
	settings := pickerSection{Heading: "Settings"}
	if role == roles.UserRole {
		for _, n := range s.networkNames() {
			settings.Options = append(settings.Options, s.pickerOption(w, role, store.AssignNetwork, n, inRow))
		}
		settings.Options = append(settings.Options, s.pickerOption(w, role, store.AssignGuests, "", inRow))
	}
	domains := pickerSection{Heading: "Domain groups"}
	lists := pickerSection{Heading: "Lists"}
	names := make([]string, 0, len(w.groups))
	for n := range w.groups {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		return strings.ToLower(w.groupLabel(names[i])) < strings.ToLower(w.groupLabel(names[j]))
	})
	for _, n := range names {
		if w.groups[n].Kind == store.GroupKindDomain {
			domains.Options = append(domains.Options, s.pickerOption(w, role, store.AssignDomainGroup, n, inRow))
		} else {
			lists.Options = append(lists.Options, s.pickerOption(w, role, store.AssignList, n, inRow))
		}
	}
	pv.NewGroupHref = newGroupHref
	if !offers(domains) && !offers(lists) {
		pv.NoGroups = template.HTML(fmt.Sprintf(msgPickerNoGroups, `<a href="`+newGroupHref+`">`+template.HTMLEscapeString(msgPickerGroupsPage)+`</a>`))
	} else {
		pv.NewGroup = msgPickerNewGroup
	}
	for _, sec := range []pickerSection{settings, domains, lists} {
		var keep []pickerOption
		for _, o := range sec.Options {
			if o.Field != "" {
				keep = append(keep, o)
			}
		}
		if len(keep) > 0 {
			sec.Options = keep
			pv.Sections = append(pv.Sections, sec)
		}
	}
	return pv
}

// offers reports whether a picker section has a holder that can be chosen.
func offers(sec pickerSection) bool {
	for _, o := range sec.Options {
		if o.Field != "" {
			return true
		}
	}
	return false
}

// pickerOption is one holder in the picker; an option already in the row
// (held, or about to be given) is left without a field and dropped.
func (s *Server) pickerOption(w *rolesWorld, role, kind, ref string, inRow map[string]bool) pickerOption {
	id := holderID(kind, ref)
	t := s.holderToken(w, kind, ref)
	o := pickerOption{Token: t, Who: s.holderWho(w, kind, ref)}
	if !inRow[id] {
		o.Field, o.Value = "r."+role, id
	}
	return o
}

// longDate is "12 November 2026" in the display timezone.
func (s *Server) longDate(t time.Time) string { return t.In(s.tzloc()).Format("2 January 2006") }
