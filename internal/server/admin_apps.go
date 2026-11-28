package server

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/roles"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// The Apps pages: every app role and who holds it (GET /admin/apps), and one
// app's page, where its roles are given and taken away
// (GET /admin/apps/{app}). A change on an app's page is first shown for
// review ("Review the changes"), with the warnings the server finds, and is
// then saved in one transaction with a record of each change, after which the
// other administrators are emailed once.

// The strings the review and the email use. Each is kept here, once.
const (
	msgLastHolder   = "Nobody will hold %s once this is saved, so %s will be closed to everyone."
	msgNetworkOpens = "Anyone on the %s will reach %s without signing in."
	msgGuestsOpen   = "Anyone who confirms an email address will reach %s."
	// msgGuestsSignIn follows msgGuestsOpen: giving guests a role opens guest
	// sign-in on the app's hosts (openToGuests). %s is the hosts.
	msgGuestsSignIn  = "Once this is saved, anyone who confirms an email address at %s will be signed in as a guest."
	msgOrphanRole    = "This role is no longer in the snippet. Its assignments are kept until you remove them."
	msgSaveNote      = "Saving these changes emails the other administrators, and each change is recorded in the admin log."
	msgChangeSubject = "Access to %s has changed."
	msgChangeBody    = "%s made these changes on %s:\n\n%s\nEach change is recorded in the admin log.\n"
	msgCheckInvited  = "%s holds no role yet. An invitation to %s has not been accepted."
)

// appsView is the Apps overview.
type appsView struct {
	Attention []attentionLine
	Filter    string
	Address   string
	Holder    string
	Focus     string // the sentence about the checked address or token
	Apps      []appBlockView
	Key       keyView
}

type attentionLine struct {
	Bad        bool
	Before     string
	Link, Name string
	After      string
}

// keyView is the key under the overview.
type keyView struct {
	Amber, Grey []tokenView
	Card        tokenView
	Steps       []keyStep
}

type keyStep struct {
	Step accessStep
	Bars []bool
}

func (s *Server) handleAdminApps(w http.ResponseWriter, r *http.Request) {
	if !s.rolesOn() {
		http.Redirect(w, r, "/admin/", http.StatusFound)
		return
	}
	world, err := s.loadRolesWorld(r.Context())
	if err != nil {
		s.adminError(w, r)
		return
	}
	q := r.URL.Query()
	v := &appsView{Filter: strings.TrimSpace(q.Get("q")), Holder: q.Get("holder")}
	focus := &rowFocus{}
	if addr := normalizeEmail(q.Get("address")); addr != "" && plainAddress(addr) {
		v.Address = addr
		focus.address = addr
		focus.heldByAddress, focus.heldVia, v.Focus = s.checkAddress(r.Context(), world, addr)
	} else if raw := strings.TrimSpace(q.Get("address")); raw != "" {
		// An address that is not a full one is said to be so, rather than
		// the check being left without an answer.
		if rs := []rune(raw); len(rs) > 254 {
			raw = string(rs[:254])
		}
		v.Address = raw
		v.Focus = fmt.Sprintf(msgCheckNotAddress, raw)
	} else if kind, ref, ok := parseHolderID(v.Holder); ok && kind != store.AssignPerson {
		focus.holderKind, focus.holderRef = kind, ref
		v.Focus = s.holderFocus(world, kind, ref)
	}
	filter := strings.ToLower(v.Filter)
	v.Attention = closedAppLines(world)
	for _, a := range world.m.Sorted() {
		block := s.appBlock(world, a, false, focus, nil)
		if filter != "" && !appMatches(world, a, block, filter) {
			continue
		}
		v.Apps = append(v.Apps, block)
	}
	v.Attention = append(v.Attention, s.invitationLines(world)...)
	v.Key = s.key(world)
	s.renderAdmin(w, r, http.StatusOK, "admin_apps", adminData{Title: "Apps", Apps: v, Script: rolesScript})
}

// closedAppLines are the attention lines about apps that nothing holds a
// role in, which the Apps page and the Overview both show.
func closedAppLines(w *rolesWorld) []attentionLine {
	var out []attentionLine
	for _, a := range w.m.Sorted() {
		if anyHolder(w, a) {
			continue
		}
		out = append(out, attentionLine{Bad: true, Before: "Nobody holds the User role in ", Link: "/admin/apps/" + a.Name, Name: a.Label, After: ", so nobody can reach it."})
	}
	return out
}

// anyHolder reports whether anything holds a role in the app.
func anyHolder(w *rolesWorld, a *roles.App) bool {
	for _, role := range a.RoleOrder {
		if len(w.live(a.Name, role)) > 0 || len(w.cardsFor(a.Name, role)) > 0 {
			return true
		}
	}
	return false
}

// appMatches is the filter: the app's name or host, a role's label, or the
// label of a token in one of its rows.
func appMatches(w *rolesWorld, a *roles.App, b appBlockView, f string) bool {
	if strings.Contains(strings.ToLower(a.Label), f) || strings.Contains(a.Name, f) {
		return true
	}
	for _, h := range a.Hosts {
		if strings.Contains(h, f) {
			return true
		}
	}
	for _, row := range b.Rows {
		if strings.Contains(strings.ToLower(row.Label), f) {
			return true
		}
		for _, t := range row.Tokens {
			if strings.Contains(strings.ToLower(t.Label), f) {
				return true
			}
		}
	}
	return false
}

// checkAddress works out which roles an address holds, and says so.
// Networks are left out, because an address has no network, and so are
// guests, which the sentence names separately.
func (s *Server) checkAddress(ctx context.Context, w *rolesWorld, addr string) (held, via map[string]bool, focus string) {
	lists := map[string]bool{}
	if gs, err := s.store.GroupsForEmail(ctx, addr); err == nil {
		for _, g := range gs {
			lists[g] = true
		}
	}
	sub := roles.Subject{Session: true, Email: addr, Lists: lists}
	sub.Guest = s.currentRole(ctx, addr) == authz.RoleDeny
	env := roles.Env{Domains: w.domains, Now: w.now}
	held, via = map[string]bool{}, map[string]bool{}
	apps := map[string]bool{}
	var through []string
	seen := map[string]bool{}
	direct := false
	var guestApps []string
	for _, a := range w.m.Sorted() {
		guests := false
		for _, role := range a.RoleOrder {
			for _, as := range w.assigned(a.Name, role) {
				if !roles.Honoured(as) {
					continue
				}
				if as.Kind == store.AssignGuests {
					guests = true
					continue
				}
				if as.Kind == store.AssignNetwork || len(roles.Held(a.Name, sub, []store.RoleAssignment{as}, env)) == 0 {
					continue
				}
				held[a.Name+":"+role] = true
				apps[a.Name] = true
				if as.Kind == store.AssignPerson {
					direct = true
				} else {
					via[a.Name+":"+role+"|"+holderID(as.Kind, as.Ref)] = true
					if l := w.groupLabel(as.Ref); !seen[l] {
						seen[l] = true
						through = append(through, l)
					}
				}
			}
		}
		if guests {
			guestApps = append(guestApps, a.Label)
		}
	}
	if direct {
		through = append(through, "a direct assignment")
	}
	var waiting []string
	for _, v := range w.openInvites() {
		if v.Email == addr && w.m.Has(v.App, v.Role) {
			a := w.m.Apps[v.App]
			waiting = append(waiting, a.Label+": "+roleLabel(a, v.Role))
		}
	}
	switch {
	case len(held) == 0 && len(waiting) > 0:
		return held, via, fmt.Sprintf(msgCheckInvited, addr, joinAnd(waiting))
	case len(held) > 0:
		return held, via, fmt.Sprintf("%s holds %s in %s, through %s.", addr, countWords(len(held), "role", "roles"), countWords(len(apps), "app", "apps"), joinAnd(through))
	case len(guestApps) > 0:
		return held, via, fmt.Sprintf("%s holds no role. The address can sign in only as a guest, at %s.", addr, joinAnd(guestApps))
	}
	return held, via, addr + " holds no role."
}

// holderFocus is the sentence about a token clicked on the overview.
func (s *Server) holderFocus(w *rolesWorld, kind, ref string) string {
	n, apps := 0, map[string]bool{}
	for _, a := range w.as {
		if a.Kind == kind && a.Ref == ref && w.m.Has(a.App, a.Role) && roles.Honoured(a) {
			n++
			apps[a.App] = true
		}
	}
	t := s.holderToken(w, kind, ref)
	who := s.holderWho(w, kind, ref)
	if who != "" {
		who = strings.ToLower(who[:1]) + who[1:]
	}
	return fmt.Sprintf("%s (%s) holds %s in %s.", t.Label, who, countWords(n, "role", "roles"), countWords(len(apps), "app", "apps"))
}

// key draws the key's example tokens from the gateway's own holders where it
// has them.
func (s *Server) key(w *rolesWorld) keyView {
	k := keyView{}
	if names := s.networkNames(); len(names) > 0 {
		k.Amber = append(k.Amber, s.holderToken(w, store.AssignNetwork, names[0]))
	}
	k.Amber = append(k.Amber, s.holderToken(w, store.AssignGuests, ""))
	var dom, list string
	names := make([]string, 0, len(w.groups))
	for n := range w.groups {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if w.groups[n].Kind == store.GroupKindDomain && dom == "" {
			dom = n
		}
		if w.groups[n].Kind == store.GroupKindList && list == "" {
			list = n
		}
	}
	if dom != "" {
		k.Grey = append(k.Grey, s.holderToken(w, store.AssignDomainGroup, dom))
	}
	if list != "" {
		k.Grey = append(k.Grey, s.holderToken(w, store.AssignList, list))
	}
	if len(k.Grey) < 2 {
		k.Grey = append(k.Grey, tokenView{Icon: iconPerson, Label: "One person"})
	}
	k.Card = tokenView{Icon: iconCard, Tone: "card", Label: "One card"}
	for _, st := range s.accessSteps() {
		r := s.reach(st.Level)
		k.Steps = append(k.Steps, keyStep{Step: st, Bars: r.Bars})
	}
	return k
}

// --- One app ---

// appView is one app's page.
type appView struct {
	Name, Label, Host string
	RolesText         string
	Source            string
	OpenText          string
	Block             appBlockView
	Blocks            []appBlockView // Block alone, for the shared role list
	Roles             []roleOption
	People            []personRow
	Groups            []groupHereRow
	Paths             []pathRow
	Orphans           []orphanRow
	OrphanNote        string
	// Ignored are assignments of a network or guests to a role other than
	// User, which the gateway does not honour; IgnoredHead and IgnoredNote
	// head their table.
	Ignored                  []orphanRow
	IgnoredHead, IgnoredNote string
	// Reaches are the widest-access cell for each step, 0 to 6, which the
	// page's script copies into a row as its changes are made.
	Reaches []levelReach
	// Pending is set while the page shows unsaved changes.
	Pending bool
	// PendingText counts the unsaved changes in the changes bar, as the
	// page's script does, so the page says it without the script too.
	PendingText string
	Review      *reviewView
	// Confirm is the invitation whose withdrawal is being confirmed
	// (?withdraw=id), with the confirmation's wording.
	Confirm                                 int64
	ConfirmText, ConfirmButton, ConfirmKeep string
	// PickerDone closes a picker. ChangesNone is the changes bar while
	// nothing is unsaved.
	PickerDone, ChangesNone string
}

type roleOption struct{ Role, Label string }

type levelReach struct {
	Level int
	Reach reachView
}

type personRow struct {
	Email, Role, RoleLabel, How, HowTitle, Until string
	Ended                                        bool
	// NoEnd marks a role held with no end date, which the Until cell shows
	// in muted text.
	NoEnd bool
	// InviteID is set on the row of an invitation not yet accepted, which
	// gives nobody the role.
	InviteID int64
}

type groupHereRow struct {
	Token tokenView
	Who   string
	Here  string
	Other string
}

type pathRow struct {
	Patterns string
	Mono     bool
	Open     bool
	Needs    string
	Reason   string
}

type orphanRow struct {
	Role   string
	Token  tokenView
	Person string
	Value  string // the take value
}

func (s *Server) handleAdminApp(w http.ResponseWriter, r *http.Request) {
	a, ok := s.appFromPath(w, r)
	if !ok {
		return
	}
	s.renderApp(w, r, http.StatusOK, a, nil, nil, "")
}

// appFromPath returns the manifest app the path names, or redirects to the
// overview.
func (s *Server) appFromPath(w http.ResponseWriter, r *http.Request) (*roles.App, bool) {
	if !s.rolesOn() {
		http.Redirect(w, r, "/admin/", http.StatusFound)
		return nil, false
	}
	a, ok := s.appRoles.Apps[r.PathValue("app")]
	if !ok {
		http.Redirect(w, r, "/admin/apps", http.StatusFound)
		return nil, false
	}
	return a, true
}

func (s *Server) renderApp(w http.ResponseWriter, r *http.Request, status int, a *roles.App, p *pending, review *reviewView, warning string) {
	world, err := s.loadRolesWorld(r.Context())
	if err != nil {
		s.adminError(w, r)
		return
	}
	v := s.appPage(world, a, p)
	v.Review = review
	v.PickerDone = msgPickerDone
	v.ChangesNone = msgChangesNone
	if r.Method == http.MethodGet {
		if id, err := strconv.ParseInt(r.URL.Query().Get("withdraw"), 10, 64); err == nil {
			for _, p := range v.People {
				if p.InviteID == id {
					v.Confirm = id
					v.ConfirmText, v.ConfirmButton, v.ConfirmKeep = fmt.Sprintf(msgWithdrawConfirm, p.Email), msgWithdrawButton, msgWithdrawKeep
				}
			}
		}
	}
	s.renderAdmin(w, r, status, "admin_app", adminData{Title: a.Label, App: v, Warning: warning, Script: rolesScript})
}

func (s *Server) appPage(w *rolesWorld, a *roles.App, p *pending) *appView {
	v := &appView{Name: a.Name, Label: a.Label, Source: a.Source, OrphanNote: msgOrphanRole, Pending: p.any(),
		IgnoredHead: msgIgnoredHeading, IgnoredNote: msgIgnoredNote}
	if len(a.Hosts) > 0 {
		v.Host = a.Hosts[0]
	}
	var labels []string
	for _, role := range a.RoleOrder {
		labels = append(labels, a.Roles[role])
		v.Roles = append(v.Roles, roleOption{Role: role, Label: a.Roles[role]})
	}
	v.RolesText = joinAnd(labels)
	v.OpenText = "None"
	if n := len(a.OpenPaths()); n > 0 {
		v.OpenText = capFirst(countWords(n, "path", "paths")) + ", listed below"
	}
	if n := p.count(); n > 0 {
		v.PendingText = capFirst(numberWord(n)) + pluralWord(n, " change has", " changes have") + " not been saved."
	}
	v.Block = s.appBlock(w, a, true, nil, p)
	v.Blocks = []appBlockView{v.Block}

	used := map[string]map[string]bool{} // holder id -> roles here
	var order []string
	for _, as := range w.as {
		if as.App != a.Name {
			continue
		}
		if _, declared := a.Roles[as.Role]; !declared {
			o := orphanRow{Role: as.Role, Value: as.Role + "|" + as.Kind + "|" + as.Ref}
			if as.Kind == store.AssignPerson {
				o.Person = as.Ref
			} else {
				o.Token = s.holderToken(w, as.Kind, as.Ref)
			}
			v.Orphans = append(v.Orphans, o)
			continue
		}
		if as.Kind == store.AssignPerson {
			v.People = append(v.People, s.personRow(a, as))
			continue
		}
		if !roles.Honoured(as) {
			v.Ignored = append(v.Ignored, orphanRow{Role: roleLabel(a, as.Role), Token: s.holderToken(w, as.Kind, as.Ref), Value: as.Role + "|" + as.Kind + "|" + as.Ref})
			continue
		}
		id := holderID(as.Kind, as.Ref)
		if used[id] == nil {
			used[id] = map[string]bool{}
			order = append(order, id)
		}
		used[id][as.Role] = true
	}
	sort.SliceStable(v.People, func(i, j int) bool { return v.People[i].Email < v.People[j].Email })
	v.People = append(v.People, s.invitedRows(w, a)...)
	for l := 0; l <= 6; l++ {
		v.Reaches = append(v.Reaches, levelReach{Level: l, Reach: s.reach(l)})
	}
	sort.Slice(order, func(i, j int) bool {
		ki, _, _ := parseHolderID(order[i])
		kj, _, _ := parseHolderID(order[j])
		if holderOrder[ki] != holderOrder[kj] {
			return holderOrder[ki] < holderOrder[kj]
		}
		return order[i] < order[j]
	})
	for _, id := range order {
		kind, ref, _ := parseHolderID(id)
		var here []string
		for _, role := range a.RoleOrder {
			if used[id][role] {
				here = append(here, a.Roles[role])
			}
		}
		others := map[string]bool{}
		for _, as := range w.as {
			if as.App != a.Name && as.Kind == kind && as.Ref == ref && w.m.Has(as.App, as.Role) {
				others[as.App] = true
			}
		}
		other := "None"
		if len(others) > 0 {
			other = strconv.Itoa(len(others))
		}
		v.Groups = append(v.Groups, groupHereRow{Token: s.holderToken(w, kind, ref), Who: s.holderWho(w, kind, ref), Here: strings.Join(here, ", "), Other: other})
	}
	for _, pth := range a.Paths {
		row := pathRow{Open: pth.Open()}
		switch {
		case pth.Rest() && len(a.Paths) == 1:
			row.Patterns = "All paths"
		case pth.Rest():
			row.Patterns = "Everything else"
		default:
			row.Patterns, row.Mono = strings.Join(pth.Patterns, " "), true
		}
		if row.Open {
			row.Needs, row.Reason = "Nothing, open by design", pth.Reason
		} else {
			row.Needs = "The " + a.Roles[pth.Role] + " role"
			if pth.Role == roles.UserRole && len(a.Roles) > 1 {
				row.Needs += ", or any other"
			}
			row.Reason = "Not applicable"
		}
		v.Paths = append(v.Paths, row)
	}
	return v
}

// personRow is one person given a role directly. How names the
// administrator by the part of their address before the "@"; the whole
// address is in its title. An invitation (another part of the gateway) sets
// How to AssignedByInvite.
func (s *Server) personRow(a *roles.App, as store.RoleAssignment) personRow {
	p := personRow{Email: as.Ref, Role: as.Role, RoleLabel: a.Roles[as.Role], Until: "No end date", NoEnd: as.Until.IsZero()}
	by, _, _ := strings.Cut(as.CreatedBy, "@")
	switch as.How {
	case store.AssignedByInvite:
		p.How = "Accepted an invitation, " + s.longDate(as.CreatedAt)
	default:
		p.How = "By " + by + ", " + s.longDate(as.CreatedAt)
		p.HowTitle = "By " + as.CreatedBy + ", " + s.longDate(as.CreatedAt)
	}
	if !as.Until.IsZero() {
		// Until is the moment the role ends: the start of the day after the
		// last day it is held.
		p.Until = s.longDate(as.Until.Add(-time.Second))
		p.Ended = !s.now().Before(as.Until)
		if p.Ended {
			p.Until = fmt.Sprintf(msgPersonEnded, p.Until)
		}
	}
	return p
}
