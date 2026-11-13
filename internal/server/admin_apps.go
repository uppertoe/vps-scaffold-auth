package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/email"
	"github.com/uppertoe/vps-scaffold-auth/internal/roles"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// The Apps pages: every app role and who holds it (GET /admin/apps), and one
// app's page, where its roles are given and taken away
// (GET /admin/apps/{app}). A change on an app's page is first shown for
// review ("Save these changes?"), with the warnings the server finds, and is
// then saved in one transaction with a record of each change, after which the
// other administrators are emailed once.

// The strings the review and the email use. Each is kept here, once.
const (
	msgLastHolder    = "Nobody will hold %s once this is saved, so %s will be closed to everyone."
	msgNetworkOpens  = "Anyone on the %s will reach %s without signing in."
	msgGuestsOpen    = "Anyone who confirms an email address will reach %s."
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
		if !anyHolder(w, a) {
			out = append(out, attentionLine{Bad: true, Before: "Nobody holds the User role in ", Link: "/admin/apps/" + a.Name, Name: a.Label, After: ", so nobody can reach it."})
		}
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
	// InviteHref opens the Invite people form with this app's user role.
	InviteHref string
	// Pending is set while the page shows unsaved changes.
	Pending bool
	Review  *reviewView
	// Confirm is the invitation whose withdrawal is being confirmed
	// (?withdraw=id), with the confirmation's wording.
	Confirm                                 int64
	ConfirmText, ConfirmButton, ConfirmKeep string
	// PickerDone closes a picker.
	PickerDone string
}

type roleOption struct{ Role, Label string }

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
	v := &appView{Name: a.Name, Label: a.Label, Source: a.Source, OrphanNote: msgOrphanRole, Pending: p != nil && (len(p.give)+len(p.take) > 0),
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
	v.InviteHref = "/admin/invitations/new?role=" + url.QueryEscape(a.Name+":"+roles.UserRole)
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

// --- Changes and their review ---

// roleChange is one change on an app's page.
type roleChange struct {
	Give bool
	A    store.RoleAssignment
}

// encode is how the review form carries a change: give|role|kind|ref|until.
func (c roleChange) encode() string {
	op := "take"
	if c.Give {
		op = "give"
	}
	until := "0"
	if !c.A.Until.IsZero() {
		until = strconv.FormatInt(c.A.Until.Unix(), 10)
	}
	return strings.Join([]string{op, c.A.Role, c.A.Kind, c.A.Ref, until}, "|")
}

func decodeChange(app, v string) (roleChange, bool) {
	f := strings.Split(v, "|")
	if len(f) != 5 || (f[0] != "give" && f[0] != "take") {
		return roleChange{}, false
	}
	c := roleChange{Give: f[0] == "give", A: store.RoleAssignment{App: app, Role: f[1], Kind: f[2], Ref: f[3]}}
	if _, known := holderOrder[c.A.Kind]; !known {
		return roleChange{}, false
	}
	if n, err := strconv.ParseInt(f[4], 10, 64); err == nil && n > 0 {
		c.A.Until = time.Unix(n, 0)
	}
	return c, true
}

// reviewView is the "Save these changes?" dialog.
type reviewView struct {
	Items    []reviewItem
	Warnings []string
	Values   []string // the changes, for the form
	Note     string
}

type reviewItem struct {
	Role   string
	Op     string
	Token  *tokenView
	Person string
}

// handleAdminAppReview turns the app page's form into a list of changes and
// shows them for review, with the warnings the change raises.
func (s *Server) handleAdminAppReview(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	a, ok := s.appFromPath(w, r)
	if !ok {
		return
	}
	world, err := s.loadRolesWorld(r.Context())
	if err != nil {
		s.adminError(w, r)
		return
	}
	changes, warning := s.changesFromForm(r, world, a)
	if warning != "" {
		s.renderApp(w, r, http.StatusBadRequest, a, nil, nil, warning)
		return
	}
	if len(changes) == 0 {
		s.renderApp(w, r, http.StatusOK, a, nil, nil, "Nothing has been changed, so there is nothing to save.")
		return
	}
	s.renderApp(w, r, http.StatusOK, a, pendingOf(changes), s.review(world, a, changes), "")
}

// handleAdminAppEdit is "Keep editing": the app page again, with the changes
// under review still shown as unsaved.
func (s *Server) handleAdminAppEdit(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	a, ok := s.appFromPath(w, r)
	if !ok {
		return
	}
	var changes []roleChange
	for _, v := range r.PostForm["c"] {
		if c, ok := decodeChange(a.Name, v); ok {
			changes = append(changes, c)
		}
	}
	s.renderApp(w, r, http.StatusOK, a, pendingOf(changes), nil, "")
}

// pendingOf is the unsaved state the app page shows for changes. People are
// left out: they are listed in their own table, and are added again there.
func pendingOf(changes []roleChange) *pending {
	p := &pending{give: map[string]map[string]bool{}, take: map[string]map[string]bool{}}
	for _, c := range changes {
		if c.A.Kind == store.AssignPerson {
			continue
		}
		m := p.take
		if c.Give {
			m = p.give
		}
		if m[c.A.Role] == nil {
			m[c.A.Role] = map[string]bool{}
		}
		m[c.A.Role][holderID(c.A.Kind, c.A.Ref)] = true
	}
	return p
}

// changesFromForm reads the app page's forms: the holders ticked for each
// role ("roles" and "r.<role>"), a person to add ("person", "person_role",
// "until"), and assignments to take away ("take", role|kind|ref). It returns
// a warning, and no changes, for a person who cannot be added.
func (s *Server) changesFromForm(r *http.Request, w *rolesWorld, a *roles.App) ([]roleChange, string) {
	var out []roleChange
	current := map[string]store.RoleAssignment{}
	for _, as := range w.assigned2(a.Name) {
		current[as.Role+"|"+as.Kind+"|"+as.Ref] = as
	}
	for _, role := range r.PostForm["roles"] {
		if _, ok := a.Roles[role]; !ok {
			continue
		}
		want := map[string]bool{}
		for _, v := range r.PostForm["r."+role] {
			kind, ref, ok := parseHolderID(v)
			if !ok || kind == store.AssignPerson || !s.validHolder(w, kind, ref) {
				continue
			}
			if !roles.Honoured(store.RoleAssignment{Kind: kind, Role: role}) {
				return nil, msgNetworkUserOnly
			}
			want[holderID(kind, ref)] = true
		}
		for _, as := range w.assigned(a.Name, role) {
			id := holderID(as.Kind, as.Ref)
			// People are changed in their own table, and an assignment the
			// gateway ignores only by its own Remove.
			if as.Kind == store.AssignPerson || !roles.Honoured(as) {
				continue
			}
			if !want[id] {
				out = append(out, roleChange{A: as})
			}
			delete(want, id)
		}
		ids := make([]string, 0, len(want))
		for id := range want {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			kind, ref, _ := parseHolderID(id)
			out = append(out, roleChange{Give: true, A: store.RoleAssignment{App: a.Name, Role: role, Kind: kind, Ref: ref}})
		}
	}
	if raw := strings.TrimSpace(r.PostFormValue("person")); raw != "" {
		addr := normalizeEmail(raw)
		role := r.PostFormValue("person_role")
		if _, ok := a.Roles[role]; !ok {
			role = roles.UserRole
		}
		if !plainAddress(addr) {
			return nil, "The person has not been added. Enter a full email address, such as name@example.org."
		}
		pa := store.RoleAssignment{App: a.Name, Role: role, Kind: store.AssignPerson, Ref: addr, How: store.AssignedByAdmin}
		if d := strings.TrimSpace(r.PostFormValue("until")); d != "" {
			day, err := time.ParseInLocation("2006-01-02", d, s.tzloc())
			if err != nil {
				return nil, "The person has not been added. Enter the end date as a day, month and year."
			}
			pa.Until = day.AddDate(0, 0, 1)
			if !pa.Until.After(s.now()) {
				return nil, "The person has not been added, because the end date has passed."
			}
		}
		out = append(out, roleChange{Give: true, A: pa})
	}
	for _, v := range r.PostForm["take"] {
		f := strings.SplitN(v, "|", 3)
		if len(f) != 3 {
			continue
		}
		if as, ok := current[f[0]+"|"+f[1]+"|"+f[2]]; ok {
			out = append(out, roleChange{A: as})
		}
	}
	return out, ""
}

// assigned2 returns every assignment of an app, declared roles or not.
func (w *rolesWorld) assigned2(app string) []store.RoleAssignment {
	var out []store.RoleAssignment
	for _, a := range w.as {
		if a.App == app {
			out = append(out, a)
		}
	}
	return out
}

// validHolder reports whether a role may be given to the holder: a network
// NETWORK_RANGES names, guests, or a group of the matching kind.
func (s *Server) validHolder(w *rolesWorld, kind, ref string) bool {
	switch kind {
	case store.AssignNetwork:
		_, ok := s.cfg.NetworkRanges[ref]
		return ok
	case store.AssignGuests:
		return ref == ""
	case store.AssignDomainGroup:
		g, ok := w.groups[ref]
		return ok && g.Kind == store.GroupKindDomain
	case store.AssignList:
		g, ok := w.groups[ref]
		return ok && g.Kind == store.GroupKindList
	}
	return false
}

// review lists the changes and the warnings they raise.
func (s *Server) review(w *rolesWorld, a *roles.App, changes []roleChange) *reviewView {
	rv := &reviewView{Note: msgSaveNote}
	for _, c := range changes {
		rv.Values = append(rv.Values, c.encode())
		item := reviewItem{Role: roleLabel(a, c.A.Role), Op: "Take from"}
		if c.Give {
			item.Op = "Give to"
		}
		if c.A.Kind == store.AssignPerson {
			item.Person = c.A.Ref
			if c.Give && !c.A.Until.IsZero() {
				item.Person += ", until " + s.longDate(c.A.Until.Add(-time.Second))
			}
		} else {
			t := s.holderToken(w, c.A.Kind, c.A.Ref)
			item.Token = &t
		}
		rv.Items = append(rv.Items, item)
	}
	rv.Warnings = s.reviewWarnings(w, a, changes)
	return rv
}

func roleLabel(a *roles.App, role string) string {
	if l, ok := a.Roles[role]; ok {
		return l
	}
	return role
}

// reviewWarnings are the consequences a reviewer should see: a role left
// with nobody (for the user role, only once no role in the app is held,
// since any role admits it), and a role given to a network or to guests.
func (s *Server) reviewWarnings(w *rolesWorld, a *roles.App, changes []roleChange) []string {
	count := func(after bool) map[string]int {
		n := map[string]int{}
		held := map[string]bool{}
		for _, as := range w.assigned2(a.Name) {
			if w.current(as) {
				held[as.Role+"|"+as.Kind+"|"+as.Ref] = true
			}
		}
		if after {
			for _, c := range changes {
				held[c.A.Role+"|"+c.A.Kind+"|"+c.A.Ref] = c.Give
			}
		}
		for k, ok := range held {
			if ok {
				n[strings.SplitN(k, "|", 2)[0]]++
			}
		}
		for _, role := range a.RoleOrder {
			n[role] += len(w.cardsFor(a.Name, role))
		}
		return n
	}
	closed := func(n map[string]int, role string) bool {
		if n[role] > 0 {
			return false
		}
		if role != roles.UserRole {
			return true
		}
		for _, r := range a.RoleOrder {
			if n[r] > 0 {
				return false
			}
		}
		return true
	}
	before, after := count(false), count(true)
	var out []string
	for _, role := range a.RoleOrder {
		if !closed(before, role) && closed(after, role) {
			out = append(out, fmt.Sprintf(msgLastHolder, a.Roles[role], pathsPhrase(a, role)))
		}
	}
	for _, c := range changes {
		if !c.Give {
			continue
		}
		switch c.A.Kind {
		case store.AssignNetwork:
			out = append(out, fmt.Sprintf(msgNetworkOpens, s.networkLabel(c.A.Ref), pathsPhrase(a, c.A.Role)))
		case store.AssignGuests:
			out = append(out, fmt.Sprintf(msgGuestsOpen, pathsPhrase(a, c.A.Role)))
		}
	}
	return out
}

// handleAdminAppSave saves the reviewed changes in one transaction, with one
// admin-log record for each, then drops the role cache and emails the other
// administrators once.
func (s *Server) handleAdminAppSave(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	a, ok := s.appFromPath(w, r)
	if !ok {
		return
	}
	world, err := s.loadRolesWorld(r.Context())
	if err != nil {
		s.adminError(w, r)
		return
	}
	actor := ""
	if id, ok := s.sessions.ReadSession(r, s.now()); ok {
		actor = id.Email
	}
	var give, take []store.RoleAssignment
	var events []store.AdminEvent
	var lines []string
	for _, v := range r.PostForm["c"] {
		c, ok := decodeChange(a.Name, v)
		if !ok {
			continue
		}
		if c.Give {
			if _, declared := a.Roles[c.A.Role]; !declared {
				continue
			}
			if c.A.Kind == store.AssignPerson {
				if !plainAddress(c.A.Ref) || (!c.A.Until.IsZero() && !c.A.Until.After(s.now())) {
					continue
				}
				c.A.How = store.AssignedByAdmin
			} else if !s.validHolder(world, c.A.Kind, c.A.Ref) || !roles.Honoured(c.A) {
				continue
			}
			c.A.CreatedBy = actor
			give = append(give, c.A)
		} else {
			take = append(take, c.A)
		}
		action, op := store.AdminActionRoleTake, "Take from"
		if c.Give {
			action, op = store.AdminActionRoleGive, "Give to"
		}
		detail := c.A.Kind + " " + c.A.Ref
		holder := c.A.Ref
		if c.A.Kind != store.AssignPerson {
			holder = s.holderToken(world, c.A.Kind, c.A.Ref).Label
		}
		if c.Give && !c.A.Until.IsZero() {
			detail += " until " + s.longDate(c.A.Until.Add(-time.Second))
			holder += ", until " + s.longDate(c.A.Until.Add(-time.Second))
		}
		events = append(events, store.AdminEvent{
			Actor: actor, Action: action, Target: a.Name + ":" + c.A.Role, Detail: strings.TrimSpace(detail),
			ClientIP: clientIP(r), UserAgent: clampUserAgent(r.UserAgent()), CreatedAt: s.now(),
		})
		lines = append(lines, roleLabel(a, c.A.Role)+" · "+op+" · "+holder)
	}
	if len(events) == 0 {
		s.renderApp(w, r, http.StatusOK, a, nil, nil, "Nothing has been changed, so there is nothing to save.")
		return
	}
	if err := s.store.ApplyRoleChanges(r.Context(), give, take, events); err != nil {
		if errors.Is(err, store.ErrNoSuchGroup) || errors.Is(err, store.ErrGroupKind) || errors.Is(err, store.ErrInvalidAssignment) {
			s.renderApp(w, r, http.StatusConflict, a, nil, nil, "The changes have not been saved, because a group they name has been changed or deleted. Review the changes again.")
			return
		}
		s.adminError(w, r)
		return
	}
	s.forgetRoles()
	s.emailOtherAdmins(actor, fmt.Sprintf(msgChangeSubject, a.Label), lines)
	s.redirectDone(w, r, "/admin/apps/"+url.PathEscape(a.Name), "roles-saved", "")
}

// emailOtherAdmins sends one email about a saved change to every
// administrator except the one who made it.
func (s *Server) emailOtherAdmins(actor, subject string, lines []string) {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString("- " + l + "\n")
	}
	text := fmt.Sprintf(msgChangeBody, actor, s.longDate(s.now()), b.String())
	for _, to := range s.cfg.AdminEmails {
		if to == actor {
			continue
		}
		msg := email.Message{To: to, Subject: subject, Text: text}
		s.sendNotice("access change to "+to, func(ctx context.Context) error { return s.sender.Send(ctx, msg) })
	}
}
