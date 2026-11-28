// Changing an app's role holders: the edit form, the review step and saving.

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

	"github.com/uppertoe/vps-scaffold-auth/internal/email"
	"github.com/uppertoe/vps-scaffold-auth/internal/roles"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

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

// reviewView is the "Review the changes" dialog.
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
		// The changes that can be made stay on the page, unsaved.
		s.renderApp(w, r, http.StatusBadRequest, a, pendingOf(changes), nil, warning)
		return
	}
	if len(changes) == 0 {
		s.renderApp(w, r, http.StatusOK, a, nil, nil, "Nothing has been changed, so there is nothing to save.")
		return
	}
	s.renderApp(w, r, http.StatusOK, a, pendingOf(changes), s.review(world, a, changes), "")
}

// handleAdminAppEdit is the app page again, with changes still shown as
// unsaved: "Keep editing" sends the changes under review ("c"), and a
// picker's Add, without the page's script, sends the app page's own form.
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
	world, err := s.loadRolesWorld(r.Context())
	if err != nil {
		s.adminError(w, r)
		return
	}
	more, warning := s.changesFromForm(r, world, a)
	changes = append(changes, more...)
	status := http.StatusOK
	if warning != "" {
		status = http.StatusBadRequest
	}
	s.renderApp(w, r, status, a, pendingOf(changes), nil, warning)
}

// pendingOf is the unsaved state the app page shows for changes: holders
// about to be given or taken away, and people about to be given a role or
// have it taken away, each on the role's row.
func pendingOf(changes []roleChange) *pending {
	p := &pending{give: map[string]map[string]bool{}, take: map[string]map[string]bool{}}
	for _, c := range changes {
		if c.A.Kind == store.AssignPerson {
			if c.Give {
				p.people = append(p.people, c.A)
			} else {
				p.unpeople = append(p.unpeople, c.A)
			}
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
// role ("roles" and "r.<role>"); people about to be given a role, as tokens
// on its row ("p.<role>", address|day) or as typed in its picker ("pa.<role>"
// and "pu.<role>"); a person from the older single form ("person",
// "person_role", "until"); and assignments to take away ("take",
// role|kind|ref). Each change is checked here and again when it is saved. A
// change that cannot be made is left out, and the first such change's
// refusal is returned with the others, so the page can show them still
// unsaved.
func (s *Server) changesFromForm(r *http.Request, w *rolesWorld, a *roles.App) ([]roleChange, string) {
	var out []roleChange
	warning := ""
	refuse := func(msg string) {
		if warning == "" {
			warning = msg
		}
	}
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
				refuse(msgNetworkUserOnly)
				continue
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
	people := map[string]bool{} // role|address, so a person is added once
	addPerson := func(role, raw, day string) {
		if _, ok := a.Roles[role]; !ok {
			return
		}
		c, msg := s.personChange(a, role, raw, day)
		if msg != "" {
			refuse(msg)
			return
		}
		if k := role + "|" + c.A.Ref; !people[k] {
			people[k] = true
			out = append(out, c)
		}
	}
	for _, role := range a.RoleOrder {
		for _, v := range r.PostForm["p."+role] {
			addr, day, _ := strings.Cut(v, "|")
			addPerson(role, addr, day)
		}
		if raw := strings.TrimSpace(r.PostFormValue("pa." + role)); raw != "" {
			addPerson(role, raw, r.PostFormValue("pu."+role))
		}
	}
	if raw := strings.TrimSpace(r.PostFormValue("person")); raw != "" {
		role := r.PostFormValue("person_role")
		if _, ok := a.Roles[role]; !ok {
			role = roles.UserRole
		}
		addPerson(role, raw, r.PostFormValue("until"))
	}
	taken := map[string]bool{}
	for _, v := range r.PostForm["take"] {
		f := strings.SplitN(v, "|", 3)
		if len(f) != 3 || taken[v] {
			continue
		}
		if as, ok := current[f[0]+"|"+f[1]+"|"+f[2]]; ok {
			taken[v] = true
			out = append(out, roleChange{A: as})
		}
	}
	return out, warning
}

// personChange is a person about to be given a role, with an end date given
// as a day ("2006-01-02") or none. The role then ends at the start of the
// next day. It returns the refusal for an address or a day that cannot be
// used.
func (s *Server) personChange(a *roles.App, role, raw, day string) (roleChange, string) {
	addr := normalizeEmail(strings.TrimSpace(raw))
	if !plainAddress(addr) {
		return roleChange{}, msgPersonNotAddress
	}
	pa := store.RoleAssignment{App: a.Name, Role: role, Kind: store.AssignPerson, Ref: addr, How: store.AssignedByAdmin}
	if d := strings.TrimSpace(day); d != "" {
		t, err := time.ParseInLocation("2006-01-02", d, s.tzloc())
		if err != nil {
			return roleChange{}, msgPersonBadDate
		}
		pa.Until = t.AddDate(0, 0, 1)
		if !pa.Until.After(s.now()) {
			return roleChange{}, msgPersonPastDate
		}
	}
	return roleChange{Give: true, A: pa}, ""
}

// lastDay is the day a person's role is last held, as a form writes it: the
// day before Until, which is the start of the day after.
func (s *Server) lastDay(until time.Time) string {
	if until.IsZero() {
		return ""
	}
	return until.Add(-time.Second).In(s.tzloc()).Format("2006-01-02")
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
		switch {
		case c.A.Kind == store.AssignNetwork:
			out = append(out, fmt.Sprintf(msgNetworkOpens, s.networkLabel(c.A.Ref), pathsPhrase(a, c.A.Role)))
		case c.A.Kind == store.AssignGuests:
			out = append(out, fmt.Sprintf(msgGuestsOpen, pathsPhrase(a, c.A.Role)))
			if len(a.Hosts) > 0 {
				out = append(out, fmt.Sprintf(msgGuestsSignIn, joinOr(a.Hosts)))
			}
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
	actor := s.adminActor(r)
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
