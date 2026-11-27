package server

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// Groups under the app-roles model: a group is a domain group (email domains)
// or a list (people), chosen once when it is made. Every group page shows the
// app roles the group holds, because a change to the group reaches all of
// them.

// The groups pages' strings that carry a value. Each is kept here, once.
const (
	msgWebmail       = "%s is a public email service, so anyone could sign in with it. A domain group cannot include it."
	msgBadDomain     = "Enter a domain such as example.org.au, without the @ or anything before it."
	msgDomainTwice   = "The group already includes @%s."
	msgGroupHolds    = "%s holds %s. Remove the group from those roles on each app's page, then delete it."
	msgGroupExists   = "A group called %s already exists. Choose another name."
	msgGroupNameNew  = "A group cannot be called \"new\", because the page for a new group has that address."
	msgDomainSubject = "Access through %s has changed."
	msgDomainAdded   = "Added the domain @%s"
	msgDomainRemoved = "Removed the domain @%s"
	// msgDomainGroupGone is the line emailed when a domain group is deleted;
	// %s is its domains, such as "@rch.org.au and @mcri.edu.au".
	msgDomainGroupGone = "Deleted the group, which included %s"
	msgDomainsNeedOne  = "Enter at least one domain, such as example.org.au."
)

// appRoleRef is one app role a group holds, for "Roles this group holds".
type appRoleRef struct {
	App, Label string
}

// newGroupView is the New group page.
type newGroupView struct {
	Kind, Label, Domains, Org string
	OrgText                   orgNameCopy
	// Kinds is false with the app-roles model off, when only lists exist.
	Kinds bool
}

// groupDisplayName is a group's label, or its name when it has none.
func groupDisplayName(g groupView) string {
	if g.Label != "" {
		return g.Label
	}
	return g.Name
}

// fillGroupRoles adds each group's kind, domains and app roles to its view.
func (s *Server) fillGroupRoles(r *http.Request, view []groupView) error {
	ctx := r.Context()
	groups, err := s.store.ListGroups(ctx)
	if err != nil {
		return err
	}
	kinds := map[string]string{}
	orgs := map[string]string{}
	labels := map[string]string{}
	for _, g := range groups {
		kinds[g.Name] = g.Kind
		orgs[g.Name] = g.Org
		labels[g.Name] = g.Label
	}
	refs := func(names []string) []groupRef {
		out := make([]groupRef, 0, len(names))
		for _, n := range names {
			l := labels[n]
			if l == "" {
				l = n
			}
			out = append(out, groupRef{Name: n, Label: l})
		}
		return out
	}
	domains, err := s.store.ListGroupDomains(ctx)
	if err != nil {
		return err
	}
	as, err := s.store.ListRoleAssignments(ctx, "")
	if err != nil {
		return err
	}
	readers := s.readerGroups()
	for i := range view {
		g := &view[i]
		g.Kind = kinds[g.Name]
		if g.Kind == "" {
			g.Kind = store.GroupKindList
		}
		g.Domains = domains[g.Name]
		g.Org, g.OrgText = orgs[g.Name], orgNameText
		g.Display = groupDisplayName(*g)
		g.IncludeRefs, g.IncludedInRefs, g.OptionRefs = refs(g.Includes), refs(g.IncludedIn), refs(g.IncludeOptions)
		apps := map[string]bool{}
		for _, a := range as {
			if (a.Kind != store.AssignDomainGroup && a.Kind != store.AssignList) || a.Ref != g.Name {
				continue
			}
			g.RoleCount++
			app, role := a.App, a.Role
			if !apps[a.App] {
				label := a.App
				if ap, ok := s.appRoles.Apps[a.App]; ok {
					label = ap.Label
				}
				g.AppLabels = append(g.AppLabels, label)
			}
			apps[a.App] = true
			if ap, ok := s.appRoles.Apps[a.App]; ok {
				app = ap.Label
				if l, ok := ap.Roles[a.Role]; ok {
					role = l
				}
			}
			g.Roles = append(g.Roles, appRoleRef{App: a.App, Label: app + ": " + role})
		}
		sort.Slice(g.Roles, func(i, j int) bool { return g.Roles[i].Label < g.Roles[j].Label })
		sort.Slice(g.AppLabels, func(i, j int) bool { return strings.ToLower(g.AppLabels[i]) < strings.ToLower(g.AppLabels[j]) })
		g.AppCount = len(apps)
		g.Token = tokenView{Icon: iconDomain, Label: g.Display, Title: g.Display, Href: "/admin/groups/" + g.Name}
		if g.Kind != store.GroupKindDomain {
			g.Token.Icon, g.Token.Count = iconList, fmt.Sprint(len(g.Members))
		}
		if g.RoleCount > 0 {
			g.HoldsText = fmt.Sprintf(msgGroupHolds, g.Display, countWords(g.RoleCount, "role", "roles"))
		}
		if g.Kind == store.GroupKindDomain {
			at := make([]string, len(g.Domains))
			for j, d := range g.Domains {
				at[j] = "@" + d
			}
			g.Who = strings.Join(at, ", ")
			if g.Who == "" {
				g.Who = "No domains yet"
			}
		} else {
			kept := "kept by hand"
			if g.Feed != nil {
				kept = "filled from a feed"
			}
			g.Who = capFirst(countWords(len(g.Members), "person", "people")) + ", " + kept
		}
		if g.RoleCount > 0 {
			g.UsedBy = capFirst(countWords(g.RoleCount, "role", "roles")) + " in " + countWords(g.AppCount, "app", "apps")
		}
		g.Uses = s.groupUses(g, readers)
		g.NotUsed = g.Unused && g.RoleCount == 0 && len(g.Uses) == 0
		if g.Label == "" {
			// A group without a label is named by its slug, drawn as a slug.
			g.Token.Tone = "slug"
		}
	}
	return nil
}

// renderGroup shows one group's page, with an optional warning.
func (s *Server) renderGroup(w http.ResponseWriter, r *http.Request, status int, name, warning string) {
	view, err := s.groupViews(r)
	if err != nil {
		s.adminError(w, r)
		return
	}
	if err := s.fillGroupRoles(r, view); err != nil {
		s.adminError(w, r)
		return
	}
	for i := range view {
		if view[i].Name == name {
			if r.Method == http.MethodGet {
				s.confirmDomainRemoval(&view[i], r.URL.Query().Get("remove"))
			}
			s.renderAdmin(w, r, status, "admin_group", adminData{
				Title: groupDisplayName(view[i]), Group: &view[i], NameText: groupNameText, OpenGroup: name, Warning: warning, GroupsText: groupsText,
			})
			return
		}
	}
	http.Redirect(w, r, "/admin/groups", http.StatusFound)
}

// confirmDomainRemoval fills the confirmation of removing one of a domain
// group's domains: the roles the group holds, in which apps, and whether
// the group will admit anybody afterwards.
func (s *Server) confirmDomainRemoval(g *groupView, domain string) {
	found := false
	for _, d := range g.Domains {
		found = found || d == domain
	}
	if !found || g.Kind != store.GroupKindDomain {
		return
	}
	g.ConfirmDomain = domain
	g.ConfirmButton, g.ConfirmKeep = fmt.Sprintf(msgDomainRemoveButton, domain), msgDomainRemoveKeep
	switch {
	case g.RoleCount == 0:
		g.ConfirmText = fmt.Sprintf(msgDomainRemoveNoRole, g.Display, domain)
	case len(g.Domains) == 1:
		g.ConfirmText = fmt.Sprintf(msgDomainRemoveHolds, g.Display, countWords(g.RoleCount, "role", "roles"), joinAnd(g.AppLabels)) + " " +
			fmt.Sprintf(msgDomainRemoveLast, domain, domain, g.Display)
	default:
		g.ConfirmText = fmt.Sprintf(msgDomainRemoveHolds, g.Display, countWords(g.RoleCount, "role", "roles"), joinAnd(g.AppLabels)) + " " +
			fmt.Sprintf(msgDomainRemoveSome, domain, domain, g.Display)
	}
}

// handleAdminNewGroup is the New group page.
func (s *Server) handleAdminNewGroup(w http.ResponseWriter, r *http.Request) {
	s.renderNewGroup(w, r, http.StatusOK, &newGroupView{Kind: store.GroupKindList}, "")
}

func (s *Server) renderNewGroup(w http.ResponseWriter, r *http.Request, status int, v *newGroupView, warning string) {
	v.Kinds = s.rolesOn()
	v.OrgText = orgNameText
	if !v.Kinds {
		v.Kind = store.GroupKindList
	}
	s.renderAdmin(w, r, status, "admin_group_new", adminData{Title: "New group", NewGroup: v, Warning: warning})
}

// groupSlug makes a group name from a label: "RCH and MCRI staff" is
// "rch-and-mcri-staff".
func groupSlug(label string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(label) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 64 {
		out = strings.Trim(out[:64], "-")
	}
	return out
}

// splitDomains reads a field of domains separated by commas, spaces or
// lines.
func splitDomains(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' || r == '\t' })
}

// createGroupFromNewPage handles the New group page's form: the kind, a name
// (the group's label, from which its name is made) and, for a domain group,
// its domains, all checked before anything is created.
func (s *Server) createGroupFromNewPage(w http.ResponseWriter, r *http.Request) {
	v := &newGroupView{Kind: r.PostFormValue("kind"), Label: clampLabel(r.PostFormValue("label")), Domains: r.PostFormValue("domains"),
		Org: clampOrg(r.PostFormValue("org"))}
	if v.Kind != store.GroupKindDomain || !s.rolesOn() {
		v.Kind = store.GroupKindList
	}
	name := groupSlug(v.Label)
	switch {
	case name == "new":
		s.renderNewGroup(w, r, http.StatusBadRequest, v, msgGroupNameNew)
		return
	case authz.IsReservedGroup(name):
		s.renderNewGroup(w, r, http.StatusBadRequest, v, "The names \"admin\", \"user\" and \"guest\" are reserved roles and cannot be used as group names.")
		return
	case !authz.ValidGroupName(name):
		s.renderNewGroup(w, r, http.StatusBadRequest, v, "Enter a name for the group, using letters or numbers.")
		return
	}
	if s.groupExists(r, name) {
		s.renderNewGroup(w, r, http.StatusConflict, v, fmt.Sprintf(msgGroupExists, name))
		return
	}
	var domains []string
	if v.Kind == store.GroupKindDomain {
		for _, raw := range splitDomains(v.Domains) {
			d, err := store.NormalizeDomain(raw)
			if err != nil {
				s.renderNewGroup(w, r, http.StatusBadRequest, v, msgBadDomain)
				return
			}
			if store.IsWebmailDomain(d) {
				s.renderNewGroup(w, r, http.StatusBadRequest, v, fmt.Sprintf(msgWebmail, d))
				return
			}
			domains = append(domains, d)
		}
		if len(domains) == 0 {
			s.renderNewGroup(w, r, http.StatusBadRequest, v, msgDomainsNeedOne)
			return
		}
	}
	if err := s.store.CreateGroupOfKind(r.Context(), name, v.Label, v.Kind); err != nil {
		s.adminError(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionGroupCreate, name, v.Kind)
	var lines []string
	for _, d := range domains {
		if err := s.store.AddGroupDomain(r.Context(), name, d); err != nil {
			s.forgetRoles()
			s.adminError(w, r)
			return
		}
		s.auditAdmin(r, store.AdminActionGroupDomainAdd, name, d)
		lines = append(lines, fmt.Sprintf(msgDomainAdded, d))
	}
	if len(lines) > 0 {
		s.domainsChanged(r, name, lines)
	}
	if v.Kind == store.GroupKindDomain && v.Org != "" {
		if _, err := s.store.SetGroupOrg(r.Context(), name, v.Org); err != nil {
			s.adminError(w, r)
			return
		}
		s.auditAdmin(r, store.AdminActionGroupOrg, name, v.Org)
	}
	s.redirectDone(w, r, "/admin/groups", "group-created", name)
}

// handleAdminAddDomain adds a domain to a domain group. The change reaches
// every role the group holds, so the role cache is dropped and the other
// administrators are emailed.
func (s *Server) handleAdminAddDomain(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	group := normalizeGroupName(r.PathValue("name"))
	d, err := store.NormalizeDomain(r.PostFormValue("domain"))
	if err != nil {
		s.renderGroup(w, r, http.StatusBadRequest, group, msgBadDomain)
		return
	}
	if store.IsWebmailDomain(d) {
		s.renderGroup(w, r, http.StatusBadRequest, group, fmt.Sprintf(msgWebmail, d))
		return
	}
	have, err := s.store.ListGroupDomains(r.Context())
	if err != nil {
		s.adminError(w, r)
		return
	}
	for _, x := range have[group] {
		if x == d {
			s.renderGroup(w, r, http.StatusOK, group, fmt.Sprintf(msgDomainTwice, d))
			return
		}
	}
	switch err := s.store.AddGroupDomain(r.Context(), group, d); {
	case errors.Is(err, store.ErrNoSuchGroup):
		http.NotFound(w, r)
		return
	case errors.Is(err, store.ErrGroupKind):
		s.renderGroup(w, r, http.StatusBadRequest, group, "A domain can be added to a domain group only. A list holds people.")
		return
	case err != nil:
		s.adminError(w, r)
		return
	}
	s.domainChanged(r, group, d, store.AdminActionGroupDomainAdd, fmt.Sprintf(msgDomainAdded, d))
	s.redirectDone(w, r, "/admin/groups", "domain-added", group)
}

func (s *Server) handleAdminRemoveDomain(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	group := normalizeGroupName(r.PathValue("name"))
	d := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(r.PostFormValue("domain"))), "@")
	have, err := s.store.ListGroupDomains(r.Context())
	if err != nil {
		s.adminError(w, r)
		return
	}
	found := false
	for _, x := range have[group] {
		found = found || x == d
	}
	if !found {
		s.redirectDone(w, r, "/admin/groups", "", group)
		return
	}
	if err := s.store.RemoveGroupDomain(r.Context(), group, d); err != nil {
		s.adminError(w, r)
		return
	}
	s.domainChanged(r, group, d, store.AdminActionGroupDomainRemove, fmt.Sprintf(msgDomainRemoved, d))
	s.redirectDone(w, r, "/admin/groups", "domain-removed", group)
}

// domainChanged records a domain change, drops the role cache and emails the
// other administrators.
func (s *Server) domainChanged(r *http.Request, group, domain, action, line string) {
	s.auditAdmin(r, action, group, domain)
	s.domainsChanged(r, group, []string{line})
}

// domainsChanged drops the role cache, so the change applies at the next
// decision, and emails the other administrators the lines describing it.
// Adding or removing a domain, and creating or deleting a domain group, all
// come through here; the caller records each change in the audit.
func (s *Server) domainsChanged(r *http.Request, group string, lines []string) {
	s.forgetRoles()
	actor := s.actorOf(r)
	label := group
	if gs, err := s.store.ListGroups(r.Context()); err == nil {
		for _, g := range gs {
			if g.Name == group && g.Label != "" {
				label = g.Label
			}
		}
	}
	s.emailOtherAdmins(actor, fmt.Sprintf(msgDomainSubject, label), lines)
}

// actorOf is the address of the administrator making a request, for the
// emails to the other administrators.
func (s *Server) actorOf(r *http.Request) string {
	if id, ok := s.sessions.ReadSession(r, s.now()); ok {
		return id.Email
	}
	return ""
}

// clampOrg trims an organisation name, drops control characters and caps it
// at 80 characters.
func clampOrg(org string) string {
	org = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, trimField(org))
	if r := []rune(org); len(r) > 80 {
		org = strings.TrimSpace(string(r[:80]))
	}
	return org
}

// handleAdminGroupOrg sets a domain group's organisation name, which a
// withdrawn or replaced card's page names. It changes nobody's access, so the
// other administrators are not emailed.
func (s *Server) handleAdminGroupOrg(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	group := normalizeGroupName(r.PathValue("name"))
	org := clampOrg(r.PostFormValue("org"))
	found, err := s.store.SetGroupOrg(r.Context(), group, org)
	if err != nil {
		s.adminError(w, r)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionGroupOrg, group, org)
	s.redirectDone(w, r, "/admin/groups", "org-saved", group)
}

// --- Groups: every use of a group ---

// The Groups pages' wording for a group's uses. Each is kept here, once.
const (
	msgUseIncluded   = "Included in %s"
	msgUseFeed       = "Feed to %s"
	msgOtherUsesHead = "Also used by"
	msgNoNameSet     = "No name set"
	msgNotUsedTitle  = "This group holds no app role. No feed, app, setting, other group or break-glass card names it, so the group may be left over from an app that has been removed."
)

// groupsCopy is the Groups pages' wording for a group's uses.
type groupsCopy struct {
	NoName, OtherUses, NotUsedTitle string
}

var groupsText = groupsCopy{NoName: msgNoNameSet, OtherUses: msgOtherUsesHead, NotUsedTitle: msgNotUsedTitle}

// groupUse is one use of a group other than its roles: a group that
// includes it, or an app it is fed to.
type groupUse struct {
	Label, Href, Icon string
}

// groupUses lists the uses of a group other than its roles, in that order:
// the groups that include it, and the apps that read its members.
func (s *Server) groupUses(g *groupView, readers map[string][]string) []groupUse {
	var out []groupUse
	for _, ref := range g.IncludedInRefs {
		out = append(out, groupUse{Label: fmt.Sprintf(msgUseIncluded, ref.Label), Href: "/admin/groups/" + ref.Name, Icon: "list"})
	}
	var apps []string
	for app, groups := range readers {
		for _, gr := range groups {
			if gr == g.Name {
				apps = append(apps, app)
			}
		}
	}
	sort.Strings(apps)
	for _, app := range apps {
		label := capFirst(app)
		if a, ok := s.appRoles.Apps[app]; ok {
			label = a.Label
		}
		out = append(out, groupUse{Label: fmt.Sprintf(msgUseFeed, label), Href: appFeedsPath, Icon: "feed"})
	}
	return out
}

// readerGroups are the groups each app reads from the members endpoint, from
// the readers file and MEMBER_READERS, usable or not.
func (s *Server) readerGroups() map[string][]string {
	out := map[string][]string{}
	for app, gs := range s.cfg.MemberReadersFilePairs {
		out[app] = append(out[app], gs...)
	}
	for _, r := range s.members.readers {
		if !r.fromFile {
			out[r.app] = append(out[r.app], r.groups...)
		}
	}
	for _, u := range s.cfg.UnusableMemberReaders {
		if _, listed := s.cfg.MemberReadersFilePairs[u.App]; !listed {
			out[u.App] = append(out[u.App], u.Groups...)
		}
	}
	for app, gs := range out {
		sort.Strings(gs)
		out[app] = compactStrings(gs)
	}
	return out
}

func compactStrings(xs []string) []string {
	var out []string
	for i, x := range xs {
		if i == 0 || x != xs[i-1] {
			out = append(out, x)
		}
	}
	return out
}
