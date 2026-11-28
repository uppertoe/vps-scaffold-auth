// The admin lists pages: creating and deleting lists, labels and members.

package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"unicode"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// --- Groups ---

// handleAdminGroups lists the groups. A link from before groups had their own
// pages (?open=name) goes to that group's page.
func (s *Server) handleAdminGroups(w http.ResponseWriter, r *http.Request) {
	view, err := s.groupViews(r)
	if err == nil {
		err = s.fillGroupRoles(r, view)
	}
	if err != nil {
		s.adminError(w, r)
		return
	}
	if open := normalizeGroupName(r.URL.Query().Get("open")); open != "" {
		for _, g := range view {
			if g.Name == open {
				http.Redirect(w, r, "/admin/groups/"+open, http.StatusFound)
				return
			}
		}
	}
	s.renderAdmin(w, r, http.StatusOK, "admin_groups", adminData{
		Title: "Groups", Groups: view, NoOrgName: msgNoOrgName, GroupsText: groupsText,
	})
}

// handleAdminGroup shows one group: its source, members, includes and label,
// or a domain group's domains, and the app roles it holds.
func (s *Server) handleAdminGroup(w http.ResponseWriter, r *http.Request) {
	s.renderGroup(w, r, http.StatusOK, normalizeGroupName(r.PathValue("name")), "")
}

// groupViews builds every group's view.
func (s *Server) groupViews(r *http.Request) ([]groupView, error) {
	groups, err := s.store.ListGroups(r.Context())
	if err != nil {
		return nil, err
	}
	cardTargets := map[string]bool{}
	codes, err := s.store.ListBreakGlassCodes(r.Context())
	if err != nil {
		return nil, err
	}
	for _, c := range codes {
		if c.TargetGroup != "" {
			cardTargets[normalizeGroupName(c.TargetGroup)] = true
		}
	}
	includes, err := s.store.ListGroupIncludes(r.Context())
	if err != nil {
		return nil, err
	}
	syncStates, err := s.store.ListGroupSyncStates(r.Context())
	if err != nil {
		return nil, err
	}
	includedIn := map[string][]string{}
	for g, incs := range includes {
		for _, inc := range incs {
			includedIn[inc] = append(includedIn[inc], g)
		}
	}
	referenced := s.referencedGroups()
	existing := make(map[string]bool, len(groups))
	view := make([]groupView, 0, len(groups))
	for _, g := range groups {
		existing[g.Name] = true
		members, err := s.store.ListGroupMembers(r.Context(), g.Name)
		if err != nil {
			return nil, err
		}
		var addedFrom map[string]string
		if _, fed := s.feedFor(g.Name); fed {
			addedFrom = syncStates[g.Name].AddedFrom
		}
		mv := make([]memberView, 0, len(members))
		for _, m := range members {
			ok := s.known(r.Context(), m)
			mv = append(mv, memberView{Email: m, Permitted: ok, Guest: !ok, AddedFrom: addedFrom[m]})
		}
		inc := map[string]bool{}
		for _, i := range includes[g.Name] {
			inc[i] = true
		}
		var options []string
		for _, o := range groups {
			if o.Name != g.Name && !inc[o.Name] {
				options = append(options, o.Name)
			}
		}
		sort.Strings(includedIn[g.Name])
		view = append(view, groupView{
			Feed: s.feedViewFor(g.Name, syncStates),
			Name: g.Name, Label: g.Label, Members: mv,
			Unused:         !cardTargets[g.Name] && len(includedIn[g.Name]) == 0 && !referenced[g.Name],
			Includes:       includes[g.Name],
			IncludedIn:     includedIn[g.Name],
			IncludeOptions: options,
		})
	}
	// A feed-filled group whose feed has never answered has no group row yet
	// (the sync creates the row once the feed has answered), but it may have a
	// sync state saying why. List it anyway, with that state and the "Sync
	// now" button, so a failed first fetch can be seen and retried here and
	// not only reported on the overview.
	unsynced := make([]string, 0)
	for g := range s.feeds.feeds {
		if !existing[g] {
			unsynced = append(unsynced, g)
		}
	}
	sort.Strings(unsynced)
	for _, g := range unsynced {
		view = append(view, groupView{
			Feed: s.feedViewFor(g, syncStates), NotYetCreated: true,
			Name: g, Members: []memberView{},
		})
	}
	return view, nil
}

// referencedGroups are the groups named by a setting or manifest rather than
// by the role assignments: a feed fills it (GROUP_FEEDS), an app reads its
// members (the member-readers manifest or MEMBER_READERS), or the deprecated
// BREAKGLASS_REFUSED_GROUPS names it. Such a group is in use, so it is never
// offered for deletion as unused.
func (s *Server) referencedGroups() map[string]bool {
	out := map[string]bool{}
	for g := range s.feeds.feeds {
		out[normalizeGroupName(g)] = true
	}
	for _, gs := range s.readerGroups() {
		for _, g := range gs {
			out[normalizeGroupName(g)] = true
		}
	}
	for _, g := range s.cfg.BreakGlassRefusedGroups {
		out[normalizeGroupName(g)] = true
	}
	return out
}

// feedViewFor describes a feed-filled group's source and last sync for the
// Groups page, or returns nil for a group no feed fills.
func (s *Server) feedViewFor(group string, syncStates map[string]store.GroupSyncState) *feedView {
	f, ok := s.feedFor(group)
	if !ok {
		return nil
	}
	fv := &feedView{}
	if u, err := url.Parse(f.URL); err == nil {
		fv.Host = u.Host
	}
	if st, ok := syncStates[group]; ok {
		fv.Status, fv.Detail = st.Status, st.Detail
		fv.LastAttempt = s.stampMin(st.LastAttempt)
		if !st.LastSuccess.IsZero() {
			fv.LastSuccess = s.stampMin(st.LastSuccess)
			fv.Since = st.LastSuccess.In(s.tzloc()).Format("2 January")
		}
		fv.Pending = st.Status == store.GroupSyncHeld
		if fv.Pending {
			fv.PendingAdd, fv.PendingRemove = st.PendingAddList, st.PendingRemoveList
			fv.PendingHash = st.PendingHash
			if s.cfg.FeedAutoApplyAfter > 0 {
				fv.Kept = st.KeptHash != "" && st.KeptHash == st.PendingHash
				if !fv.Kept && !st.HeldSince.IsZero() {
					fv.AutoAt = s.stampMin(st.HeldSince.Add(s.cfg.FeedAutoApplyAfter))
				}
			}
		}
	}
	if r, ok := s.feeds.retryFor(group); ok {
		fv.Retry = &feedRetryView{At: s.stampMin(r.At), Next: s.stampMin(r.Next), Reason: r.Reason, Left: 1 + feedRetries - r.Attempt}
	}
	return fv
}

func (s *Server) handleAdminCreateGroup(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	if r.PostFormValue("from") == "new" {
		s.createGroupFromNewPage(w, r)
		return
	}
	name := normalizeGroupName(r.PostFormValue("name"))
	if name == "new" {
		s.renderAdmin(w, r, http.StatusBadRequest, "admin_message", adminData{Title: "Invalid group name", Message: msgGroupNameNew})
		return
	}
	if authz.IsReservedGroup(name) {
		s.renderAdmin(w, r, http.StatusBadRequest, "admin_message", adminData{
			Title:   "Reserved group name",
			Message: "The names \"admin\", \"user\" and \"guest\" are reserved roles and cannot be used as group names.",
		})
		return
	}
	if !authz.ValidGroupName(name) {
		s.renderAdmin(w, r, http.StatusBadRequest, "admin_message", adminData{
			Title:   "Invalid group name",
			Message: "Group names may use only lowercase letters, numbers, hyphens, and underscores — no spaces, commas, or other punctuation. Use the label field for a friendly display name.",
		})
		return
	}
	if err := s.store.CreateGroup(r.Context(), name, clampLabel(r.PostFormValue("label"))); err != nil {
		s.adminError(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionGroupCreate, name, "")
	s.redirectDone(w, r, "/admin/groups", "group-created", name)
}

func (s *Server) handleAdminDeleteGroup(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	if _, synced := s.feedFor(normalizeGroupName(r.PathValue("name"))); synced {
		s.redirectDone(w, r, "/admin/groups", "group-synced", normalizeGroupName(r.PathValue("name")))
		return
	}
	name := normalizeGroupName(r.PathValue("name"))
	// The group's approvals for apps to read its members go with it (in
	// DeleteGroup's transaction); note them first, to audit each.
	approvals, err := s.store.ListMemberReaderApprovals(r.Context())
	if err != nil {
		s.adminError(w, r)
		return
	}
	// A domain group's domains are noted too, for the email to the other
	// administrators, and its label, which goes with it.
	domains, err := s.store.ListGroupDomains(r.Context())
	if err != nil {
		s.adminError(w, r)
		return
	}
	label := name
	if gs, err := s.store.ListGroups(r.Context()); err == nil {
		for _, g := range gs {
			if g.Name == name && g.Label != "" {
				label = g.Label
			}
		}
	}
	if err := s.store.DeleteGroup(r.Context(), name); errors.Is(err, store.ErrGroupHoldsRoles) {
		n, err := s.store.GroupRoleCount(r.Context(), name)
		if err != nil {
			s.adminError(w, r)
			return
		}
		label := name
		if gs, err := s.store.ListGroups(r.Context()); err == nil {
			for _, g := range gs {
				if g.Name == name && g.Label != "" {
					label = g.Label
				}
			}
		}
		s.renderGroup(w, r, http.StatusConflict, name, fmt.Sprintf(msgGroupHolds, label, countWords(n, "role", "roles")))
		return
	} else if err != nil {
		s.adminError(w, r)
		return
	}
	s.markGroupsChanged(s.now())
	s.auditAdmin(r, store.AdminActionGroupDelete, name, "")
	s.forgetRoles()
	if ds := domains[name]; len(ds) > 0 {
		at := make([]string, len(ds))
		for i, d := range ds {
			at[i] = "@" + d
		}
		s.emailOtherAdmins(s.adminActor(r), fmt.Sprintf(msgDomainSubject, label), []string{fmt.Sprintf(msgDomainGroupGone, joinAnd(at))})
	}
	for _, a := range approvals {
		if a.Group == name {
			s.auditAdmin(r, store.AdminActionMemberReaderWithdraw, a.App, a.Group)
		}
	}
	s.redirectDone(w, r, "/admin/groups", "group-deleted", "")
}

func (s *Server) handleAdminAddMember(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	if _, synced := s.feedFor(normalizeGroupName(r.PathValue("name"))); synced {
		s.redirectDone(w, r, "/admin/groups", "group-synced", normalizeGroupName(r.PathValue("name")))
		return
	}
	group := normalizeGroupName(r.PathValue("name"))
	if !s.groupExists(r, group) {
		http.NotFound(w, r)
		return
	}
	// One field takes one address or many (pasted, one per line or separated
	// by commas or semicolons). A single valid new address is added at once;
	// anything more goes through a confirmation page.
	raw := r.PostFormValue("emails")
	if raw == "" {
		raw = r.PostFormValue("email")
	}
	plan, err := s.planBulkAdd(r, group, raw)
	if err != nil {
		s.adminError(w, r)
		return
	}
	if plan.total() == 0 || (len(plan.Invalid) > 0 && plan.total() == len(plan.Invalid)) {
		s.redirectDone(w, r, "/admin/groups", "member-invalid", group)
		return
	}
	if plan.total() == 1 && len(plan.Add) == 1 && plan.Add[0].Permitted {
		s.addMembers(w, r, group, []string{plan.Add[0].Email})
		return
	}
	s.renderAdmin(w, r, http.StatusOK, "admin_bulk_add", adminData{Title: "Add members", Bulk: plan})
}

// validCardLabel reports whether a break-glass card label may become part of
// a session's principal: no "@", no comma and no control character.
func validCardLabel(label string) bool {
	for _, r := range label {
		if r == '@' || r == ',' || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// clampLabel trims a group label and caps it at 200 characters.
func clampLabel(label string) string {
	label = trimField(label)
	if r := []rune(label); len(r) > 200 {
		label = string(r[:200])
	}
	return label
}

// handleAdminGroupLabel changes a group's display label. The label is shown to
// administrators only; apps see the group name.
func (s *Server) handleAdminGroupLabel(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	group := normalizeGroupName(r.PathValue("name"))
	label := clampLabel(r.PostFormValue("label"))
	found, err := s.store.UpdateGroupLabel(r.Context(), group, label)
	if err != nil {
		s.adminError(w, r)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionGroupLabel, group, label)
	s.redirectDone(w, r, "/admin/groups", "label-saved", group)
}

func (s *Server) handleAdminRemoveMember(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	if _, synced := s.feedFor(normalizeGroupName(r.PathValue("name"))); synced {
		s.redirectDone(w, r, "/admin/groups", "group-synced", normalizeGroupName(r.PathValue("name")))
		return
	}
	group := normalizeGroupName(r.PathValue("name"))
	emailAddr := normalizeEmail(r.PostFormValue("email"))
	if err := s.store.RemoveGroupMember(r.Context(), group, emailAddr); err != nil {
		s.adminError(w, r)
		return
	}
	s.markGroupsChanged(s.now())
	s.auditAdmin(r, store.AdminActionGroupRemoveMember, group, emailAddr)
	s.redirectDone(w, r, "/admin/groups", "member-removed", group)
}
