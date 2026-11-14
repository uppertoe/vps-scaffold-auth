package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// maxBulkAddresses caps one paste, so a stray file cannot become a very long
// confirmation page or transaction.
const maxBulkAddresses = 1000

// bulkPlan sorts a pasted list of addresses for the confirmation page.
type bulkPlan struct {
	Group   string
	Label   string       // the group's label, or its name when it has none
	Add     []memberView // valid and not yet members; Permitted false = not on the allow-list
	Already []string     // already members
	Invalid []string     // not an email address
	TooMany bool         // the paste was cut at maxBulkAddresses
	// Refused are addresses the allow-list does not admit, which the gateway
	// will not add to this group because the group is an application role
	// (RefusedReason says which kind); see refusedTargets.
	Refused       []string
	RefusedReason string
}

func (p *bulkPlan) total() int {
	return len(p.Add) + len(p.Already) + len(p.Invalid) + len(p.Refused)
}

var (
	bulkSplit = regexp.MustCompile(`[\s,;]+`)
	angleAddr = regexp.MustCompile(`[^,;\n<>]*<([^<>\s]+)>`)
)

func (s *Server) groupExists(r *http.Request, name string) bool {
	if !authz.ValidGroupName(name) {
		return false
	}
	groups, err := s.store.ListGroups(r.Context())
	if err != nil {
		return false
	}
	for _, g := range groups {
		if g.Name == name {
			return true
		}
	}
	return false
}

// planBulkAdd splits raw into addresses and sorts them. Display-name forms
// such as "Jane Citizen <jane@example.org>" are accepted, as people paste them
// from mail clients.
func (s *Server) planBulkAdd(r *http.Request, group, raw string) (*bulkPlan, error) {
	plan := &bulkPlan{Group: group, Label: group}
	plan.RefusedReason, _ = s.targetRefusal(group)
	if gs, err := s.store.ListGroups(r.Context()); err == nil {
		for _, g := range gs {
			if g.Name == group && g.Label != "" {
				plan.Label = g.Label
			}
		}
	}
	members, err := s.store.ListGroupMembers(r.Context(), group)
	if err != nil {
		return nil, err
	}
	existing := make(map[string]bool, len(members))
	for _, m := range members {
		existing[m] = true
	}
	seen := map[string]bool{}
	// Keep only the address from "Name <addr>" forms, then split. Words with
	// no "@" are names or noise and are ignored; anything with an "@" that is
	// not a valid address is listed as invalid.
	raw = angleAddr.ReplaceAllString(raw, " $1 ")
	for _, tok := range bulkSplit.Split(raw, -1) {
		tok = strings.Trim(tok, `"'<>()`)
		if !strings.Contains(tok, "@") {
			continue
		}
		e := normalizeEmail(tok)
		if seen[e] {
			continue
		}
		if plan.total() >= maxBulkAddresses {
			plan.TooMany = true
			break
		}
		seen[e] = true
		switch {
		case !plainAddress(e):
			plan.Invalid = append(plan.Invalid, tok)
		case existing[e]:
			plan.Already = append(plan.Already, e)
		case plan.RefusedReason != "" && !s.policy.Allowed(e):
			plan.Refused = append(plan.Refused, e)
		default:
			ok := s.policy.Allowed(e)
			plan.Add = append(plan.Add, memberView{Email: e, Permitted: ok, Guest: !ok})
		}
	}
	return plan, nil
}

// handleAdminConfirmMembers adds the addresses ticked on the confirmation page.
func (s *Server) handleAdminConfirmMembers(w http.ResponseWriter, r *http.Request) {
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
	// The confirmation page never offers a stranger for a group that is an
	// application role, but the check is made here as well, so a request made
	// without the page cannot add one.
	_, refused := s.targetRefusal(group)
	var emails []string
	dropped := false
	for _, e := range r.PostForm["add"] {
		e = normalizeEmail(e)
		if !plainAddress(e) || len(emails) >= maxBulkAddresses {
			continue
		}
		if refused && !s.policy.Allowed(e) {
			dropped = true
			continue
		}
		emails = append(emails, e)
	}
	if len(emails) == 0 {
		if dropped {
			s.redirectDone(w, r, "/admin/groups", "members-refused", group)
			return
		}
		s.redirectDone(w, r, "/admin/groups", "members-none", group)
		return
	}
	s.addMembers(w, r, group, emails)
}

// addMembers adds addresses, audits each one actually added, and returns to
// the group.
func (s *Server) addMembers(w http.ResponseWriter, r *http.Request, group string, emails []string) {
	added, err := s.store.AddGroupMembers(r.Context(), group, emails)
	if err != nil {
		s.adminError(w, r)
		return
	}
	s.markGroupsChanged(s.now())
	for _, e := range added {
		s.auditAdmin(r, store.AdminActionGroupAddMember, group, e)
	}
	done := "members-added"
	if len(emails) == 1 {
		done = "member-added"
	}
	s.redirectDone(w, r, "/admin/groups", done, group)
}

func (s *Server) handleAdminAddInclude(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	group := normalizeGroupName(r.PathValue("name"))
	included := normalizeGroupName(r.PostFormValue("included"))
	if authz.IsReservedGroup(group) || authz.IsReservedGroup(included) || !s.groupExists(r, group) || !s.groupExists(r, included) {
		http.NotFound(w, r)
		return
	}
	// A synced group means "whoever the feed lists"; it must not admit a
	// hand-managed group as well.
	if _, synced := s.feedFor(group); synced {
		s.redirectDone(w, r, "/admin/groups", "group-synced", group)
		return
	}
	before, err := s.appRoleOutsiders(r)
	if err != nil {
		s.adminError(w, r)
		return
	}
	if err := s.store.AddGroupInclude(r.Context(), group, included); err != nil {
		if errors.Is(err, store.ErrIncludeCycle) {
			s.redirectDone(w, r, "/admin/groups", "include-cycle", group)
			return
		}
		s.adminError(w, r)
		return
	}
	// An include must not bring an address the allow-list does not admit
	// into a group an application reads as one of its own roles, directly or
	// through groups that include this one. Sessions drop such groups for
	// those addresses anyway (withoutAppRolesForOutsider); refusing the
	// include keeps the groups pages truthful. A failure to check undoes the
	// include rather than keep one that could not be checked.
	after, err := s.appRoleOutsiders(r)
	if err != nil || gainedOutsider(before, after) {
		if rmErr := s.store.RemoveGroupInclude(r.Context(), group, included); rmErr != nil {
			log.Printf("undo include %s <- %s: %v", group, included, rmErr)
		}
		if err != nil {
			s.adminError(w, r)
			return
		}
		s.redirectDone(w, r, "/admin/groups", "include-refused", group)
		return
	}
	s.markGroupsChanged(s.now())
	s.auditAdmin(r, store.AdminActionGroupIncludeAdd, group, included)
	s.redirectDone(w, r, "/admin/groups", "include-added", group)
}

// appRoleOutsiders lists, for each hand-managed application-role group, the
// addresses it admits through includes that the allow-list does not admit.
func (s *Server) appRoleOutsiders(r *http.Request) (map[string]map[string]bool, error) {
	out := map[string]map[string]bool{}
	for g := range s.appRoleGroups() {
		if _, feed := s.feedFor(g); feed {
			continue
		}
		members, exists, err := s.store.GroupMembersResolved(r.Context(), g)
		if err != nil {
			return nil, err
		}
		if !exists {
			continue
		}
		for _, m := range members {
			if !s.policy.Allowed(m) {
				if out[g] == nil {
					out[g] = map[string]bool{}
				}
				out[g][m] = true
			}
		}
	}
	return out, nil
}

// gainedOutsider reports whether any group admits an outside address in
// after that it did not admit in before.
func gainedOutsider(before, after map[string]map[string]bool) bool {
	for g, set := range after {
		for m := range set {
			if !before[g][m] {
				return true
			}
		}
	}
	return false
}

func (s *Server) handleAdminRemoveInclude(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	group := normalizeGroupName(r.PathValue("name"))
	included := normalizeGroupName(r.PostFormValue("included"))
	if err := s.store.RemoveGroupInclude(r.Context(), group, included); err != nil {
		s.adminError(w, r)
		return
	}
	s.markGroupsChanged(s.now())
	s.auditAdmin(r, store.AdminActionGroupIncludeRemove, group, included)
	s.redirectDone(w, r, "/admin/groups", "include-removed", group)
}

// handleAdminKeepMembers stops the held change shown from being applied
// automatically (GROUP_FEED_AUTO_APPLY_AFTER). It changes no members.
func (s *Server) handleAdminKeepMembers(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	group := normalizeGroupName(r.PathValue("name"))
	if _, ok := s.feedFor(group); !ok {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	switch err := s.keepHeldChange(ctx, group, r.PostFormValue("hash")); {
	case errors.Is(err, errNothingHeld):
		s.redirectDone(w, r, "/admin/groups", "sync-nothing-held", group)
	case errors.Is(err, errChangeReplaced):
		s.redirectDone(w, r, "/admin/groups", "keep-replaced", group)
	case errors.Is(err, errAlreadyApplied):
		s.redirectDone(w, r, "/admin/groups", "keep-applied", group)
	case err != nil:
		s.adminError(w, r)
	default:
		s.auditAdmin(r, store.AdminActionGroupKeep, group, "the held change will not be applied automatically")
		s.redirectDone(w, r, "/admin/groups", "keep-ok", group)
	}
}

// handleAdminSyncGroup fetches a feed-filled group's feed now. accept=1
// applies a change that was held for being too large a shrink.
func (s *Server) handleAdminSyncGroup(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	group := normalizeGroupName(r.PathValue("name"))
	if _, ok := s.feedFor(group); !ok {
		http.NotFound(w, r)
		return
	}
	actor := "group feed"
	if id, ok := s.readSession(r, s.now()); ok {
		actor = id.Email
	}
	// Detached from the request: closing the tab must not fail the sync.
	ctx, cancel := context.WithTimeout(context.Background(), feedFetchTimeout+10*time.Second)
	defer cancel()
	acceptHash := ""
	if r.PostFormValue("accept") == "1" {
		// The hash of the held change the admin was shown; a different (newer)
		// held change is not accepted on the strength of an old page.
		if acceptHash = r.PostFormValue("hash"); acceptHash == "" {
			s.redirectDone(w, r, "/admin/groups", "sync-nothing-held", group)
			return
		}
	}
	st, err := s.syncFeed(ctx, group, actor, acceptHash)
	switch {
	case errors.Is(err, errNothingHeld):
		s.redirectDone(w, r, "/admin/groups", "sync-nothing-held", group)
	case errors.Is(err, errChangeReplaced):
		s.redirectDone(w, r, "/admin/groups", "sync-replaced", group)
	case errors.Is(err, errStateUnreadable):
		s.redirectDone(w, r, "/admin/groups", "sync-unreadable", group)
	case err != nil:
		s.adminError(w, r)
	case st.Status == store.GroupSyncOK:
		s.redirectDone(w, r, "/admin/groups", "sync-ok", group)
	case st.Status == store.GroupSyncHeld:
		s.redirectDone(w, r, "/admin/groups", "sync-held", group)
	default:
		s.redirectDone(w, r, "/admin/groups", "sync-failed", group)
	}
}

// plainAddress is validEmail restricted to printable ASCII with a dotted
// domain name: no look-alike Unicode, invisible characters, IP literals or
// bare hosts. Used where many addresses arrive at once (bulk add, feeds).
func plainAddress(e string) bool {
	if !validEmail(e) {
		return false
	}
	for i := 0; i < len(e); i++ {
		if e[i] < 0x21 || e[i] > 0x7e {
			return false
		}
	}
	at := strings.LastIndexByte(e, '@')
	domain := e[at+1:]
	return strings.Contains(domain, ".") && !strings.ContainsAny(domain, "[]:")
}
