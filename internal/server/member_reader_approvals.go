package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// An app listed in MEMBER_READERS_FILE proposes the groups it reads; an
// administrator approves each (app, group) pair on the App feeds page
// (admin_app_feeds.go) before the gateway serves it. The file can narrow access on its own (a removed row is
// not served, whatever its approval, and its approval is cleared at the next
// start), but never widen it. An app in MEMBER_READERS is operator-reviewed
// configuration and needs no approval.

// The strings an approval shows and sends. Change them only with the owner's
// agreement.
const (
	msgReaderApprovedBy   = "Started by %s on %s."
	msgReaderApproved     = "The feed of %s to %s has started."
	msgReaderWithdrawn    = "The feed of %s to %s has stopped."
	msgReaderConfirm      = "Starting the feed sends %[1]s the email address of everyone in %[2]s, and keeps %[1]s up to date as the group changes."
	msgReaderSubject      = "Access to the members of %s has changed."
	msgReaderApproveLine  = "Approved %s to read the members of %s"
	msgReaderWithdrawLine = "Withdrew the approval for %s to read the members of %s"
	msgReaderNoGroup      = "This group does not exist yet."
	msgReaderClearSubject = "Approvals to read group members have been cleared."
	msgReaderClearLine    = "Cleared the approval for %s to read the members of %s, which the readers file no longer lists"
	msgReaderClearEnvLine = "Cleared the approval for %s to read the members of %s, because MEMBER_READERS now decides its groups"
	noticeReaderApproved  = "reader-approved"
	noticeReaderWithdrawn = "reader-withdrawn"
	noticeReaderCookieSep = ":"
)

// readerApprovalView is one pair from the readers file, for the App
// feeds page.
type readerApprovalView struct {
	App, Group string
	Approved   bool
	// Missing: the group does not exist, so it cannot be approved.
	Missing bool
	// Kind is the group's kind, when it exists.
	Kind   string
	Status string
}

// filePairs returns the (app, group) pairs the readers file lists, app ->
// groups.
func (s *Server) filePairs() map[string][]string {
	out := map[string][]string{}
	for _, r := range s.members.readers {
		if r.fromFile {
			out[r.app] = append(out[r.app], r.groups...)
		}
	}
	return out
}

// isFilePair reports whether the readers file lists app reading group.
func (s *Server) isFilePair(app, group string) bool {
	return slices.Contains(s.filePairs()[app], group)
}

// readersFileActor names the gateway in the admin log and the email when it
// clears an approval itself, as "group feed" names a feed's changes.
const (
	readersFileActor      = "gateway"
	readersFileEmailActor = "The gateway"
)

// clearStaleReaderApprovals deletes, at start-up, every approval whose pair a
// readers file that was read whole no longer lists, so a line that is removed
// and added again needs approval again. An app in MEMBER_READERS loses all
// its approvals, since MEMBER_READERS decides its groups. Nothing is cleared
// when the file could not be read, or for a pair the file still lists whose
// app's token is unusable for now: those approvals stay and are simply not
// served. Each clearing is recorded in the admin log, and the
// other administrators get one email listing them all.
func (s *Server) clearStaleReaderApprovals(ctx context.Context) {
	if !s.cfg.MemberReadersFileRead {
		return
	}
	approvals, err := s.store.ListMemberReaderApprovals(ctx)
	if err != nil {
		log.Printf("ERROR member readers: reading approvals: %v", err)
		return
	}
	var lines []string
	for _, a := range approvals {
		// An app in MEMBER_READERS loses its file approvals, so that a pair
		// approved long ago is never served again without a fresh approval
		// if the app moves back to the file.
		line := msgReaderClearLine
		if slices.Contains(s.cfg.MemberReadersEnvApps, a.App) {
			line = msgReaderClearEnvLine
		} else if slices.Contains(s.cfg.MemberReadersFilePairs[a.App], a.Group) {
			continue
		}
		removed, err := s.store.WithdrawMemberReader(ctx, a.App, a.Group)
		if err != nil {
			log.Printf("ERROR member readers: clearing the approval for %q to read %q: %v", a.App, a.Group, err)
			continue
		}
		if !removed {
			continue
		}
		log.Printf("member readers: %s", fmt.Sprintf(line, a.App, a.Group))
		if err := s.store.RecordAdminEvent(ctx, store.AdminEvent{
			Actor: readersFileActor, Action: store.AdminActionMemberReaderClear, Target: a.App, Detail: a.Group, CreatedAt: s.now(),
		}); err != nil {
			log.Printf("record admin event %s (%s reading %s): %v", store.AdminActionMemberReaderClear, a.App, a.Group, err)
		}
		lines = append(lines, fmt.Sprintf(line, a.App, a.Group))
	}
	if len(lines) > 0 {
		s.emailOtherAdmins(readersFileEmailActor, msgReaderClearSubject, lines)
	}
}

// readerApprovalViews lists every pair from the readers file, waiting or
// approved, for the App feeds page.
func (s *Server) readerApprovalViews(ctx context.Context) ([]readerApprovalView, error) {
	approvals, err := s.store.ListMemberReaderApprovals(ctx)
	if err != nil {
		return nil, err
	}
	byPair := map[string]store.MemberReaderApproval{}
	for _, a := range approvals {
		byPair[a.App+"\x00"+a.Group] = a
	}
	var out []readerApprovalView
	for _, r := range s.members.readers {
		if !r.fromFile {
			continue
		}
		for _, g := range r.groups {
			v := readerApprovalView{App: r.app, Group: g}
			if a, ok := byPair[r.app+"\x00"+g]; ok {
				v.Approved = true
				v.Status = fmt.Sprintf(msgReaderApprovedBy, a.ApprovedBy, s.longDate(a.ApprovedAt))
			}
			if kind, exists, err := s.store.GroupKind(ctx, g); err != nil {
				return nil, err
			} else if !exists {
				v.Missing, v.Status = true, msgReaderNoGroup
			} else {
				v.Kind = kind
			}
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b readerApprovalView) int {
		if c := strings.Compare(a.App, b.App); c != 0 {
			return c
		}
		return strings.Compare(a.Group, b.Group)
	})
	return out, nil
}

// readerPair reads and checks the app and group a form names: the pair must
// be one the readers file lists now.
func (s *Server) readerPair(r *http.Request) (app, group string, ok bool) {
	app = normalizeGroupName(r.PostFormValue("app"))
	group = normalizeGroupName(r.PostFormValue("group"))
	if !authz.ValidGroupName(app) || !authz.ValidGroupName(group) || !s.isFilePair(app, group) {
		return "", "", false
	}
	return app, group, true
}

// handleAdminApproveReader approves one pair from the readers file.
func (s *Server) handleAdminApproveReader(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	app, group, ok := s.readerPair(r)
	if !ok {
		http.Redirect(w, r, appFeedsPath, http.StatusFound)
		return
	}
	// An approval is for a group that exists, never for a name that a group
	// created later would take over.
	if _, exists, err := s.store.GroupKind(r.Context(), group); err != nil {
		s.adminError(w, r)
		return
	} else if !exists {
		http.Redirect(w, r, appFeedsPath, http.StatusFound)
		return
	}
	actor := s.adminActor(r)
	added, err := s.store.ApproveMemberReader(r.Context(), app, group, actor, s.now())
	if err != nil {
		s.adminError(w, r)
		return
	}
	if added {
		s.auditAdmin(r, store.AdminActionMemberReaderApprove, app, group)
		s.emailOtherAdmins(actor, fmt.Sprintf(msgReaderSubject, s.groupLabel(r.Context(), group)), []string{fmt.Sprintf(msgReaderApproveLine, app, group)})
	}
	s.redirectDone(w, r, appFeedsPath, noticeReaderApproved+noticeReaderCookieSep+app+noticeReaderCookieSep+group, "")
}

// handleAdminWithdrawReader withdraws the approval of one pair. Reads stop
// at once.
func (s *Server) handleAdminWithdrawReader(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	app, group, ok := s.readerPair(r)
	if !ok {
		http.Redirect(w, r, appFeedsPath, http.StatusFound)
		return
	}
	removed, err := s.store.WithdrawMemberReader(r.Context(), app, group)
	if err != nil {
		s.adminError(w, r)
		return
	}
	if removed {
		s.auditAdmin(r, store.AdminActionMemberReaderWithdraw, app, group)
		s.emailOtherAdmins(s.adminActor(r), fmt.Sprintf(msgReaderSubject, s.groupLabel(r.Context(), group)), []string{fmt.Sprintf(msgReaderWithdrawLine, app, group)})
	}
	s.redirectDone(w, r, appFeedsPath, noticeReaderWithdrawn+noticeReaderCookieSep+app+noticeReaderCookieSep+group, "")
}

// adminActor is the address of the administrator making the request, as
// requireAdmin admitted it. It is read from the request, not the session, so
// an administrator who has just ended their own sessions (replacing their
// authenticator, say) is still named.
func (s *Server) adminActor(r *http.Request) string {
	actor, _ := r.Context().Value(adminActorKey{}).(string)
	return actor
}

// groupLabel is a group's label, or its name when it has none.
func (s *Server) groupLabel(ctx context.Context, group string) string {
	if gs, err := s.store.ListGroups(ctx); err == nil {
		for _, g := range gs {
			if g.Name == group && g.Label != "" {
				return g.Label
			}
		}
	}
	return group
}

// readerNotice turns a reader notice code ("reader-approved:app:group") into
// its sentence, naming the group by label. The names are checked against the
// group-name grammar, so a notice can only ever show a well-formed app and
// group.
func readerNotice(code string, label func(group string) string) (string, bool) {
	parts := strings.Split(code, noticeReaderCookieSep)
	if len(parts) != 3 || !authz.ValidGroupName(parts[1]) || !authz.ValidGroupName(parts[2]) {
		return "", false
	}
	switch parts[0] {
	case noticeReaderApproved:
		return fmt.Sprintf(msgReaderApproved, label(parts[2]), capFirst(parts[1])), true
	case noticeReaderWithdrawn:
		return fmt.Sprintf(msgReaderWithdrawn, label(parts[2]), capFirst(parts[1])), true
	}
	return "", false
}
