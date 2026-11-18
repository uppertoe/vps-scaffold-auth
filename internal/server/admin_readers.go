package server

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// The member readers page lists every app and group pair the gateway knows
// of from MEMBER_READERS_FILE and MEMBER_READERS: one row per pair, waiting
// approvals first, with Approve and Withdraw approval confirmed in place
// (?confirm=approve|withdraw&app=&group=). The approval itself, and its
// checks, are in member_reader_approvals.go; this file only presents them.

const readersPath = "/admin/readers"

// readersReadsSince is how far back the page counts reads.
const readersReadsSince = 30 * 24 * time.Hour

// The strings the member readers page, its menu item, the Overview line and
// the Access log's link show. Change them only with the owner's agreement.
const (
	msgReadersMenu          = "Member readers"
	msgReadersTitle         = "Apps that read group members"
	msgReadersLead          = "An app in the readers file can read a group's members only once an administrator has approved that app and group."
	msgReadersWaitingOne    = "One request to read group members"
	msgReadersWaitingMany   = "%s requests to read group members"
	msgReadersWaitingIs     = " is waiting for an administrator's approval."
	msgReadersWaitingAre    = " are waiting for an administrator's approval."
	msgReadersNoneWaiting   = "No requests to read group members are waiting for approval."
	msgReaderStateWaiting   = "Waiting for approval"
	msgReaderStateApproved  = "Approved"
	msgReaderStateNoGroup   = "Group does not exist yet"
	msgReaderStateUnusable  = "Not usable"
	msgReaderStateEnv       = "Listed in MEMBER_READERS"
	msgReaderEnvTitle       = "MEMBER_READERS is reviewed with the gateway's configuration, so this app needs no approval."
	msgReadersNone          = "No app is listed to read group members."
	msgReaderWithdrawAsk    = "Withdrawing the approval stops %s from reading the members of %s."
	msgReaderApproveButton  = "Approve"
	msgReaderWithdrawButton = "Withdraw approval"
	msgReaderCancel         = "Cancel"
	msgReadersReadsHead     = "Reads in the last 30 days"
	msgReaderTokenSetting   = "The app's token belongs in"
	msgAccessReadersBefore  = "Apps that read group members are listed on the "
	msgAccessReadersAfter   = " page."
	// msgDomainGroupRead is the problem shown for a reader listed for a
	// domain group.
	msgDomainGroupRead = "This is a domain group, which has no member list to read."
)

// readersView is the member readers page.
type readersView struct {
	Lead, Empty, Cancel string
	Rows                []readerRow
	// Strip is the line above the list, the same height whatever it says:
	// the result of the last action, the confirmation being asked for, or
	// how many approvals are waiting. Tone is "ok", "warn", "ask", "waiting"
	// or "none".
	Strip, StripTone string
	// Unusable shows the remedies for rows that are not usable.
	Unusable  bool
	ReadsHead string
	Reads     []memberReadView
}

// readerRow is one app and group pair. Action is "approve", "withdraw" or
// empty; Confirming swaps the action cell for the confirming form.
type readerRow struct {
	App   string
	Group tokenView
	State tokenView
	Note  string
	// Setting is the environment variable an unusable app's token belongs
	// in, introduced by SettingText.
	Setting, SettingText string
	Action               string
	ActionText           string
	AskHref              string
	Confirming           bool
	// rank orders the rows: waiting first, then approved, then the rest.
	rank int
}

// memberReadView is one app's reads of one group over the period.
type memberReadView struct {
	App, Group, Source, Last string
	Reads                    int
}

// readersOn reports whether any app may read group members, which shows the
// page and its menu item.
func (s *Server) readersOn() bool {
	return s.cfg.MembersReadersSet || len(s.members.readers) > 0 || len(s.cfg.UnusableMemberReaders) > 0
}

// waitingReaders counts the pairs an administrator can approve now.
func (s *Server) waitingReaders(ctx context.Context) int {
	if !s.readersOn() {
		return 0
	}
	views, err := s.readerApprovalViews(ctx)
	if err != nil {
		return 0
	}
	n := 0
	for _, v := range views {
		if readerWaiting(v) {
			n++
		}
	}
	return n
}

// readerWaiting reports whether a pair can be approved now: not approved, and
// its group exists with a member list to read.
func readerWaiting(v readerApprovalView) bool {
	return !v.Approved && !v.Missing && v.Kind != store.GroupKindDomain
}

// readersWaitingLine is the Overview's line, and the page's strip, for n
// waiting approvals.
func readersWaitingLine(n int) attentionLine {
	if n == 1 {
		return attentionLine{Link: readersPath, Name: msgReadersWaitingOne, After: msgReadersWaitingIs}
	}
	return attentionLine{Link: readersPath, Name: fmt.Sprintf(msgReadersWaitingMany, capFirst(numberWord(n))), After: msgReadersWaitingAre}
}

// handleAdminReaders shows the member readers page. A GET never changes
// anything: ?confirm= only draws the confirming form.
func (s *Server) handleAdminReaders(w http.ResponseWriter, r *http.Request) {
	if !s.readersOn() {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	rows, unusable, err := s.readerRows(ctx)
	if err != nil {
		s.adminError(w, r)
		return
	}
	v := &readersView{Lead: msgReadersLead, Empty: msgReadersNone, Cancel: msgReaderCancel, Rows: rows, Unusable: unusable, ReadsHead: msgReadersReadsHead}
	waiting := 0
	for _, row := range rows {
		if row.Action == "approve" {
			waiting++
		}
	}
	if waiting > 0 {
		l := readersWaitingLine(waiting)
		v.Strip, v.StripTone = l.Name+l.After, "waiting"
	} else {
		v.Strip, v.StripTone = msgReadersNoneWaiting, "none"
	}

	q := r.URL.Query()
	if kind := q.Get("confirm"); kind == "approve" || kind == "withdraw" {
		app, group := normalizeGroupName(q.Get("app")), normalizeGroupName(q.Get("group"))
		if authz.ValidGroupName(app) && authz.ValidGroupName(group) {
			for i := range v.Rows {
				row := &v.Rows[i]
				if row.App == app && row.Group.Value == group && row.Action == kind {
					row.Confirming = true
					v.StripTone = "ask"
					if kind == "approve" {
						v.Strip = fmt.Sprintf(msgReaderConfirm, app, group)
					} else {
						v.Strip = fmt.Sprintf(msgReaderWithdrawAsk, app, group)
					}
				}
			}
		}
	}

	// The result of the last action shows in the strip, in place of the
	// notice above the page, so that nothing below it moves.
	notice, warning := s.takeNotice(w, r)
	if notice != "" {
		v.Strip, v.StripTone = notice, "ok"
	} else if warning != "" {
		v.Strip, v.StripTone = warning, "warn"
	}

	reads, err := s.store.SummariseMemberReads(ctx, s.now().Add(-readersReadsSince))
	if err != nil {
		s.adminError(w, r)
		return
	}
	for _, m := range reads {
		v.Reads = append(v.Reads, memberReadView{App: m.App, Group: m.Group, Source: m.Source, Last: s.stampMin(m.Last), Reads: m.Reads})
	}
	s.renderAdmin(w, r, http.StatusOK, "admin_readers", adminData{Title: msgReadersTitle, Readers: v, NoticeInPage: true, Notice: notice, Warning: warning})
}

// readerRows builds one row per pair: the readers file's pairs with their
// approvals, the pairs of apps without a usable token, and the domain groups
// an app is listed for. unusable reports whether any row is not usable.
func (s *Server) readerRows(ctx context.Context) (rows []readerRow, unusable bool, err error) {
	groups, err := s.store.ListGroups(ctx)
	if err != nil {
		return nil, false, err
	}
	byName := map[string]store.Group{}
	for _, g := range groups {
		byName[g.Name] = g
	}
	counts := map[string]int{}
	groupToken := func(name string) (tokenView, error) {
		g, ok := byName[name]
		if !ok {
			return tokenView{Icon: "k-none", Tone: "gone", Label: name, Title: msgReaderNoGroup, Value: name}, nil
		}
		label := g.Name
		if g.Label != "" {
			label = g.Label
		}
		t := tokenView{Icon: iconDomain, Label: label, Title: label, Href: "/admin/groups/" + g.Name, Value: g.Name}
		if g.Kind != store.GroupKindDomain {
			if _, seen := counts[name]; !seen {
				members, err := s.store.ListGroupMembers(ctx, name)
				if err != nil {
					return t, err
				}
				counts[name] = len(members)
			}
			t.Icon, t.Count = iconList, fmt.Sprint(counts[name])
		}
		return t, nil
	}
	notUsable := func(app, group, problem string) (readerRow, error) {
		t, err := groupToken(group)
		return readerRow{App: app, Group: t, State: tokenView{Icon: "k-alert", Tone: "card", Label: msgReaderStateUnusable, Title: problem}, Note: problem, rank: 2}, err
	}

	views, err := s.readerApprovalViews(ctx)
	if err != nil {
		return nil, false, err
	}
	seen := map[string]bool{}
	for _, v := range views {
		seen[v.App+"\x00"+v.Group] = true
		var row readerRow
		switch {
		case v.Kind == store.GroupKindDomain:
			row, err = notUsable(v.App, v.Group, msgDomainGroupRead)
			unusable = true
		case v.Missing:
			row.Group, err = groupToken(v.Group)
			row.App, row.rank = v.App, 2
			row.State = tokenView{Icon: "k-none", Tone: "card", Label: msgReaderStateNoGroup, Title: msgReaderNoGroup}
		case v.Approved:
			row.Group, err = groupToken(v.Group)
			row.App, row.rank, row.Note = v.App, 1, v.Status
			row.State = tokenView{Icon: "k-check", Label: msgReaderStateApproved, Title: v.Status}
		default:
			row.Group, err = groupToken(v.Group)
			row.App, row.rank = v.App, 0
			row.State = tokenView{Icon: "k-clock", Tone: "wide", Label: msgReaderStateWaiting, Title: msgReaderWaiting}
			row.Action, row.ActionText = "approve", msgReaderApproveButton
		}
		if err != nil {
			return nil, false, err
		}
		// An approval can always be withdrawn, whatever has become of its
		// group since.
		if v.Approved {
			row.Action, row.ActionText = "withdraw", msgReaderWithdrawButton
		}
		rows = append(rows, row)
	}
	for _, u := range s.cfg.UnusableMemberReaders {
		for _, g := range u.Groups {
			row, err := notUsable(u.App, g, u.Problem)
			if err != nil {
				return nil, false, err
			}
			row.Setting, row.SettingText = u.TokenEnv, msgReaderTokenSetting
			rows, unusable = append(rows, row), true
		}
	}
	domainReads := s.domainGroupReads(ctx)
	// An app in MEMBER_READERS needs no approval; its pairs are listed so
	// that the page shows every app that reads group members.
	for _, m := range s.members.readers {
		if m.fromFile {
			continue
		}
		for _, g := range m.groups {
			if slices.Contains(domainReads[m.app], g) || seen[m.app+"\x00"+g] {
				continue
			}
			seen[m.app+"\x00"+g] = true
			t, err := groupToken(g)
			if err != nil {
				return nil, false, err
			}
			row := readerRow{App: m.app, Group: t, rank: 1, State: tokenView{Icon: "k-lock", Label: msgReaderStateEnv, Title: msgReaderEnvTitle}}
			if _, ok := byName[g]; !ok {
				row.rank, row.State = 2, tokenView{Icon: "k-none", Tone: "card", Label: msgReaderStateNoGroup, Title: msgReaderNoGroup}
			}
			rows = append(rows, row)
		}
	}
	for _, m := range s.members.readers {
		for _, g := range domainReads[m.app] {
			if seen[m.app+"\x00"+g] {
				continue
			}
			seen[m.app+"\x00"+g] = true
			row, err := notUsable(m.app, g, msgDomainGroupRead)
			if err != nil {
				return nil, false, err
			}
			rows, unusable = append(rows, row), true
		}
	}
	for i := range rows {
		if rows[i].Action != "" {
			q := "?confirm=" + rows[i].Action + "&app=" + rows[i].App + "&group=" + rows[i].Group.Value
			rows[i].AskHref = readersPath + q
		}
	}
	slices.SortStableFunc(rows, func(a, b readerRow) int {
		if a.rank != b.rank {
			return a.rank - b.rank
		}
		if c := strings.Compare(a.App, b.App); c != 0 {
			return c
		}
		return strings.Compare(a.Group.Value, b.Group.Value)
	})
	return rows, unusable, nil
}
