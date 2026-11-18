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

// The App feeds page lists every app and group pair the gateway knows of
// from MEMBER_READERS_FILE and MEMBER_READERS: one row per pair, waiting
// feeds first, with Start the feed and Stop the feed confirmed in place
// (?confirm=approve|withdraw&app=&group=). The approval itself, and its
// checks, are in member_reader_approvals.go; this file only presents them.

const appFeedsPath = "/admin/app-feeds"

// feedsReadsSince is how far back the page counts reads.
const feedsReadsSince = 30 * 24 * time.Hour

// The strings the App feeds page, its menu item, the Overview line and the
// Access log's link show. Change them only with the owner's agreement.
const (
	msgFeedsMenu         = "App feeds"
	msgFeedsTitle        = "Feeds to apps"
	msgFeedsLead         = "An app feed sends the people in one group to one app. An app receives a feed only once an administrator has started it."
	msgFeedsAskedOne     = " has asked for a feed of one group."
	msgFeedsAskedMany    = " has asked for feeds of %s groups."
	msgFeedsWaitingMany  = "%s feeds"
	msgFeedsWaitingAre   = " are waiting to start."
	msgFeedsNoneWaiting  = "No app is waiting for a feed to start."
	msgFeedStateWaiting  = "Waiting to start"
	msgFeedStateFeeding  = "Feeding"
	msgFeedStateNoGroup  = "Group does not exist yet"
	msgFeedStateUnusable = "Not usable"
	msgFeedStateEnv      = "Started in the gateway's settings"
	msgFeedEnvTitle      = "This feed is set in the gateway's settings, so it needs no approval here."
	msgFeedsNone         = "No app has asked for a feed."
	msgFeedStopAsk       = "Once the feed stops, %s no longer receives the people in %s."
	msgFeedStartButton   = "Start the feed"
	msgFeedStopButton    = "Stop the feed"
	msgFeedCancel        = "Cancel"
	msgFeedsColumnFeed   = "Feed"
	msgFeedsReadsHead    = "Feeds sent in the last 30 days"
	msgFeedTokenSetting  = "The app's token belongs in"
	msgAccessFeedsBefore = "Feeds of group members to apps are listed on the "
	msgAccessFeedsAfter  = " page."
	// msgDomainGroupRead is the problem shown for a feed of a domain group.
	msgDomainGroupRead = "This is a domain group, which has no member list to read."
)

// readersView is the App feeds page.
type readersView struct {
	Lead, Empty, Cancel, Column string
	Rows                        []readerRow
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

// waitingReaders lists the app of each pair an administrator can start
// now.
func (s *Server) waitingReaders(ctx context.Context) []string {
	if !s.readersOn() {
		return nil
	}
	views, err := s.readerApprovalViews(ctx)
	if err != nil {
		return nil
	}
	var apps []string
	for _, v := range views {
		if readerWaiting(v) {
			apps = append(apps, v.App)
		}
	}
	return apps
}

// readerWaiting reports whether a pair can be approved now: not approved, and
// its group exists with a member list to read.
func readerWaiting(v readerApprovalView) bool {
	return !v.Approved && !v.Missing && v.Kind != store.GroupKindDomain
}

// feedsWaitingLine is the Overview's line, the menu's tooltip and the page's
// strip for the waiting feeds, given the app of each.
func feedsWaitingLine(apps []string) attentionLine {
	l := attentionLine{Link: appFeedsPath}
	switch {
	case len(slices.Compact(slices.Sorted(slices.Values(apps)))) > 1:
		l.Name, l.After = fmt.Sprintf(msgFeedsWaitingMany, capFirst(numberWord(len(apps)))), msgFeedsWaitingAre
	case len(apps) == 1:
		l.Name, l.After = apps[0], msgFeedsAskedOne
	default:
		l.Name, l.After = apps[0], fmt.Sprintf(msgFeedsAskedMany, numberWord(len(apps)))
	}
	return l
}

// handleAdminReaders shows the App feeds page. A GET never changes
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
	v := &readersView{Lead: msgFeedsLead, Empty: msgFeedsNone, Column: msgFeedsColumnFeed, Cancel: msgFeedCancel, Rows: rows, Unusable: unusable, ReadsHead: msgFeedsReadsHead}
	var waiting []string
	for _, row := range rows {
		if row.Action == "approve" {
			waiting = append(waiting, row.App)
		}
	}
	if len(waiting) > 0 {
		l := feedsWaitingLine(waiting)
		v.Strip, v.StripTone = l.Name+l.After, "waiting"
	} else {
		v.Strip, v.StripTone = msgFeedsNoneWaiting, "none"
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
					// The group is named as its token names it.
					if kind == "approve" {
						v.Strip = fmt.Sprintf(msgReaderConfirm, app, row.Group.Label)
					} else {
						v.Strip = fmt.Sprintf(msgFeedStopAsk, app, row.Group.Label)
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

	reads, err := s.store.SummariseMemberReads(ctx, s.now().Add(-feedsReadsSince))
	if err != nil {
		s.adminError(w, r)
		return
	}
	for _, m := range reads {
		v.Reads = append(v.Reads, memberReadView{App: m.App, Group: m.Group, Source: m.Source, Last: s.stampMin(m.Last), Reads: m.Reads})
	}
	s.renderAdmin(w, r, http.StatusOK, "admin_app_feeds", adminData{Title: msgFeedsTitle, Readers: v, NoticeInPage: true, Notice: notice, Warning: warning})
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
		return readerRow{App: app, Group: t, State: tokenView{Icon: "k-alert", Tone: "card", Label: msgFeedStateUnusable, Title: problem}, Note: problem, rank: 2}, err
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
			row.State = tokenView{Icon: "k-none", Tone: "card", Label: msgFeedStateNoGroup, Title: msgReaderNoGroup}
		case v.Approved:
			row.Group, err = groupToken(v.Group)
			row.App, row.rank, row.Note = v.App, 1, v.Status
			row.State = tokenView{Icon: "k-check", Label: msgFeedStateFeeding, Title: v.Status}
		default:
			row.Group, err = groupToken(v.Group)
			row.App, row.rank = v.App, 0
			row.State = tokenView{Icon: "k-clock", Tone: "wide", Label: msgFeedStateWaiting}
			row.Action, row.ActionText = "approve", msgFeedStartButton
		}
		if err != nil {
			return nil, false, err
		}
		// An approval can always be withdrawn, whatever has become of its
		// group since.
		if v.Approved {
			row.Action, row.ActionText = "withdraw", msgFeedStopButton
		}
		rows = append(rows, row)
	}
	for _, u := range s.cfg.UnusableMemberReaders {
		for _, g := range u.Groups {
			row, err := notUsable(u.App, g, u.Problem)
			if err != nil {
				return nil, false, err
			}
			row.Setting, row.SettingText = u.TokenEnv, msgFeedTokenSetting
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
			row := readerRow{App: m.app, Group: t, rank: 1, State: tokenView{Icon: "k-lock", Label: msgFeedStateEnv, Title: msgFeedEnvTitle}}
			if _, ok := byName[g]; !ok {
				row.rank, row.State = 2, tokenView{Icon: "k-none", Tone: "card", Label: msgFeedStateNoGroup, Title: msgReaderNoGroup}
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
			rows[i].AskHref = appFeedsPath + q
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
