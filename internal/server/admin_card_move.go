package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/uppertoe/vps-scaffold-auth/internal/roles"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// Moving a card that opens a group onto an app. Cards made before app roles
// name a group, and a site that has moved to a role guard admits a card only
// when the card names its app (roles.Held). Moving the card keeps its token,
// so the printed card keeps working without being printed and placed again.
//
// A move is offered only for an app whose snippet names card pages (a card
// page must lie under a user @path line). A moved card's scan carries no
// group, as a card made for the app does.
//
// Sessions already started from the card keep the group in their cookie
// until they end (at most the break-glass session TTL), and a role guard
// does not read the card's app for them (cardIssuedAsNow): they keep only
// the group's sites. Only a new scan opens the app.

// Wording of the move, drafted on 18 November 2026 for approval.
const (
	msgMoveAction  = "Move this card to an app"
	msgMoveHeading = "Move the card to an app"
	// %s is the card's group.
	msgMoveIntro = "This card stops opening a site of the group %s once that site moves to app roles. Moving the card to an app keeps its printed code, so nobody needs to print and place the card again."
	// %s is the card's location.
	msgMoveChoose = "Choose the app and the page that the card for %s will open."
	msgMoveKeeps  = "The card keeps its printed code, location, design and note."
	// %s is the card's group.
	msgMoveNext = "The next scan opens the chosen app as a user, and the card no longer opens the sites of the group %s."
	// %s is the break-glass session length, such as "8 hours".
	msgMoveSessions = "Sessions already started from the card keep the group's sites until they end, at most %s after the scan that started them."
	msgMoveButton   = "Move the card"
	// The card's location, then the app's label.
	msgCardMoveSubj = "The break-glass card for %s has been moved to %s."
)

// cardMoveView is the move panel on the page of a card that opens a group.
type cardMoveView struct {
	Action, Heading, Intro string
	Choose, Keeps, Next    string
	Sessions, Button       string
	ChooseFirst            string
	Apps                   []newCardApp
}

// cardMoveView lists every app in the manifest, as the new-card form does:
// an app with card pages can be chosen, and any other is shown with the
// reason it cannot be. app and page are the choices so far.
func (s *Server) cardMoveView(ctx context.Context, c store.BreakGlassCode, app, page string) *cardMoveView {
	ttl, _, _ := s.effectiveSettings(ctx)
	v := &cardMoveView{Action: msgMoveAction, Heading: msgMoveHeading,
		Intro:  fmt.Sprintf(msgMoveIntro, c.TargetGroup),
		Choose: fmt.Sprintf(msgMoveChoose, c.Label), Keeps: msgMoveKeeps,
		Next:     fmt.Sprintf(msgMoveNext, c.TargetGroup),
		Sessions: fmt.Sprintf(msgMoveSessions, renewWithin(ttl)),
		Button:   msgMoveButton, ChooseFirst: msgCardChooseAppFirst}
	for _, a := range s.appRoles.Sorted() {
		na := newCardApp{Name: a.Name, Label: a.Label, Token: tokenView{Icon: iconApp, Label: a.Label, Title: a.Label + ": User"},
			PagesHint: fmt.Sprintf(msgCardPagesHint, a.Label)}
		host := ""
		if len(a.Hosts) > 0 {
			host = a.Hosts[0]
		}
		if movable(a) {
			for i, p := range a.CardPages {
				na.Pages = append(na.Pages, newCardPage{Path: p.Path, Label: p.Label, URL: host + p.Path,
					Checked: (a.Name == app && p.Path == page) || (i == 0 && !(a.Name == app && hasPage(a, page)))})
			}
			na.Checked = a.Name == app
		} else {
			na.Disabled = true
			na.Cards = msgCardNoPages
		}
		v.Apps = append(v.Apps, na)
	}
	return v
}

// movable reports whether a card can be moved to a: an app whose snippet
// names a page for a scan to open, on a host the manifest names.
func movable(a *roles.App) bool {
	return len(a.CardPages) > 0 && len(a.Hosts) > 0
}

// handleAdminBreakMove moves a card that opens a group onto an app's user
// role and one of the app's card pages, keeping its printed code. The move
// is audited and emailed to the other administrators. Sessions already
// started from the card are left to end on their own.
func (s *Server) handleAdminBreakMove(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	c, ok := s.codeFromPath(w, r)
	if !ok {
		return
	}
	back := "/admin/break/" + strconv.FormatInt(c.ID, 10)
	if !s.rolesOn() || c.App != "" || c.Status != store.BreakGlassActive {
		s.redirectDone(w, r, back, "card-move-refused", "")
		return
	}
	app := r.PostFormValue("app")
	page := r.PostFormValue("page." + app)
	refuse := func(msg string) {
		s.renderCardPage(w, r, http.StatusBadRequest, c, "move", app, page, msg)
	}
	a, ok := s.appRoles.Apps[app]
	if !ok || !s.appRoles.Has(app, roles.UserRole) {
		refuse(msgCardNoApp)
		return
	}
	// A scan may open only a page the app's snippet offers to cards.
	if !movable(a) || !hasPage(a, page) {
		refuse(msgCardNoPage)
		return
	}
	redirect := "https://" + a.Hosts[0] + page
	if err := s.store.MoveBreakGlassCard(r.Context(), c.ID, app, redirect); err != nil {
		if errors.Is(err, store.ErrCardNotGroup) {
			s.redirectDone(w, r, back, "card-move-refused", "")
			return
		}
		s.adminError(w, r)
		return
	}
	s.forgetRoles()
	s.auditAdmin(r, store.AdminActionBreakMove, c.Label, "group="+c.TargetGroup+" app="+app+" page="+page)
	s.emailOtherAdmins(s.adminActor(r), fmt.Sprintf(msgCardMoveSubj, c.Label, a.Label),
		[]string{c.Label + " · opens " + a.Label + " · " + a.Hosts[0] + page + " · no longer opens the group " + c.TargetGroup})
	s.redirectDone(w, r, back, "card-moved", "")
}
