// Making a new break-glass card: the form, the preview and creation.

package server

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/uppertoe/vps-scaffold-auth/internal/breakglass"
	"github.com/uppertoe/vps-scaffold-auth/internal/roles"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// --- The new-card form ---

// newCardView is the new-card form, with what has been chosen so far.
type newCardView struct {
	Label, Note string
	App         string // the chosen app's name
	Apps        []newCardApp
	Designs     []designChoice
	Design      int64
	PreviewURL  string
	Caption     string
	RolesOn     bool
	ChooseFirst string
}

type newCardApp struct {
	Name, Label string
	Token       tokenView
	Cards       string
	Reach       reachView
	Pages       []newCardPage
	PagesHint   string
	Disabled    bool
	Checked     bool
}

type newCardPage struct {
	Path, Label, URL string
	Checked          bool
}

type designChoice struct {
	ID       int64
	Name     string
	Size     string
	Caption  string
	Checked  bool
	ThumbURL string
}

func (s *Server) handleAdminBreakNew(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.renderNewCard(w, r, http.StatusOK, q.Get("label"), q.Get("note"), q.Get("app"), q.Get("page."+q.Get("app")), q.Get("design"), "")
}

// renderNewCard draws the form with the values given; warning says what is
// missing after a refused create.
func (s *Server) renderNewCard(w http.ResponseWriter, r *http.Request, status int, label, note, app, page, design, warning string) {
	ctx := r.Context()
	v := &newCardView{Label: trimField(label), Note: trimField(note), App: app, RolesOn: s.rolesOn(),
		ChooseFirst: msgCardChooseAppFirst}
	designs, err := s.store.ListCardDesigns(ctx)
	if err != nil {
		s.adminError(w, r)
		return
	}
	if len(designs) == 0 {
		designs = []store.CardDesign{defaultDesign()}
	}
	v.Design, _ = strconv.ParseInt(design, 10, 64)
	chosen := designs[0]
	for _, d := range designs {
		if d.ID == v.Design {
			chosen = d
		}
	}
	v.Design = chosen.ID
	appLabel := ""
	if v.RolesOn {
		world, err := s.loadRolesWorld(ctx)
		if err != nil {
			s.adminError(w, r)
			return
		}
		for _, a := range s.appRoles.Sorted() {
			na := newCardApp{Name: a.Name, Label: a.Label, Token: tokenView{Icon: iconApp, Label: a.Label, Title: a.Label + ": User"},
				PagesHint: fmt.Sprintf(msgCardPagesHint, a.Label)}
			n := len(world.cardsFor(a.Name, roles.UserRole))
			if n == 0 {
				na.Cards = "No cards yet"
			} else {
				na.Cards = capFirst(countWords(n, "card", "cards")) + " already"
			}
			na.Reach = s.roleRow(world, a, roles.UserRole, false, nil, nil).Reach
			host := ""
			if len(a.Hosts) > 0 {
				host = a.Hosts[0]
			}
			for i, p := range a.CardPages {
				na.Pages = append(na.Pages, newCardPage{Path: p.Path, Label: p.Label, URL: host + p.Path,
					Checked: (a.Name == app && p.Path == page) || (i == 0 && !(a.Name == app && hasPage(a, page)))})
			}
			if len(na.Pages) == 0 {
				na.Disabled = true
				na.Cards = msgCardNoPages
			}
			if a.Name == app && !na.Disabled {
				na.Checked = true
				appLabel = a.Label
			}
			v.Apps = append(v.Apps, na)
		}
	}
	for _, d := range designs {
		v.Designs = append(v.Designs, designChoice{ID: d.ID, Name: d.Name, Size: d.Size, Caption: d.Size + ", " + sizeText(d.Size),
			Checked: d.ID == chosen.ID, ThumbURL: previewURL(d.ID, v.Label, appLabel)})
	}
	v.PreviewURL = previewURL(chosen.ID, v.Label, appLabel)
	v.Caption = "Printed at " + chosen.Size + ": " + sizeText(chosen.Size)
	s.renderAdmin(w, r, status, "admin_card_new", adminData{Title: "New card", NewCard: v, Warning: warning, Script: cardFormScript})
}

func hasPage(a *roles.App, path string) bool {
	for _, p := range a.CardPages {
		if p.Path == path {
			return true
		}
	}
	return false
}

// previewURL is the address of a preview of a card in design id.
func previewURL(id int64, label, app string) string {
	q := url.Values{"design": {strconv.FormatInt(id, 10)}}
	if label != "" {
		q.Set("label", label)
	}
	if app != "" {
		q.Set("app", app)
	}
	return "/admin/break/preview.svg?" + q.Encode()
}

// handleAdminBreakPreview draws a card not yet made, for the new-card form:
// the design chosen, the location typed and the app's label.
func (s *Server) handleAdminBreakPreview(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	id, _ := strconv.ParseInt(q.Get("design"), 10, 64)
	d, err := s.cardDesign(r.Context(), id)
	if err != nil {
		s.adminError(w, r)
		return
	}
	label := clampLabel(trimField(q.Get("label")))
	if label == "" {
		label = sampleLocation
	}
	card := breakglass.Card{Design: s.drawDesign(r.Context(), d), Location: label, App: clampLabel(trimField(q.Get("app")))}
	writeSVG(w, card.SVG())
}

// handleAdminBreakCreate makes a card. A card opens one of an app's card
// pages, as the app's user and nothing more. A form that names a group is
// refused, since a card can no longer be made for a group.
func (s *Server) handleAdminBreakCreate(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	label := trimField(r.PostFormValue("label"))
	note := trimField(r.PostFormValue("note"))
	app := r.PostFormValue("app")
	page := r.PostFormValue("page." + app)
	design := r.PostFormValue("design")
	refuse := func(msg string) {
		s.renderNewCard(w, r, http.StatusBadRequest, label, note, app, page, design, msg)
	}
	// "Show the preview", without a script, shows the form again.
	if r.PostFormValue("preview") != "" {
		s.renderNewCard(w, r, http.StatusOK, label, note, app, page, design, "")
		return
	}
	if !s.rolesOn() {
		refuse(msgCardNoApp)
		return
	}
	if label == "" {
		refuse(msgCardNoLocation)
		return
	}
	if !validCardLabel(label) {
		refuse(msgCardBadLocation)
		return
	}
	a, ok := s.appRoles.Apps[app]
	if !ok || !s.appRoles.Has(app, roles.UserRole) {
		refuse(msgCardNoApp)
		return
	}
	// A scan may open only a page the app's snippet offers to cards.
	if !hasPage(a, page) || len(a.Hosts) == 0 {
		refuse(msgCardNoPage)
		return
	}
	designID, _ := strconv.ParseInt(design, 10, 64)
	if _, found, err := s.store.GetCardDesign(r.Context(), designID); err != nil {
		s.adminError(w, r)
		return
	} else if !found {
		refuse(msgCardNoDesign)
		return
	}
	tokenEnc, tokenHash, err := s.newToken()
	if err != nil {
		s.adminError(w, r)
		return
	}
	redirect := "https://" + a.Hosts[0] + page
	id, err := s.store.CreateBreakGlassCode(r.Context(), store.BreakGlassCode{
		Label: label, Note: note, App: app, Role: store.RoleUser, TokenEnc: tokenEnc, TokenHash: tokenHash,
		Redirect: redirect, DesignID: designID,
	})
	if err != nil {
		refuse(fmt.Sprintf(msgCardTaken, label))
		return
	}
	s.forgetRoles()
	s.auditAdmin(r, store.AdminActionBreakCreate, label, "app="+app+" page="+page)
	s.emailOtherAdmins(s.adminActor(r), fmt.Sprintf(msgCardCreatedSubj, a.Label), []string{label + " · opens " + a.Label + " · " + a.Hosts[0] + page})
	s.redirectDone(w, r, "/admin/break/"+strconv.FormatInt(id, 10), "card-created", "")
}
