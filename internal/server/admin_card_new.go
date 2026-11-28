// Making a new break-glass card: the form, the preview and creation.

package server

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
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
	// Without app roles, a card still opens a group (the form before app
	// roles).
	Targets  []targetOptionView
	Group    string
	Redirect string
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
	s.renderNewCard(w, r, http.StatusOK, q.Get("label"), q.Get("note"), q.Get("app"), q.Get("page."+q.Get("app")), q.Get("design"), q.Get("group"), q.Get("redirect"), "")
}

// renderNewCard draws the form with the values given; warning says what is
// missing after a refused create.
func (s *Server) renderNewCard(w http.ResponseWriter, r *http.Request, status int, label, note, app, page, design, group, redirect, warning string) {
	ctx := r.Context()
	v := &newCardView{Label: trimField(label), Note: trimField(note), App: app, RolesOn: s.rolesOn(), Group: group, Redirect: redirect,
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
	} else {
		groups, err := s.store.ListGroups(ctx)
		if err != nil {
			s.adminError(w, r)
			return
		}
		names := make([]string, 0, len(groups))
		for _, g := range groups {
			names = append(names, g.Name)
		}
		v.Targets = s.targetOptions(ctx, names)
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

// handleAdminBreakCreate makes a card. With app roles a card opens one of an
// app's card pages, as the app's user and nothing more; a form that names a
// group instead makes a card the way the gateway did before app roles.
func (s *Server) handleAdminBreakCreate(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	if r.PostFormValue("app") == "" && r.PostFormValue("preview") == "" && (r.PostFormValue("group") != "" || r.PostFormValue("group_new") != "") {
		s.createGroupCard(w, r)
		return
	}
	label := trimField(r.PostFormValue("label"))
	note := trimField(r.PostFormValue("note"))
	app := r.PostFormValue("app")
	page := r.PostFormValue("page." + app)
	design := r.PostFormValue("design")
	refuse := func(msg string) {
		s.renderNewCard(w, r, http.StatusBadRequest, label, note, app, page, design, "", "", msg)
	}
	// "Show the preview", without a script, shows the form again.
	if r.PostFormValue("preview") != "" {
		s.renderNewCard(w, r, http.StatusOK, label, note, app, page, design, r.PostFormValue("group"), r.PostFormValue("redirect"), "")
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

// createGroupCard makes a card that opens a group, as the gateway did before
// app roles. It is kept for a gateway without APP_ROLES_FILE.
func (s *Server) createGroupCard(w http.ResponseWriter, r *http.Request) {
	label := trimField(r.PostFormValue("label"))
	// The form offers the known groups in a list and takes a new name in a
	// second field; a typed name wins over the list.
	group := normalizeGroupName(r.PostFormValue("group_new"))
	if group == "" {
		group = normalizeGroupName(r.PostFormValue("group"))
	}
	if label == "" || group == "" {
		s.renderAdmin(w, r, http.StatusBadRequest, "admin_message", adminData{
			Title: "Missing fields", Message: "A label and a target group are both required.",
		})
		return
	}
	// The label becomes the session's principal, "breakglass:<label>", which
	// apps read as Remote-User and Remote-Email. An "@" could make an app that
	// takes the domain after the last "@" read the card as a department
	// address, a comma could split a header list, and a line break has no
	// place in a header.
	if !validCardLabel(label) {
		s.renderAdmin(w, r, http.StatusBadRequest, "admin_message", adminData{
			Title: "Invalid label", Message: "A label cannot contain \"@\", a comma or a line break.",
		})
		return
	}
	if authz.IsReservedGroup(group) {
		s.renderAdmin(w, r, http.StatusBadRequest, "admin_message", adminData{
			Title:   "Reserved target group",
			Message: "A break-glass code cannot target the reserved roles \"admin\", \"user\" or \"guest\". Use a dedicated group instead.",
		})
		return
	}
	if !authz.ValidGroupName(group) {
		s.renderAdmin(w, r, http.StatusBadRequest, "admin_message", adminData{
			Title:   "Invalid target group",
			Message: "A target group may use only lowercase letters, numbers, hyphens, and underscores — no spaces, commas, or other punctuation.",
		})
		return
	}
	if reason, refused := s.targetRefusal(r.Context(), group); refused {
		title, msg := "Staff-only list", "A break-glass code cannot target \""+group+"\", because it is a staff-only list, and a card would admit whoever carries it in that list's roles."
		switch reason {
		case refusedFeed:
			title, msg = "Group filled from a feed", "A break-glass code cannot target \""+group+"\", because its members come from a feed and a card would admit whoever carries it alongside them."
		case refusedIncluded:
			title, msg = "Group included in a staff-only list", "A break-glass code cannot target \""+group+"\", because a staff-only list includes it."
		case refusedUnreadable:
			title, msg = "Group not checked", "A break-glass code cannot target \""+group+"\" now, because every group is staff only while the gateway cannot read the app roles."
		}
		s.renderAdmin(w, r, http.StatusBadRequest, "admin_message", adminData{
			Title:   title,
			Message: msg + " Choose another group.",
		})
		return
	}
	tokenEnc, tokenHash, err := s.newToken()
	if err != nil {
		s.adminError(w, r)
		return
	}
	designID, _ := strconv.ParseInt(r.PostFormValue("design"), 10, 64)
	if designID > 0 {
		if _, found, err := s.store.GetCardDesign(r.Context(), designID); err != nil || !found {
			designID = 0
		}
	}
	rd := authz.SafeRedirect(trimField(r.PostFormValue("redirect")), s.cfg.Domain, "")
	id, err := s.store.CreateBreakGlassCode(r.Context(), store.BreakGlassCode{
		Label: label, Note: trimField(r.PostFormValue("note")), TargetGroup: group,
		TokenEnc: tokenEnc, TokenHash: tokenHash, Redirect: rd, DesignID: designID,
	})
	if err != nil {
		// Most likely a duplicate label (UNIQUE constraint).
		s.renderAdmin(w, r, http.StatusConflict, "admin_message", adminData{
			Title: "Could not create code", Message: "A code with that label already exists. Labels must be unique.",
		})
		return
	}
	s.auditAdmin(r, store.AdminActionBreakCreate, label, "group="+group)
	s.emailOtherAdmins(s.adminActor(r), fmt.Sprintf(msgCardCreatedSubj, group), []string{label + " · opens the group " + group})
	s.redirectDone(w, r, "/admin/break/"+strconv.FormatInt(id, 10), "card-created", "")
}
