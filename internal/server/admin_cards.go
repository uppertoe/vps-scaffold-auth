package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/breakglass"
	"github.com/uppertoe/vps-scaffold-auth/internal/roles"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// The break-glass cards pages: the list grouped by app, the new-card form,
// one card's page, and the card's drawings (PDF and SVG preview), which both
// come from breakglass.Card.Layout.

// Wording of the cards pages that the code builds. The prototype's wording is
// used where it has some; the rest was written in phase 2c and approved on
// 13 November 2026.
const (
	msgCardUntested    = "has never been tested. Scan it while you are signed in to confirm it works."
	msgCardBusy        = "has been used %s times in the last 30 days."
	msgCardNoLocation  = "Enter where the card will live, such as PICU bed 7."
	msgCardBadLocation = "A location cannot contain \"@\", a comma or a line break."
	msgCardTaken       = "A card for %s already exists. Choose another location, or replace that card."
	msgCardNoApp       = "Choose the app the card opens."
	msgCardNoPage      = "Choose one of the app's pages for the card to open."
	msgCardNoDesign    = "Choose a design for the card."
	msgCardCreatedSubj = "A break-glass card has been created for %s."
	msgCardReplaceSubj = "The break-glass card for %s has been replaced."
	msgCardWithdrawSub = "The break-glass card for %s has been withdrawn."
	msgCardNoPages     = "The app's snippet names no page a card may open."
	msgLegacyHeading   = "Cards that open a group"
	msgLegacyNote      = "These cards were made before app roles, and each one opens the sites of its group. They keep working until they are replaced or withdrawn."
)

// sampleLocation and sampleApp fill a preview before the form has them.
const sampleLocation = "Location"

// cardsView is the cards list.
type cardsView struct {
	Attention []cardAttention
	Apps      []cardAppGroup
	Legacy    []cardRow
	Empty     bool
	LegacyH   string
	LegacyN   string
}

type cardAttention struct {
	Bad      bool
	ID       int64
	Label    string
	Sentence string
}

type cardAppGroup struct {
	Name, Label, Host string
	Rows              []cardRow
}

type cardRow struct {
	ID       int64
	Label    string
	Note     string
	LastUsed string
	Uses     string
	Tested   string
	Active   bool
	Group    string // a legacy card's group
	Refused  string // why that group may no longer be a card's (see refusedTargets)
	Version  string // changes when the drawing does, so the thumbnail is fetched again
}

// cardStats are a card's uses, from its events.
type cardStats struct {
	last   time.Time
	uses30 int
}

func (s *Server) cardStats(ctx context.Context) (map[int64]cardStats, error) {
	events, err := s.store.ListBreakGlassEvents(ctx, 0, 5000, 0)
	if err != nil {
		return nil, err
	}
	since := s.now().Add(-30 * 24 * time.Hour)
	out := map[int64]cardStats{}
	for _, e := range events {
		if e.Outcome != store.OutcomeGranted {
			continue
		}
		st := out[e.CodeID]
		if e.CreatedAt.After(st.last) {
			st.last = e.CreatedAt
		}
		if e.CreatedAt.After(since) {
			st.uses30++
		}
		out[e.CodeID] = st
	}
	return out, nil
}

// shortStamp is "2 Nov, 3:07 am" in the display timezone.
func (s *Server) shortStamp(t time.Time) string {
	return t.In(s.tzloc()).Format("2 Jan, 3:04 pm")
}

func usesWord(n int) string {
	if n == 0 {
		return ""
	}
	return capFirst(countWords(n, "use", "uses"))
}

func (s *Server) handleAdminBreakList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	codes, err := s.store.ListBreakGlassCodes(ctx)
	if err != nil {
		s.adminError(w, r)
		return
	}
	stats, err := s.cardStats(ctx)
	if err != nil {
		s.adminError(w, r)
		return
	}
	v := &cardsView{Empty: len(codes) == 0, LegacyH: msgLegacyHeading, LegacyN: msgLegacyNote}
	groups := map[string]*cardAppGroup{}
	refused := s.refusedTargets()
	sort.SliceStable(codes, func(i, j int) bool {
		ai, aj := codes[i].Status == store.BreakGlassActive, codes[j].Status == store.BreakGlassActive
		if ai != aj {
			return ai
		}
		return strings.ToLower(codes[i].Label) < strings.ToLower(codes[j].Label)
	})
	for _, c := range codes {
		st := stats[c.ID]
		row := cardRow{ID: c.ID, Label: c.Label, Note: c.Note, Active: c.Status == store.BreakGlassActive, Uses: usesWord(st.uses30),
			Version: strconv.FormatInt(c.UpdatedAt.Unix(), 10)}
		if !st.last.IsZero() {
			row.LastUsed = s.shortStamp(st.last)
		}
		if !c.TestedAt.IsZero() {
			row.Tested = s.longDate(c.TestedAt)
		}
		if row.Active && c.TestedAt.IsZero() {
			v.Attention = append(v.Attention, cardAttention{Bad: true, ID: c.ID, Label: c.Label, Sentence: msgCardUntested})
		}
		if row.Active && st.uses30 >= 3 {
			v.Attention = append(v.Attention, cardAttention{ID: c.ID, Label: c.Label, Sentence: fmt.Sprintf(msgCardBusy, numberWord(st.uses30))})
		}
		if c.App == "" {
			row.Group = c.TargetGroup
			row.Refused = refused[normalizeGroupName(c.TargetGroup)]
			v.Legacy = append(v.Legacy, row)
			continue
		}
		g, ok := groups[c.App]
		if !ok {
			g = &cardAppGroup{Name: c.App, Label: c.App}
			if a, ok := s.appRoles.Apps[c.App]; ok {
				g.Label = a.Label
				if len(a.Hosts) > 0 {
					g.Host = a.Hosts[0]
				}
			}
			groups[c.App] = g
		}
		g.Rows = append(g.Rows, row)
	}
	for _, g := range groups {
		v.Apps = append(v.Apps, *g)
	}
	sort.Slice(v.Apps, func(i, j int) bool { return strings.ToLower(v.Apps[i].Label) < strings.ToLower(v.Apps[j].Label) })
	s.renderAdmin(w, r, http.StatusOK, "admin_codes", adminData{Title: "Break-glass cards", Cards: v})
}

// --- Designs as cards draw them ---

// cardDesign returns the design a card uses: its own, or the first design
// when it has none (or its design has gone).
func (s *Server) cardDesign(ctx context.Context, id int64) (store.CardDesign, error) {
	if id > 0 {
		d, ok, err := s.store.GetCardDesign(ctx, id)
		if err != nil {
			return store.CardDesign{}, err
		}
		if ok {
			return d, nil
		}
	}
	ds, err := s.store.ListCardDesigns(ctx)
	if err != nil {
		return store.CardDesign{}, err
	}
	if len(ds) == 0 {
		return defaultDesign(), nil
	}
	return ds[0], nil
}

// defaultDesign is the Department preset with the default wording.
func defaultDesign() store.CardDesign {
	p := breakglass.DefaultPalette
	return store.CardDesign{Name: store.StandardDesignName, Header: p.Header, Accent: p.Accent, Stripe: true,
		Bar1: p.Bar1, Bar2: p.Bar2, Bar3: p.Bar3, LogoSource: store.DesignLogoSite, LogoMode: store.DesignLogoWhite,
		Title: store.DefaultDesignTitle, Steps: store.DefaultDesignSteps, Size: "A6"}
}

// drawDesign resolves a stored design into what the layout draws: the site
// logo or the design's own.
func (s *Server) drawDesign(ctx context.Context, d store.CardDesign) breakglass.Design {
	out := breakglass.Design{Header: d.Header, Accent: d.Accent, Stripe: d.Stripe, Bar1: d.Bar1, Bar2: d.Bar2, Bar3: d.Bar3,
		LogoMode: d.LogoMode, Title: d.Title, Steps: d.Steps, Size: d.Size}
	switch d.LogoSource {
	case store.DesignLogoOwn:
		out.Logo, out.LogoType = d.Logo, d.LogoType
	case store.DesignLogoSite:
		if logo, mime, _, err := s.siteLogo(ctx); err == nil && len(logo) > 0 {
			out.Logo, out.LogoType = logo, mime
		}
	}
	return out
}

// cardAppLabel is the name a card prints after "Opens": its app's label, or
// for a card that still opens a group, the host its scan opens.
func (s *Server) cardAppLabel(c store.BreakGlassCode) string {
	if c.App != "" {
		if a, ok := s.appRoles.Apps[c.App]; ok {
			return a.Label
		}
		return c.App
	}
	if u, err := url.Parse(c.Redirect); err == nil && u.Host != "" {
		return u.Host
	}
	return ""
}

// sizeText is "105 × 148 mm".
func sizeText(size string) string {
	wh, ok := breakglass.Sizes[size]
	if !ok {
		return ""
	}
	return fmt.Sprintf("%g × %g mm", wh[0], wh[1])
}

// sizeWords is how the design editor describes each printed size.
var sizeWords = map[string]string{
	"A6": "Postcard, 105 × 148 mm",
	"A5": "Half a sheet, 148 × 210 mm",
	"A4": "A full sheet, 210 × 297 mm",
}

// writeSVG serves a card drawing. The drawing embeds its images as data:
// addresses and holds no script, so its policy allows those images only.
func writeSVG(w http.ResponseWriter, svg []byte) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; img-src data:; sandbox")
	w.Header().Set("Content-Disposition", "inline")
	w.Write(svg)
}

// handleAdminBreakFile serves a card's drawings: its PDF, its QR code and
// its SVG preview. One pattern serves all three, because a pattern per file
// would conflict with the design pages' /admin/break/designs/{id}.
func (s *Server) handleAdminBreakFile(w http.ResponseWriter, r *http.Request) {
	switch r.PathValue("file") {
	case "pdf":
		s.handleAdminBreakPDF(w, r)
	case "qr.png":
		s.handleAdminBreakQR(w, r)
	case "card.svg":
		s.handleAdminBreakSVG(w, r)
	default:
		http.NotFound(w, r)
	}
}

// cardDrawing builds a card's drawing; withCode puts its live code in the QR.
func (s *Server) cardDrawing(ctx context.Context, c store.BreakGlassCode, withCode bool) (breakglass.Card, error) {
	d, err := s.cardDesign(ctx, c.DesignID)
	if err != nil {
		return breakglass.Card{}, err
	}
	card := breakglass.Card{Design: s.drawDesign(ctx, d), Location: c.Label, App: s.cardAppLabel(c)}
	if withCode && c.Status == store.BreakGlassActive {
		token, err := s.secrets.Open(c.TokenEnc)
		if err != nil {
			return breakglass.Card{}, err
		}
		card.QR = s.breakURL(token)
	}
	return card, nil
}

func (s *Server) handleAdminBreakSVG(w http.ResponseWriter, r *http.Request) {
	c, ok := s.codeFromPath(w, r)
	if !ok {
		return
	}
	card, err := s.cardDrawing(r.Context(), c, r.URL.Query().Get("thumb") == "")
	if err != nil {
		s.adminError(w, r)
		return
	}
	writeSVG(w, card.SVG())
}

func (s *Server) handleAdminBreakPDF(w http.ResponseWriter, r *http.Request) {
	c, ok := s.codeFromPath(w, r)
	if !ok {
		return
	}
	// A withdrawn card's code is not printed again.
	if c.Status != store.BreakGlassActive {
		http.NotFound(w, r)
		return
	}
	card, err := s.cardDrawing(r.Context(), c, true)
	if err != nil {
		s.adminError(w, r)
		return
	}
	pdf, err := card.PDF()
	if err != nil {
		s.adminError(w, r)
		return
	}
	if err := s.store.MarkCardPDF(r.Context(), c.ID, s.now()); err != nil {
		log.Printf("record the PDF download of card %d: %v", c.ID, err)
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="`+pdfFilename(c.Label)+`"`)
	w.Write(pdf)
}

func (s *Server) handleAdminBreakQR(w http.ResponseWriter, r *http.Request) {
	png, _, ok := s.codeImage(w, r)
	if !ok {
		return
	}
	writeImage(w, "image/png", png)
}

// codeFromPath loads the card the path names, or answers 404.
func (s *Server) codeFromPath(w http.ResponseWriter, r *http.Request) (store.BreakGlassCode, bool) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return store.BreakGlassCode{}, false
	}
	c, found, err := s.store.GetBreakGlassCode(r.Context(), id)
	if err != nil {
		s.adminError(w, r)
		return store.BreakGlassCode{}, false
	}
	if !found {
		http.NotFound(w, r)
		return store.BreakGlassCode{}, false
	}
	return c, true
}

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
	v := &newCardView{Label: trimField(label), Note: trimField(note), App: app, RolesOn: s.rolesOn(), Group: group, Redirect: redirect}
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
			na := newCardApp{Name: a.Name, Label: a.Label, Token: tokenView{Icon: iconApp, Label: a.Label, Title: a.Label + ": User"}}
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
		v.Targets = s.targetOptions(names)
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
	s.emailOtherAdmins(s.actor(r), fmt.Sprintf(msgCardCreatedSubj, a.Label), []string{label + " · opens " + a.Label + " · " + a.Hosts[0] + page})
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
	if reason, refused := s.targetRefusal(group); refused {
		msg := "A break-glass code cannot target \"" + group + "\", because an application reads that group as one of its own roles and a card would admit its holder in that role."
		if reason == refusedFeed {
			msg = "A break-glass code cannot target \"" + group + "\", because its members come from a feed and a card would admit its holder alongside them."
		}
		s.renderAdmin(w, r, http.StatusBadRequest, "admin_message", adminData{
			Title:   "Group " + reason,
			Message: msg + " Choose a group that an app's sign-in rule names only to grant entry.",
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
	s.emailOtherAdmins(s.actor(r), fmt.Sprintf(msgCardCreatedSubj, group), []string{label + " · opens the group " + group})
	s.redirectDone(w, r, "/admin/break/"+strconv.FormatInt(id, 10), "card-created", "")
}

// --- One card's page ---

type cardPageView struct {
	ID          int64
	Label       string
	AppLabel    string
	Active      bool
	Steps       []cardStep
	Withdrawn   string
	PreviewURL  string
	Caption     string
	Designs     []designChoice
	DesignID    int64
	DesignName  string
	AppToken    tokenView
	Group       string // a card that opens a group
	PageLabel   string
	PageURL     string
	Note        string
	UsesLine    string
	Events      []cardEventView
	Confirm     string // "replace" or "withdraw" while asking
	ConfirmText string
	ReplaceText string
	WithdrawTxt string
}

type cardStep struct {
	Done          bool
	Title, Detail string
}

type cardEventView struct {
	When, Outcome, Tone, Device, Address string
}

// Wording of the card page's actions, from the prototype.
const (
	msgReplaceBody  = "The printed card stops working at once, and the sessions its scans started end. A new PDF is then ready to print."
	msgWithdrawBody = "Every later scan is refused, and the sessions its scans started end now. The card's activity is kept."
)

// cardOutcomes names each recorded outcome on a card's page, with its tone.
var cardOutcomes = map[string][2]string{
	store.OutcomeGranted:       {"Access given", "ok"},
	store.OutcomeViewed:        {"Opened, not used", "tag"},
	store.OutcomeTested:        {"Tested by an administrator", "test"},
	store.OutcomeRevoked:       {"Refused: withdrawn", "off"},
	store.OutcomeReplaced:      {"Refused: replaced", "off"},
	store.OutcomeRedirected:    {"Opened with their own sign-in", "tag"},
	store.OutcomeRefusedTarget: {"Refused: the group is now an app role", "off"},
}

// browserOf names the browser from a user agent, or "".
func browserOf(ua string) string {
	switch {
	case strings.Contains(ua, "Edg/"):
		return "Edge"
	case strings.Contains(ua, "Firefox/"), strings.Contains(ua, "FxiOS/"):
		return "Firefox"
	case strings.Contains(ua, "Chrome/"), strings.Contains(ua, "CriOS/"):
		return "Chrome"
	case strings.Contains(ua, "Safari/"):
		return "Safari"
	}
	return ""
}

func deviceAndBrowser(ua string) string {
	var parts []string
	for _, p := range []string{deviceOf(ua), browserOf(ua)} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return "Unknown device"
	}
	return strings.Join(parts, ", ")
}

func (s *Server) handleAdminBreakDetail(w http.ResponseWriter, r *http.Request) {
	c, ok := s.codeFromPath(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	events, err := s.store.ListBreakGlassEvents(ctx, c.ID, 100, 0)
	if err != nil {
		s.adminError(w, r)
		return
	}
	designs, err := s.store.ListCardDesigns(ctx)
	if err != nil {
		s.adminError(w, r)
		return
	}
	d, err := s.cardDesign(ctx, c.DesignID)
	if err != nil {
		s.adminError(w, r)
		return
	}
	v := &cardPageView{ID: c.ID, Label: c.Label, AppLabel: s.cardAppLabel(c), Active: c.Status == store.BreakGlassActive,
		DesignID: d.ID, DesignName: d.Name, Note: c.Note,
		PreviewURL:  "/admin/break/" + strconv.FormatInt(c.ID, 10) + "/card.svg?v=" + strconv.FormatInt(c.UpdatedAt.Unix(), 10),
		Caption:     d.Size + ", " + sizeText(d.Size) + " · " + d.Name,
		ReplaceText: msgReplaceBody, WithdrawTxt: msgWithdrawBody}
	for _, x := range designs {
		v.Designs = append(v.Designs, designChoice{ID: x.ID, Name: x.Name, Checked: x.ID == d.ID})
	}
	created := cardStep{Done: true, Title: "Created", Detail: s.longDate(c.CreatedAt)}
	pdf := cardStep{Title: "PDF downloaded", Detail: "Download the PDF, then print and place the card."}
	if !c.PDFAt.IsZero() {
		pdf.Done, pdf.Detail = true, s.longDate(c.PDFAt)
	}
	tested := cardStep{Title: "Tested", Detail: "Scan the card while you are signed in. The test grants nothing."}
	if !c.TestedAt.IsZero() {
		tested.Done, tested.Detail = true, s.longDate(c.TestedAt)
	}
	v.Steps = []cardStep{created, pdf, tested}
	if !v.Active {
		v.Withdrawn = s.longDate(c.UpdatedAt) + ". Every later scan is refused."
	}
	if c.App != "" {
		v.AppToken = tokenView{Icon: iconApp, Label: v.AppLabel, Title: v.AppLabel + ": User"}
	} else {
		v.Group = c.TargetGroup
	}
	v.PageURL = strings.TrimPrefix(strings.TrimPrefix(c.Redirect, "https://"), "http://")
	v.PageLabel = v.PageURL
	if a, ok := s.appRoles.Apps[c.App]; ok {
		if u, err := url.Parse(c.Redirect); err == nil {
			for _, p := range a.CardPages {
				if p.Path == u.Path || (p.Path == "/" && u.Path == "") {
					v.PageLabel = p.Label
				}
			}
		}
	}
	if v.PageURL == "" {
		v.PageLabel = "The gateway's default page"
	}
	since := s.now().Add(-30 * 24 * time.Hour)
	uses := 0
	for _, e := range events {
		if e.Outcome == store.OutcomeGranted && e.CreatedAt.After(since) {
			uses++
		}
		o, ok := cardOutcomes[e.Outcome]
		if !ok {
			o = [2]string{e.Outcome, "tag"}
		}
		v.Events = append(v.Events, cardEventView{When: s.shortStamp(e.CreatedAt), Outcome: o[0], Tone: o[1],
			Device: deviceAndBrowser(e.UserAgent), Address: e.ClientIP})
	}
	if uses == 0 {
		v.UsesLine = "No uses in the last 30 days"
	} else {
		v.UsesLine = capFirst(countWords(uses, "use", "uses")) + " in the last 30 days"
	}
	if v.Active {
		switch r.URL.Query().Get("confirm") {
		case "replace":
			v.Confirm = "replace"
		case "withdraw":
			v.Confirm = "withdraw"
		}
	}
	s.renderAdmin(w, r, http.StatusOK, "admin_code_detail", adminData{Title: c.Label, CardPage: v})
}

// handleAdminBreakDesign gives a card another design.
func (s *Server) handleAdminBreakDesign(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	c, ok := s.codeFromPath(w, r)
	if !ok {
		return
	}
	id, _ := strconv.ParseInt(r.PostFormValue("design"), 10, 64)
	d, found, err := s.store.GetCardDesign(r.Context(), id)
	if err != nil {
		s.adminError(w, r)
		return
	}
	if !found || c.Status != store.BreakGlassActive {
		s.redirectDone(w, r, "/admin/break/"+strconv.FormatInt(c.ID, 10), "card-design-refused", "")
		return
	}
	if err := s.store.SetCardDesign(r.Context(), c.ID, d.ID); err != nil {
		s.adminError(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionCardDesign, c.Label, "design="+d.Name)
	s.redirectDone(w, r, "/admin/break/"+strconv.FormatInt(c.ID, 10), "card-design", "")
}

// handleAdminBreakRevoke withdraws a card.
func (s *Server) handleAdminBreakRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	c, ok := s.codeFromPath(w, r)
	if !ok {
		return
	}
	if err := s.store.RevokeBreakGlassCode(r.Context(), c.ID); err != nil {
		s.adminError(w, r)
		return
	}
	// Every session the card has granted ends with it.
	if err := s.endSessions(r.Context(), cardKey(c.ID), s.now()); err != nil {
		s.adminError(w, r)
		return
	}
	s.forgetRoles()
	s.auditAdmin(r, store.AdminActionBreakRevoke, "code#"+strconv.FormatInt(c.ID, 10), c.Label)
	s.emailOtherAdmins(s.actor(r), fmt.Sprintf(msgCardWithdrawSub, c.Label), []string{c.Label + " · withdrawn"})
	s.redirectDone(w, r, "/admin/break/"+strconv.FormatInt(c.ID, 10), "card-revoked", "")
}

// handleAdminBreakRemint replaces a card: a new code, so the printed card
// stops working.
func (s *Server) handleAdminBreakRemint(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	c, ok := s.codeFromPath(w, r)
	if !ok {
		return
	}
	tokenEnc, tokenHash, err := s.newToken()
	if err != nil {
		s.adminError(w, r)
		return
	}
	if err := s.store.RemintBreakGlassCode(r.Context(), c.ID, tokenEnc, tokenHash); err != nil {
		s.adminError(w, r)
		return
	}
	// The old card stops working, and so do the sessions it granted.
	if err := s.endSessions(r.Context(), cardKey(c.ID), s.now()); err != nil {
		s.adminError(w, r)
		return
	}
	s.forgetRoles()
	s.auditAdmin(r, store.AdminActionBreakRemint, "code#"+strconv.FormatInt(c.ID, 10), c.Label)
	s.emailOtherAdmins(s.actor(r), fmt.Sprintf(msgCardReplaceSubj, c.Label), []string{c.Label + " · replaced, and the printed card no longer works"})
	s.redirectDone(w, r, "/admin/break/"+strconv.FormatInt(c.ID, 10), "card-reminted", "")
}
