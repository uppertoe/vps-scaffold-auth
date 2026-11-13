package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/uppertoe/vps-scaffold-auth/internal/breakglass"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// Card designs: the list of designs and the design editor. A design sets the
// colours, logo, title, steps and printed size of every card that uses it.

// Wording of the design pages, approved on 13 November 2026 (the
// prototype's wording is used wherever it has some).
const (
	msgDesignNoName     = "Enter a name for the design."
	msgDesignNameTaken  = "A design called %s already exists. Choose another name."
	msgDesignNoSteps    = "Enter at least one step, one to a line."
	msgDesignManySteps  = "A card has room for eight steps at most."
	msgDesignLongTitle  = "A title can be 40 characters at most, so that it fits the header."
	msgDesignNoLogo     = "Choose a logo file for the cards, or choose The site logo or No logo."
	msgDesignBadLogo    = "The logo has not been saved. Logos must be PNG, JPEG or SVG files under 2 MB, and no more than 1,000 pixels wide or high."
	msgDesignInUse      = "The design has not been deleted, because %s. Give those cards another design first."
	msgDesignLast       = "The design has not been deleted, because it is the only design and every card needs one."
	msgDesignSubject    = "The card design %s has changed."
	msgAccentWarn       = "The accent colour is hard to see on white. Choose a darker accent."
	msgLogoWarnWhite    = "The logo is hard to see on this header colour. Choose In white, or On a white panel."
	msgLogoWarnAsIs     = "The logo is hard to see on this header colour. Choose As uploaded, or On a white panel."
	maxDesignSteps      = 8
	maxDesignTitleRunes = 40
	maxDesignNameRunes  = 60
)

// designPreset is one of the editor's colour presets.
type designPreset struct {
	Name, Header, Accent string
	Stripe               bool
}

var designPresets = []designPreset{
	{"Department", "#003a5c", "#0b7bbf", true},
	{"Charcoal", "#2b2f36", "#0f7b6c", false},
	{"Light", "#eef2f5", "#2f6f8f", false},
	{"Alert red", "#9b1c1c", "#b42318", false},
}

type designsView struct {
	Tiles []designTile
}

type designTile struct {
	ID       int64
	Name     string
	Uses     string
	ThumbURL string
}

// designUse counts the active cards that use each design (a card without a
// design uses the first).
func designUse(codes []store.BreakGlassCode, designs []store.CardDesign) map[int64]int {
	out := map[int64]int{}
	first := int64(0)
	if len(designs) > 0 {
		first = designs[0].ID
	}
	known := map[int64]bool{}
	for _, d := range designs {
		known[d.ID] = true
	}
	for _, c := range codes {
		if c.Status != store.BreakGlassActive {
			continue
		}
		id := c.DesignID
		if !known[id] {
			id = first
		}
		out[id]++
	}
	return out
}

func usesDesign(n int) string {
	switch n {
	case 0:
		return "No cards use it"
	case 1:
		return "One card uses it"
	}
	return capFirst(numberWord(n)) + " cards use it"
}

func (s *Server) handleAdminDesigns(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	designs, err := s.store.ListCardDesigns(ctx)
	if err != nil {
		s.adminError(w, r)
		return
	}
	codes, err := s.store.ListBreakGlassCodes(ctx)
	if err != nil {
		s.adminError(w, r)
		return
	}
	use := designUse(codes, designs)
	v := &designsView{}
	for _, d := range designs {
		v.Tiles = append(v.Tiles, designTile{ID: d.ID, Name: d.Name, Uses: usesDesign(use[d.ID]) + " · " + d.Size,
			ThumbURL: "/admin/break/designs/" + strconv.FormatInt(d.ID, 10) + "/card.svg?v=" + strconv.FormatInt(d.UpdatedAt.Unix(), 10)})
	}
	s.renderAdmin(w, r, http.StatusOK, "admin_designs", adminData{Title: "Card designs", Designs: v})
}

// sampleFor is the card a design's preview shows: the newest active card
// that uses it, or a placeholder.
func (s *Server) sampleFor(ctx context.Context, d store.CardDesign) (label, app string) {
	codes, err := s.store.ListBreakGlassCodes(ctx)
	if err == nil {
		designs, _ := s.store.ListCardDesigns(ctx)
		first := int64(0)
		if len(designs) > 0 {
			first = designs[0].ID
		}
		for _, c := range codes {
			if c.Status == store.BreakGlassActive && (c.DesignID == d.ID || (c.DesignID == 0 && d.ID == first)) {
				return c.Label, s.cardAppLabel(c)
			}
		}
	}
	return sampleLocation, ""
}

func (s *Server) handleAdminDesignSVG(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	d, found, err := s.store.GetCardDesign(r.Context(), id)
	if err != nil {
		s.adminError(w, r)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	label, app := s.sampleFor(r.Context(), d)
	writeSVG(w, breakglass.Card{Design: s.drawDesign(r.Context(), d), Location: label, App: app}.SVG())
}

// --- The editor ---

type designEditView struct {
	ID         int64
	New        bool
	Action     string
	Name       string
	Sub        string
	Presets    []designPreset
	Header     colourField
	Accent     colourField
	Stripe     bool
	Bars       []colourField
	LogoSource string
	Sources    []choiceView
	Modes      []choiceView
	HasOwnLogo bool
	InkSite    string
	InkOwn     string
	// SolidSite and SolidOwn mark a logo on a solid tile, which reads best
	// on a white panel (see breakglass.LogoSolid).
	SolidSite  bool
	SolidOwn   bool
	Title      string
	Steps      string
	Sizes      []choiceView
	AccentWarn string
	LogoWarn   string
	SaveNote   string
	PreviewURL string
	Caption    string
	Sample     string
	SampleApp  string
	CanDelete  bool
	DeleteNote string
}

type colourField struct {
	Key, Label, Value string
}

type choiceView struct {
	Value, Title, Detail, Caption string
	Checked, Rec                  bool
}

func (s *Server) handleAdminDesignNew(w http.ResponseWriter, r *http.Request) {
	d := defaultDesign()
	d.ID, d.Name = 0, ""
	// A site logo on a solid tile starts on a white panel.
	if logo, mime, _, err := s.siteLogo(r.Context()); err == nil && len(logo) > 0 {
		if solid, _ := breakglass.LogoSolid(logo, mime); solid {
			d.LogoMode = store.DesignLogoPanel
		}
	}
	if r.URL.Query().Get("draft") != "" {
		d, _ = designFromForm(r.URL.Query().Get, d)
	}
	s.renderDesign(w, r, http.StatusOK, d, "")
}

func (s *Server) handleAdminDesign(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	d, found, err := s.store.GetCardDesign(r.Context(), id)
	if err != nil {
		s.adminError(w, r)
		return
	}
	if !found {
		http.Redirect(w, r, "/admin/break/designs", http.StatusFound)
		return
	}
	// "Update the preview" and the presets, without a script, come back
	// here with the form's values.
	if r.URL.Query().Get("draft") != "" {
		d, _ = designFromForm(r.URL.Query().Get, d)
	}
	s.renderDesign(w, r, http.StatusOK, d, "")
}

// designFromForm reads the editor's fields over base. A colour comes from
// its hex field when that was edited and from its picker otherwise. It
// returns the problems that stop a save.
func designFromForm(get func(string) string, base store.CardDesign) (store.CardDesign, []string) {
	d := base
	var problems []string
	colour := func(key, cur string) string {
		hex, pick, was := get(key+"_hex"), get(key), get(key+"_was")
		if v := hexOrDefault(hex, ""); v != "" && !strings.EqualFold(v, was) {
			return v
		}
		return hexOrDefault(pick, cur)
	}
	if v := get("name"); v != "" || get("draft") == "" {
		d.Name = clampRunes(trimField(v), maxDesignNameRunes)
	}
	d.Header = colour("header", d.Header)
	d.Accent = colour("accent", d.Accent)
	d.Stripe = get("stripe") != ""
	d.Bar1, d.Bar2, d.Bar3 = colour("bar1", d.Bar1), colour("bar2", d.Bar2), colour("bar3", d.Bar3)
	if p, err := strconv.Atoi(get("preset")); err == nil && p >= 0 && p < len(designPresets) {
		pr := designPresets[p]
		d.Header, d.Accent, d.Stripe = pr.Header, pr.Accent, pr.Stripe
	}
	switch v := get("logo_source"); v {
	case store.DesignLogoSite, store.DesignLogoOwn, store.DesignLogoNone:
		d.LogoSource = v
	}
	switch v := get("logo_mode"); v {
	case store.DesignLogoAsIs, store.DesignLogoWhite, store.DesignLogoPanel:
		d.LogoMode = v
	}
	title := trimField(get("title"))
	if len([]rune(title)) > maxDesignTitleRunes {
		problems = append(problems, msgDesignLongTitle)
		title = clampRunes(title, maxDesignTitleRunes)
	}
	if title == "" {
		title = store.DefaultDesignTitle
	}
	d.Title = title
	steps := breakglass.StepLines(strings.ReplaceAll(get("steps"), "\r\n", "\n"))
	if len(steps) == 0 {
		problems = append(problems, msgDesignNoSteps)
	} else {
		if len(steps) > maxDesignSteps {
			problems = append(problems, msgDesignManySteps)
			steps = steps[:maxDesignSteps]
		}
		for i := range steps {
			steps[i] = clampRunes(steps[i], 160)
		}
		d.Steps = strings.Join(steps, "\n")
	}
	if _, ok := breakglass.Sizes[get("size")]; ok {
		d.Size = get("size")
	}
	if d.Name == "" {
		problems = append(problems, msgDesignNoName)
	}
	return d, problems
}

func clampRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// designPreviewURL is the address of the editor's preview of d.
func designPreviewURL(d store.CardDesign, label, app string) string {
	q := url.Values{
		"id": {strconv.FormatInt(d.ID, 10)}, "draft": {"1"}, "name": {d.Name},
		"header": {d.Header}, "accent": {d.Accent}, "bar1": {d.Bar1}, "bar2": {d.Bar2}, "bar3": {d.Bar3},
		"logo_source": {d.LogoSource}, "logo_mode": {d.LogoMode}, "title": {d.Title}, "steps": {d.Steps},
		"size": {d.Size}, "label": {label}, "app": {app},
	}
	if d.Stripe {
		q.Set("stripe", "1")
	}
	return "/admin/break/designs/preview.svg?" + q.Encode()
}

// handleAdminDesignPreview draws a design as the editor has it, saved or
// not. Its logo is the stored one (an upload is drawn once saved).
func (s *Server) handleAdminDesignPreview(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	base := defaultDesign()
	if id, _ := strconv.ParseInt(q.Get("id"), 10, 64); id > 0 {
		if d, found, err := s.store.GetCardDesign(r.Context(), id); err == nil && found {
			base = d
		}
	}
	d, _ := designFromForm(q.Get, base)
	label := clampLabel(trimField(q.Get("label")))
	if label == "" {
		label = sampleLocation
	}
	writeSVG(w, breakglass.Card{Design: s.drawDesign(r.Context(), d), Location: label, App: clampLabel(trimField(q.Get("app")))}.SVG())
}

// renderDesign draws the editor for d (unsaved when d.ID is 0).
func (s *Server) renderDesign(w http.ResponseWriter, r *http.Request, status int, d store.CardDesign, warning string) {
	ctx := r.Context()
	designs, err := s.store.ListCardDesigns(ctx)
	if err != nil {
		s.adminError(w, r)
		return
	}
	codes, err := s.store.ListBreakGlassCodes(ctx)
	if err != nil {
		s.adminError(w, r)
		return
	}
	n := designUse(codes, designs)[d.ID]
	v := &designEditView{ID: d.ID, New: d.ID == 0, Name: d.Name, Presets: designPresets, Stripe: d.Stripe,
		LogoSource: d.LogoSource, Title: d.Title, Steps: d.Steps,
		Header: colourField{"header", "Header", d.Header}, Accent: colourField{"accent", "Accent", d.Accent},
		Bars: []colourField{{"bar1", "Stripe 1", d.Bar1}, {"bar2", "Stripe 2", d.Bar2}, {"bar3", "Stripe 3", d.Bar3}}}
	switch {
	case v.New:
		v.Action = "/admin/break/designs"
		v.Sub = "This design is not saved yet."
		v.SaveNote = "Saving adds the design to the list."
	case n == 0:
		v.Sub = "No active card uses this design."
		v.SaveNote = "Saving changes no printed card."
	default:
		v.Sub = capFirst(countWords(n, "active card uses", "active cards use")) + " this design."
		v.SaveNote = fmt.Sprintf(msgDesignSaveNote, countWords(n, "card", "cards"))
	}
	if !v.New {
		v.Action = "/admin/break/designs/" + strconv.FormatInt(d.ID, 10) + "/save"
		v.CanDelete = n == 0 && len(designs) > 1
		switch {
		case n > 0:
			v.DeleteNote = "The design cannot be deleted while cards use it. Give those cards another design first."
		case len(designs) <= 1:
			v.DeleteNote = "The design cannot be deleted, because it is the only design and every card needs one."
		}
	}
	// The logo's own colour, for the readability check of each source.
	if logo, mime, _, err := s.siteLogo(ctx); err == nil && len(logo) > 0 {
		v.InkSite, _ = breakglass.LogoInk(logo, mime)
		v.SolidSite, _ = breakglass.LogoSolid(logo, mime)
	}
	if stored, found, _ := s.store.GetCardDesign(ctx, d.ID); found && len(stored.Logo) > 0 {
		v.HasOwnLogo = true
		v.InkOwn, _ = breakglass.LogoInk(stored.Logo, stored.LogoType)
		v.SolidOwn, _ = breakglass.LogoSolid(stored.Logo, stored.LogoType)
	}
	ink, hasLogo, solid := v.InkSite, v.InkSite != "", v.SolidSite
	if d.LogoSource == store.DesignLogoOwn {
		ink, hasLogo, solid = v.InkOwn, v.HasOwnLogo, v.SolidOwn
	}
	if d.LogoSource == store.DesignLogoNone {
		hasLogo = false
	}
	best, ok := breakglass.LogoReadable(d.Header, d.LogoMode, ink, hasLogo)
	if solid {
		best = store.DesignLogoPanel
	}
	if !ok {
		v.LogoWarn = msgLogoWarnAsIs
		if best == store.DesignLogoWhite {
			v.LogoWarn = msgLogoWarnWhite
		}
	}
	if breakglass.Contrast(d.Accent, "#ffffff") < 3 {
		v.AccentWarn = msgAccentWarn
	}
	for _, src := range [][2]string{{store.DesignLogoSite, "The site logo"}, {store.DesignLogoOwn, "A logo for cards"}, {store.DesignLogoNone, "No logo"}} {
		v.Sources = append(v.Sources, choiceView{Value: src[0], Title: src[1], Checked: d.LogoSource == src[0]})
	}
	for _, m := range [][3]string{
		{store.DesignLogoAsIs, "As uploaded", "The logo keeps its own colours."},
		{store.DesignLogoWhite, "In white", "The gateway makes a white version from the same file."},
		{store.DesignLogoPanel, "On a white panel", "The logo keeps its colours, on a white rounded panel."},
	} {
		v.Modes = append(v.Modes, choiceView{Value: m[0], Title: m[1], Detail: m[2], Checked: d.LogoMode == m[0], Rec: hasLogo && best == m[0]})
	}
	for _, size := range breakglass.SizeOrder {
		v.Sizes = append(v.Sizes, choiceView{Value: size, Title: size, Detail: sizeWords[size], Caption: "Printed at " + size + ": " + sizeText(size), Checked: d.Size == size})
	}
	v.Sample, v.SampleApp = s.sampleFor(ctx, d)
	if v.New {
		v.Sample, v.SampleApp = sampleLocation, ""
	}
	v.PreviewURL = designPreviewURL(d, v.Sample, v.SampleApp)
	v.Caption = "Printed at " + d.Size + ": " + sizeText(d.Size)
	title := d.Name
	if title == "" {
		title = "New design"
	}
	s.renderAdmin(w, r, status, "admin_design", adminData{Title: title, DesignEd: v, Warning: warning, Script: designScript})
}

// readDesignForm parses a design form (multipart, for the logo) and checks
// its token. ok is false once a response has been written.
func (s *Server) readDesignForm(w http.ResponseWriter, r *http.Request) bool {
	allowSlowUpload(w)
	r.Body = http.MaxBytesReader(w, r.Body, maxBrandingUpload+64<<10)
	if err := r.ParseMultipartForm(maxBrandingUpload); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		s.renderAdmin(w, r, http.StatusRequestEntityTooLarge, "admin_message", adminData{
			Title: "Upload too large", Message: "The images in one upload must total less than 2 MB.",
		})
		return false
	}
	return s.checkCSRF(w, r)
}

// applyDesignForm reads the form over base, takes an uploaded logo, and
// returns the design, whether the logo is to be replaced, and a warning that
// stops the save.
func (s *Server) applyDesignForm(r *http.Request, base store.CardDesign) (store.CardDesign, bool, string) {
	d, problems := designFromForm(r.PostFormValue, base)
	data, mime, present, err := readUploadedImage(r, "logo")
	if err != nil {
		return d, false, msgDesignBadLogo
	}
	replace := false
	if present {
		d.Logo, d.LogoType, replace = data, mime, true
		d.LogoSource = store.DesignLogoOwn
	}
	if d.LogoSource == store.DesignLogoOwn && len(d.Logo) == 0 {
		problems = append(problems, msgDesignNoLogo)
	}
	if len(problems) > 0 {
		return d, false, problems[0]
	}
	return d, replace, ""
}

func (s *Server) handleAdminDesignCreate(w http.ResponseWriter, r *http.Request) {
	if !s.readDesignForm(w, r) {
		return
	}
	base := defaultDesign()
	base.Name = ""
	d, _, warning := s.applyDesignForm(r, base)
	if previewOnly(r) {
		d.Logo, d.LogoType = nil, ""
		s.renderDesign(w, r, http.StatusOK, d, "")
		return
	}
	if warning != "" {
		s.renderDesign(w, r, http.StatusBadRequest, d, warning)
		return
	}
	id, err := s.store.CreateCardDesign(r.Context(), d)
	if errors.Is(err, store.ErrDesignName) {
		s.renderDesign(w, r, http.StatusConflict, d, fmt.Sprintf(msgDesignNameTaken, d.Name))
		return
	}
	if err != nil {
		s.adminError(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionDesignCreate, d.Name, "size="+d.Size)
	s.emailOtherAdmins(s.actor(r), fmt.Sprintf(msgDesignSubject, d.Name), []string{d.Name + " · a new design, which no card uses yet"})
	s.redirectDone(w, r, "/admin/break/designs/"+strconv.FormatInt(id, 10), "design-created", "")
}

func (s *Server) handleAdminDesignSave(w http.ResponseWriter, r *http.Request) {
	if !s.readDesignForm(w, r) {
		return
	}
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	base, found, err := s.store.GetCardDesign(r.Context(), id)
	if err != nil {
		s.adminError(w, r)
		return
	}
	if !found {
		http.Redirect(w, r, "/admin/break/designs", http.StatusSeeOther)
		return
	}
	d, replace, warning := s.applyDesignForm(r, base)
	if previewOnly(r) {
		d.Logo, d.LogoType = base.Logo, base.LogoType
		s.renderDesign(w, r, http.StatusOK, d, "")
		return
	}
	if warning != "" {
		s.renderDesign(w, r, http.StatusBadRequest, d, warning)
		return
	}
	if err := s.store.SaveCardDesign(r.Context(), d, replace); errors.Is(err, store.ErrDesignName) {
		s.renderDesign(w, r, http.StatusConflict, d, fmt.Sprintf(msgDesignNameTaken, d.Name))
		return
	} else if err != nil {
		s.adminError(w, r)
		return
	}
	// Code emails take their colours from the first design.
	s.forgetBranding()
	designs, _ := s.store.ListCardDesigns(r.Context())
	codes, _ := s.store.ListBreakGlassCodes(r.Context())
	n := designUse(codes, designs)[d.ID]
	s.auditAdmin(r, store.AdminActionDesignSave, d.Name, "size="+d.Size)
	s.emailOtherAdmins(s.actor(r), fmt.Sprintf(msgDesignSubject, d.Name), []string{d.Name + " · saved · " + strings.ToLower(usesDesign(n))})
	s.redirectDone(w, r, "/admin/break/designs/"+strconv.FormatInt(d.ID, 10), "design-saved", "")
}

func (s *Server) handleAdminDesignDelete(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	d, found, err := s.store.GetCardDesign(r.Context(), id)
	if err != nil {
		s.adminError(w, r)
		return
	}
	if !found {
		http.Redirect(w, r, "/admin/break/designs", http.StatusSeeOther)
		return
	}
	switch err := s.store.DeleteCardDesign(r.Context(), id); {
	case errors.Is(err, store.ErrDesignInUse):
		designs, _ := s.store.ListCardDesigns(r.Context())
		codes, _ := s.store.ListBreakGlassCodes(r.Context())
		n := designUse(codes, designs)[id]
		s.renderDesign(w, r, http.StatusConflict, d, fmt.Sprintf(msgDesignInUse, strings.ToLower(usesDesign(n))))
		return
	case errors.Is(err, store.ErrLastDesign):
		s.renderDesign(w, r, http.StatusConflict, d, msgDesignLast)
		return
	case err != nil:
		s.adminError(w, r)
		return
	}
	s.forgetBranding()
	s.auditAdmin(r, store.AdminActionDesignDelete, d.Name, "")
	s.redirectDone(w, r, "/admin/break/designs", "design-deleted", "")
}

// previewOnly reports a form sent by "Update the preview" or a colour preset
// without a script: the editor is shown again with its values, and nothing is
// saved.
func previewOnly(r *http.Request) bool {
	return r.PostFormValue("preview") != "" || r.PostFormValue("preset") != ""
}
