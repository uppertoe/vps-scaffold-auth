package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/breakglass"
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
	msgCardNoPages     = msgCardNoPagesApproved
	// Cards made for a group before app roles, which name no app. Drafted on
	// 28 November 2026 for approval.
	msgLegacyHeading = "Cards that open nothing"
	msgLegacyNote    = "Each card in this section was made for a group before app roles. The gateway refuses every scan of a group card. You can withdraw each card from its page."
)

// sampleLocation and sampleApp fill a preview before the form has them.
const sampleLocation = "Location"

// cardsView is the cards list.
type cardsView struct {
	Attention []attentionLine
	Apps      []cardAppGroup
	Legacy    []cardRow
	Empty     bool
	LegacyH   string
	LegacyN   string
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
	v := &cardsView{Empty: len(codes) == 0, LegacyH: msgLegacyHeading}
	groups := map[string]*cardAppGroup{}
	sortCards(codes)
	v.Attention = cardLines(codes, stats)
	for _, c := range codes {
		st := stats[c.ID]
		row := cardRow{ID: c.ID, Label: c.Label, Note: c.Note, Active: c.Status == store.BreakGlassActive, Uses: usesWord(st.uses30),
			Version: strconv.FormatInt(c.UpdatedAt.Unix(), 10)}
		if !st.last.IsZero() {
			row.LastUsed = s.shortStamp(st.last)
		}
		if !c.TestedAt.IsZero() {
			row.Tested = s.shortStamp(c.TestedAt)
		}
		// A card made for a group names no app and opens nothing. It is
		// listed apart, with a note to withdraw it while it is active.
		if c.App == "" {
			if row.Active {
				v.LegacyN = msgLegacyNote
			}
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

// sortCards puts active cards first, then sorts by location.
func sortCards(codes []store.BreakGlassCode) {
	sort.SliceStable(codes, func(i, j int) bool {
		ai, aj := codes[i].Status == store.BreakGlassActive, codes[j].Status == store.BreakGlassActive
		if ai != aj {
			return ai
		}
		return strings.ToLower(codes[i].Label) < strings.ToLower(codes[j].Label)
	})
}

// cardLines are the attention lines about cards, which the Cards page and
// the Overview both show: each active card never tested, and each used
// three times or more in 30 days. A card made for a group is left out, since
// its scan is refused. codes are sorted as sortCards sorts them.
func cardLines(codes []store.BreakGlassCode, stats map[int64]cardStats) []attentionLine {
	var out []attentionLine
	for _, c := range codes {
		if c.Status != store.BreakGlassActive || c.App == "" {
			continue
		}
		link := "/admin/break/" + strconv.FormatInt(c.ID, 10)
		if c.TestedAt.IsZero() {
			out = append(out, attentionLine{Bad: true, Before: "The card for ", Link: link, Name: c.Label, After: " " + msgCardUntested})
		}
		if n := stats[c.ID].uses30; n >= 3 {
			out = append(out, attentionLine{Before: "The card for ", Link: link, Name: c.Label, After: " " + fmt.Sprintf(msgCardBusy, numberWord(n))})
		}
	}
	return out
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
// "" for a card made for a group, which opens nothing.
func (s *Server) cardAppLabel(c store.BreakGlassCode) string {
	if a, ok := s.appRoles.Apps[c.App]; ok {
		return a.Label
	}
	return c.App
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
