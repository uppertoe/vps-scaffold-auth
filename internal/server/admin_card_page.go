// One break-glass card's page: its uses, design, revocation and reminting.

package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// --- One card's page ---

type cardPageView struct {
	ID         int64
	Label      string
	AppLabel   string
	Active     bool
	Steps      []cardStep
	Withdrawn  string
	PreviewURL string
	Caption    string
	Designs    []designChoice
	DesignID   int64
	DesignName string
	AppToken   tokenView
	PageLabel  string
	PageURL    string
	Note       string
	UsesLine   string
	Events     []cardEventView
	Confirm    string // "replace" or "withdraw" while asking
	// OpensNothing marks a card that names no app (see opensNothing). Its
	// page offers only Withdraw, since a replacement would open nothing too.
	OpensNothing bool
	ConfirmText  string
	ReplaceText  string
	WithdrawTxt  string
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
	store.OutcomeRefusedTarget: {"Refused: the card opens nothing", "off"},
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
	s.renderCardPage(w, r, c, r.URL.Query().Get("confirm"))
}

// renderCardPage draws a card's page. confirm is the action being confirmed
// ("replace" or "withdraw").
func (s *Server) renderCardPage(w http.ResponseWriter, r *http.Request, c store.BreakGlassCode, confirm string) {
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
	v.OpensNothing = opensNothing(c)
	if v.Active {
		switch confirm {
		case "replace":
			if !v.OpensNothing {
				v.Confirm = "replace"
			}
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
	// Every session the card has granted ends first; the card is withdrawn
	// only once they have (revokeAnd).
	if err := s.revokeAnd(r.Context(), []string{cardKey(c.ID)}, sessionsForKey(cardKey(c.ID)), s.now(), func() error {
		return s.store.RevokeBreakGlassCode(r.Context(), c.ID)
	}); err != nil {
		s.adminError(w, r)
		return
	}
	s.forgetRoles()
	s.auditAdmin(r, store.AdminActionBreakRevoke, "code#"+strconv.FormatInt(c.ID, 10), c.Label)
	s.emailOtherAdmins(s.adminActor(r), fmt.Sprintf(msgCardWithdrawSub, c.Label), []string{c.Label + " · withdrawn"})
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
	// A withdrawn card stays withdrawn; its page offers no replacement.
	if c.Status != store.BreakGlassActive {
		s.redirectDone(w, r, "/admin/break/"+strconv.FormatInt(c.ID, 10), "card-remint-refused", "")
		return
	}
	// A card that opens nothing is not offered a replacement either, which
	// would open nothing too; a hand-made post gets the neutral page.
	if opensNothing(c) {
		s.cardNotAvailable(w)
		return
	}
	tokenEnc, tokenHash, err := s.newToken()
	if err != nil {
		s.adminError(w, r)
		return
	}
	// The sessions the old card granted end first; the card is replaced only
	// once they have (revokeAnd).
	if err := s.revokeAnd(r.Context(), []string{cardKey(c.ID)}, sessionsForKey(cardKey(c.ID)), s.now(), func() error {
		return s.store.RemintBreakGlassCode(r.Context(), c.ID, tokenEnc, tokenHash)
	}); err != nil {
		if errors.Is(err, store.ErrCardNotActive) {
			s.redirectDone(w, r, "/admin/break/"+strconv.FormatInt(c.ID, 10), "card-remint-refused", "")
			return
		}
		s.adminError(w, r)
		return
	}
	s.forgetRoles()
	s.auditAdmin(r, store.AdminActionBreakRemint, "code#"+strconv.FormatInt(c.ID, 10), c.Label)
	s.emailOtherAdmins(s.adminActor(r), fmt.Sprintf(msgCardReplaceSubj, c.Label), []string{c.Label + " · replaced, and the printed card no longer works"})
	s.redirectDone(w, r, "/admin/break/"+strconv.FormatInt(c.ID, 10), "card-reminted", "")
}
