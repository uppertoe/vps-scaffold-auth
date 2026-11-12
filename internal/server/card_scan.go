package server

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/breakglass"
	"github.com/uppertoe/vps-scaffold-auth/internal/otp"
	"github.com/uppertoe/vps-scaffold-auth/internal/roles"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// The pages a phone shows when a card is scanned carry the card's design: a
// band in its header colour with its logo. A scan grants nothing until
// Continue is pressed; a signed-in gateway administrator's scan is a test,
// which grants nothing and marks the card tested.

// Scan page variants.
const (
	scanConfirm  = "confirm"
	scanGone     = "gone"
	scanWrongApp = "wrongapp"
	scanTest     = "test"
)

// scanView is a scan page.
type scanView struct {
	Variant  string
	Header   string // the band's colour
	Ink      string // the title's colour on the band, when there is no logo
	LogoURL  string
	Panel    bool
	Title    string
	Label    string
	App      string // the app's label; "" for a card that opens a group
	AppURL   string
	Token    string
	Replaced bool
	SignIn   string // "If you have an RCH or MCRI email address, ..."
	LoginURL string
	CardURL  string
}

// scanBand fills the band from the card's design.
func (s *Server) scanBand(ctx context.Context, c store.BreakGlassCode, v *scanView) {
	d, err := s.cardDesign(ctx, c.DesignID)
	if err != nil {
		d = defaultDesign()
	}
	v.Header = hexOrDefault(d.Header, breakglass.DefaultPalette.Header)
	v.Ink = breakglass.InkOn(v.Header)
	v.Title = d.Title
	if dd := s.drawDesign(ctx, d); len(dd.Logo) > 0 && d.ID > 0 {
		v.LogoURL = "/card-logo/" + strconv.FormatInt(d.ID, 10) + "?v=" + strconv.FormatInt(d.UpdatedAt.Unix(), 10)
		v.Panel = d.LogoMode == store.DesignLogoPanel
	}
}

// handleCardLogo serves a design's logo as its cards draw it (white in the
// white treatment), for the band on the scan pages. A logo is not a secret.
func (s *Server) handleCardLogo(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	d, found, err := s.store.GetCardDesign(r.Context(), id)
	if err != nil || !found {
		http.NotFound(w, r)
		return
	}
	dd := s.drawDesign(r.Context(), d)
	png, ok := breakglass.LogoPNG(dd.Logo, dd.LogoType, d.LogoMode)
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeImage(w, "image/png", png)
}

// signInSentence offers the email domains that hold the card's app, named
// by their organisation ("rch.org.au" is RCH): the domain groups that hold
// the app's user role, or the allow-list's domains.
func (s *Server) signInSentence(ctx context.Context, c store.BreakGlassCode) string {
	var domains []string
	if c.App != "" && s.rolesOn() {
		st := s.roleData(ctx)
		for _, a := range st.assignments {
			if a.App == c.App && a.Role == roles.UserRole && a.Kind == store.AssignDomainGroup {
				domains = append(domains, st.domains[a.Ref]...)
			}
		}
	}
	if len(domains) == 0 {
		domains = s.cfg.AllowedDomains
	}
	var orgs []string
	seen := map[string]bool{}
	for _, d := range domains {
		org := strings.ToUpper(strings.SplitN(strings.TrimPrefix(strings.TrimSpace(d), "@"), ".", 2)[0])
		if org != "" && !seen[org] {
			seen[org] = true
			orgs = append(orgs, org)
		}
	}
	if len(orgs) == 0 {
		return ""
	}
	article := "a"
	if strings.ContainsRune("AEFHILMNORSX", rune(orgs[0][0])) {
		article = "an"
	}
	return "If you have " + article + " " + joinOr(orgs) + " email address, you can sign in with it instead."
}

// isGatewayAdmin reports a signed-in administrator of the gateway (an
// ordinary sign-in, not a card or a guest).
func (s *Server) isGatewayAdmin(r *http.Request) bool {
	id, ok := s.readSession(r, s.now())
	return ok && id.Kind == "" && s.policy.Role(id.Email) == authz.RoleAdmin
}

// handleBreakGlassScan answers the address printed on a card. It grants
// nothing: it shows a page whose one button posts the token to /break. Link
// previews, chat apps and mail scanners (Safe Links among them) fetch a
// shared card's address on their own, and before this page each fetch was a
// grant, with its audit row and notification. The fetch is recorded as
// "viewed", so a card whose address is being passed around still shows up.
//
// A withdrawn or replaced card says so, by its label. A signed-in gateway
// administrator's scan is recorded as a test and marks the card tested.
func (s *Server) handleBreakGlassScan(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	ua := clampUserAgent(r.UserAgent())
	if !s.viewLimiter.Allow(ip) {
		s.breakTooMany(w)
		return
	}
	ctx := r.Context()
	token := r.PathValue("token")
	hash := otp.Hash(token)
	code, found, err := s.store.LookupBreakGlassByTokenHash(ctx, hash)
	if err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong"})
		return
	}
	replaced := false
	if !found {
		id, retired, err := s.store.LookupRetiredToken(ctx, hash)
		if err == nil && retired {
			code, found, err = s.store.GetBreakGlassCode(ctx, id)
			replaced = found && err == nil
		}
		if !replaced {
			log.Printf("break-glass denied (%s) from %s", store.OutcomeUnknown, ip)
			s.cardNotAvailable(w)
			return
		}
	}
	if replaced || code.Status != store.BreakGlassActive {
		outcome := store.OutcomeRevoked
		if replaced {
			outcome = store.OutcomeReplaced
		}
		_ = s.store.RecordBreakGlassEvent(ctx, store.BreakGlassEvent{CodeID: code.ID, Label: code.Label, ClientIP: ip, UserAgent: ua, Outcome: outcome})
		log.Printf("break-glass denied (%s) from %s", outcome, ip)
		v := &scanView{Variant: scanGone, Label: code.Label, Replaced: replaced, SignIn: s.signInSentence(ctx, code),
			LoginURL: s.loginURL(authz.SafeRedirect(code.Redirect, s.cfg.Domain, ""))}
		s.scanBand(ctx, code, v)
		s.render(w, http.StatusNotFound, "break_confirm", pageData{Scan: v})
		return
	}
	// A card whose group has become an application role shows the same page
	// as any card that is not active; the grant records and reports it.
	if code.App == "" {
		if _, refused := s.targetRefusal(code.TargetGroup); refused {
			s.cardNotAvailable(w)
			return
		}
	}
	v := &scanView{Variant: scanConfirm, Label: code.Label, Token: token}
	if code.App != "" {
		v.App = s.cardAppLabel(code)
	}
	s.scanBand(ctx, code, v)
	if s.isGatewayAdmin(r) {
		if err := s.store.RecordBreakGlassEvent(ctx, store.BreakGlassEvent{
			CodeID: code.ID, Label: code.Label, ClientIP: ip, UserAgent: ua, Outcome: store.OutcomeTested,
		}); err != nil {
			log.Printf("break-glass record test of %q: %v", code.Label, err)
		}
		if err := s.store.MarkCardTested(ctx, code.ID, s.now()); err != nil {
			log.Printf("break-glass mark %q tested: %v", code.Label, err)
		}
		v.Variant, v.Token = scanTest, ""
		v.CardURL = s.cfg.PublicURL + "/admin/break/" + strconv.FormatInt(code.ID, 10)
		s.render(w, http.StatusOK, "break_confirm", pageData{Scan: v})
		return
	}
	if err := s.store.RecordBreakGlassEvent(ctx, store.BreakGlassEvent{
		CodeID: code.ID, Label: code.Label, ClientIP: ip,
		UserAgent: ua, Outcome: store.OutcomeViewed,
	}); err != nil {
		// Nothing is granted here, so a failed write cannot hide a grant.
		log.Printf("break-glass record viewed event for %q: %v", code.Label, err)
	}
	s.render(w, http.StatusOK, "break_confirm", pageData{Scan: v, BreakToken: token})
}

// wrongAppPage is the denial page for someone holding a card's session who
// has followed a link to another app: it names the app the card opens. ok is
// false for a card that opens a group, which keeps the older page.
func (s *Server) wrongAppPage(ctx context.Context, id *session.Identity, rd string) (*scanView, bool) {
	code, found, err := s.store.GetBreakGlassCode(ctx, id.Card)
	if err != nil || !found || code.App == "" {
		return nil, false
	}
	v := &scanView{Variant: scanWrongApp, Label: code.Label, App: s.cardAppLabel(code),
		AppURL: authz.SafeRedirect(code.Redirect, s.cfg.Domain, s.cfg.DefaultRedirect),
		LoginURL: s.cfg.PublicURL + "/login?rd=" + url.QueryEscape(rd)}
	s.scanBand(ctx, code, v)
	return v, true
}
