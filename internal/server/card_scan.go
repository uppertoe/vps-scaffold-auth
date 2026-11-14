package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/breakglass"
	"github.com/uppertoe/vps-scaffold-auth/internal/otp"
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
	// A design that no active card uses has no logo served (see
	// handleCardLogo), so its band shows the title instead.
	if d.ID > 0 {
		if l := s.cardLogo(ctx, d.ID); l.png != nil {
			v.LogoURL = "/card-logo/" + strconv.FormatInt(d.ID, 10) + "?v=" + url.QueryEscape(l.version)
			v.Panel = d.LogoMode == store.DesignLogoPanel
		}
	}
}

// cardLogoTTL is how long a design's drawn logo, and whether an active card
// uses it, is kept in memory before the store is read again.
const cardLogoTTL = 30 * time.Second

// cardLogoMax bounds the cache; past it, the cache starts again empty.
const cardLogoMax = 64

// cardLogoEntry is a design's logo as its cards draw it. png is nil when
// the design does not exist, has no logo, or no active card uses it.
type cardLogoEntry struct {
	at      time.Time
	version string
	png     []byte // shared: callers only write it to a response
}

type cardLogoCache struct {
	mu sync.Mutex
	m  map[int64]cardLogoEntry
}

// cardLogo returns a design's drawn logo, from memory when the copy is
// recent, so a flood of logo requests reads the store at most once a
// design per cardLogoTTL. The lock is held across the read, so a flood
// causes one read, not many. A failed read keeps the previous copy.
func (s *Server) cardLogo(ctx context.Context, id int64) cardLogoEntry {
	now := s.now()
	c := &s.cardLogos
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[id]; ok && now.Sub(e.at) < cardLogoTTL && !now.Before(e.at) {
		return e
	}
	e, err := s.loadCardLogo(ctx, id)
	if err != nil {
		log.Printf("card logo %d: %v", id, err)
		return c.m[id]
	}
	e.at = now
	if c.m == nil || len(c.m) >= cardLogoMax {
		c.m = map[int64]cardLogoEntry{}
	}
	c.m[id] = e
	return e
}

// loadCardLogo reads and draws a design's logo, when an active card uses
// the design. Its version changes whenever the drawn logo can: the design is
// saved, or, for a design that uses the site logo, the site logo changes.
func (s *Server) loadCardLogo(ctx context.Context, id int64) (cardLogoEntry, error) {
	inUse, err := s.designsInUse(ctx)
	if err != nil {
		return cardLogoEntry{}, err
	}
	if !inUse[id] {
		return cardLogoEntry{}, nil
	}
	d, found, err := s.store.GetCardDesign(ctx, id)
	if err != nil || !found {
		return cardLogoEntry{}, err
	}
	dd := s.drawDesign(ctx, d)
	png, ok := breakglass.LogoPNG(dd.Logo, dd.LogoType, d.LogoMode)
	if !ok {
		return cardLogoEntry{}, nil
	}
	version := strconv.FormatInt(d.UpdatedAt.Unix(), 10)
	if d.LogoSource == store.DesignLogoSite {
		_, _, sv, err := s.siteLogo(ctx)
		if err != nil {
			return cardLogoEntry{}, err
		}
		version += "-" + sv
	}
	return cardLogoEntry{version: version, png: png}, nil
}

// designsInUse are the designs at least one active card draws: its own, or
// the first design when it has none or its design has gone (see cardDesign).
func (s *Server) designsInUse(ctx context.Context) (map[int64]bool, error) {
	codes, err := s.store.ListBreakGlassCodes(ctx)
	if err != nil {
		return nil, err
	}
	ds, err := s.store.ListCardDesigns(ctx)
	if err != nil {
		return nil, err
	}
	if len(ds) == 0 {
		return nil, nil
	}
	known := make(map[int64]bool, len(ds))
	for _, d := range ds {
		known[d.ID] = true
	}
	out := map[int64]bool{}
	for _, c := range codes {
		if c.Status != store.BreakGlassActive {
			continue
		}
		if known[c.DesignID] {
			out[c.DesignID] = true
		} else {
			out[ds[0].ID] = true
		}
	}
	return out, nil
}

// handleCardLogo serves a design's logo as its cards draw it (white in the
// white treatment), for the band on the scan pages. A logo is not a secret,
// but only the logo of a design an active card uses is served, the requests
// are limited per client address like the scan page's, and the store is read
// at most once a design per cardLogoTTL. The scan pages link the logo with
// its version (?v=), so that URL names one exact image and is cached for a
// year; any other request revalidates by ETag.
func (s *Server) handleCardLogo(w http.ResponseWriter, r *http.Request) {
	if !s.logoLimiter.Allow(clientIP(r)) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	l := s.cardLogo(r.Context(), id)
	if l.png == nil {
		http.NotFound(w, r)
		return
	}
	etag := `"` + l.version + `"`
	w.Header().Set("ETag", etag)
	if r.URL.Query().Get("v") == l.version {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	setImageHeaders(w, "image/png")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Write(l.png)
}

// msgSignInInstead is the withdrawn or replaced card's offer to sign in,
// naming organisations: "If you have an RCH or MCRI email address, you can
// sign in with it instead."
const msgSignInInstead = "If you have %s %s email address, you can sign in with it instead."

// signInSentence offers the organisations whose domain groups hold a role in
// the card's app (any app's, for a card that opens a group), by the
// organisation name each group is given, in the groups' order. A group with
// no name is left out, and with no names there is no sentence.
func (s *Server) signInSentence(ctx context.Context, c store.BreakGlassCode) string {
	if !s.rolesOn() {
		return ""
	}
	held := map[string]bool{}
	for _, a := range s.roleData(ctx).assignments {
		if a.Kind == store.AssignDomainGroup && (c.App == "" || a.App == c.App) {
			held[a.Ref] = true
		}
	}
	groups, err := s.store.ListGroups(ctx)
	if err != nil {
		log.Printf("break-glass sign-in sentence: %v", err)
		return ""
	}
	var orgs []string
	seen := map[string]bool{}
	for _, g := range groups {
		if !held[g.Name] || g.Kind != store.GroupKindDomain || g.Org == "" || seen[g.Org] {
			continue
		}
		seen[g.Org] = true
		orgs = append(orgs, g.Org)
	}
	if len(orgs) == 0 {
		return ""
	}
	return fmt.Sprintf(msgSignInInstead, articleFor(orgs[0]), joinOr(orgs))
}

// articleFor is "a" or "an" before a name: by the sound of its first letter
// for an initialism such as RCH or MCRI ("an RCH"), and by its first vowel
// for a word such as Monash ("a Monash").
func articleFor(name string) string {
	word, _, _ := strings.Cut(name, " ")
	if word == "" {
		return "a"
	}
	vowels := "AEIOUaeiou"
	if len(word) > 1 && strings.ToUpper(word) == word {
		vowels = "AEFHILMNORSX"
	}
	if strings.ContainsRune(vowels, rune(word[0])) {
		return "an"
	}
	return "a"
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
		AppURL:   authz.SafeRedirect(code.Redirect, s.cfg.Domain, s.cfg.DefaultRedirect),
		LoginURL: s.cfg.PublicURL + "/login?rd=" + url.QueryEscape(rd)}
	s.scanBand(ctx, code, v)
	return v, true
}
