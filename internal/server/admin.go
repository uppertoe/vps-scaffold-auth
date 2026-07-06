package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/breakglass"
	"github.com/uppertoe/vps-scaffold-auth/internal/otp"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
	"github.com/uppertoe/vps-scaffold-auth/internal/totp"
)

// adminRoutes registers the admin subtree on its own mux. The whole tree is
// wrapped by requireAdmin in routes(); handlers here can assume an admin caller.
func (s *Server) adminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/{$}", s.handleAdminHome)
	mux.HandleFunc("GET /admin/groups", s.handleAdminGroups)
	mux.HandleFunc("POST /admin/groups", s.handleAdminCreateGroup)
	mux.HandleFunc("POST /admin/groups/{name}/delete", s.handleAdminDeleteGroup)
	mux.HandleFunc("POST /admin/groups/{name}/members", s.handleAdminAddMember)
	mux.HandleFunc("POST /admin/groups/{name}/members/delete", s.handleAdminRemoveMember)
	mux.HandleFunc("GET /admin/access", s.handleAdminAccess)
	mux.HandleFunc("GET /admin/audit", s.handleAdminAudit)
	mux.HandleFunc("GET /admin/break", s.handleAdminBreakList)
	mux.HandleFunc("POST /admin/break", s.handleAdminBreakCreate)
	mux.HandleFunc("GET /admin/break/{id}", s.handleAdminBreakDetail)
	mux.HandleFunc("POST /admin/break/{id}/revoke", s.handleAdminBreakRevoke)
	mux.HandleFunc("POST /admin/break/{id}/remint", s.handleAdminBreakRemint)
	mux.HandleFunc("GET /admin/break/{id}/qr.png", s.handleAdminBreakQR)
	mux.HandleFunc("GET /admin/break/{id}/pdf", s.handleAdminBreakPDF)
	mux.HandleFunc("POST /admin/break/{id}/branding", s.handleAdminSaveCodeBranding)
	mux.HandleFunc("GET /admin/break/{id}/branding/{which}/img", s.handleAdminCodeBrandingImage)
	mux.HandleFunc("GET /admin/branding", s.handleAdminBranding)
	mux.HandleFunc("POST /admin/branding", s.handleAdminSaveBranding)
	mux.HandleFunc("GET /admin/branding/{which}/img", s.handleAdminBrandingImage)
	mux.HandleFunc("GET /admin/settings", s.handleAdminSettings)
	mux.HandleFunc("POST /admin/settings", s.handleAdminSaveSettings)
	mux.HandleFunc("GET /admin/totp", s.handleAdminTOTP)
	mux.HandleFunc("POST /admin/totp/generate", s.handleAdminTOTPGenerate)
	mux.HandleFunc("POST /admin/totp/remove", s.handleAdminTOTPRemove)
}

// --- Admin two-factor provisioning ---
//
// TOTP secrets are provisioned out-of-band, never self-enrolled at login (that
// would let an inbox-only attacker bootstrap the second factor). An already
// authenticated admin mints a secret here and conveys it to the target admin
// over a trusted channel; the first admin is bootstrapped with the -totp-enroll
// CLI. See startTOTP.

// handleAdminTOTP lists the configured admins and their enrolment status.
func (s *Server) handleAdminTOTP(w http.ResponseWriter, r *http.Request) {
	s.renderAdmin(w, r, http.StatusOK, "admin_totp", adminData{
		Title:       "Admin two-factor",
		TOTPEnabled: s.cfg.TOTPEnabled,
		TOTPAdmins:  s.totpAdminViews(r.Context()),
	})
}

// handleAdminTOTPGenerate mints (or resets) a TOTP secret for a configured admin
// and shows it exactly once on the returned page.
func (s *Server) handleAdminTOTPGenerate(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	emailAddr := normalizeEmail(r.PostFormValue("email"))
	if !s.isAdminEmail(emailAddr) {
		s.renderAdmin(w, r, http.StatusBadRequest, "admin_message", adminData{
			Title:   "Unknown admin",
			Message: "That address is not in the configured admin list (ADMIN_EMAILS), so a secret was not created.",
		})
		return
	}
	en, err := totp.Enroll(s.totpIssuer(), emailAddr)
	if err != nil {
		s.adminError(w, r)
		return
	}
	if err := s.setTOTPSecret(r.Context(), emailAddr, en.Secret); err != nil {
		s.adminError(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionTOTPGenerate, emailAddr, "")
	// Render (not redirect) so the secret appears once and lands in no URL or
	// history; refreshing the page drops it.
	s.renderAdmin(w, r, http.StatusOK, "admin_totp", adminData{
		Title:       "Admin two-factor",
		TOTPEnabled: s.cfg.TOTPEnabled,
		TOTPAdmins:  s.totpAdminViews(r.Context()),
		NewTOTP:     &newTOTPView{Email: emailAddr, URL: en.URL, Key: en.Secret},
	})
}

// handleAdminTOTPRemove deletes an admin's TOTP secret. With TOTP enabled, that
// admin then cannot sign in until re-provisioned.
func (s *Server) handleAdminTOTPRemove(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	emailAddr := normalizeEmail(r.PostFormValue("email"))
	if err := s.store.DeleteTOTPSecret(r.Context(), emailAddr); err != nil {
		s.adminError(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionTOTPRemove, emailAddr, "")
	http.Redirect(w, r, "/admin/totp", http.StatusFound)
}

// totpAdminViews reports each configured admin and whether a secret is stored.
func (s *Server) totpAdminViews(ctx context.Context) []totpAdminView {
	out := make([]totpAdminView, 0, len(s.cfg.AdminEmails))
	for _, e := range s.cfg.AdminEmails {
		_, ok, err := s.store.GetTOTPSecret(ctx, e)
		if err != nil {
			log.Printf("totp status for %s: %v", e, err)
		}
		out = append(out, totpAdminView{Email: e, Enrolled: ok})
	}
	return out
}

// isAdminEmail reports whether email is in the configured admin list. AdminEmails
// is already normalised (lowercased/trimmed) at config load.
func (s *Server) isAdminEmail(email string) bool {
	for _, e := range s.cfg.AdminEmails {
		if e == email {
			return true
		}
	}
	return false
}

// totpIssuer is the issuer label shown in authenticator apps.
func (s *Server) totpIssuer() string {
	if s.cfg.TOTPIssuer != "" {
		return s.cfg.TOTPIssuer
	}
	return s.cfg.Domain
}

// defaultInstructions is shown on the card when no custom instructions are set.
const defaultInstructions = "1. Open your phone camera and point it at the code.\n" +
	"2. Tap the link that appears.\n" +
	"3. You will be signed in for temporary emergency access."

// maxBrandingUpload caps logo/glyph upload size.
const maxBrandingUpload = 2 << 20 // 2 MiB

// resolvedBranding loads stored branding and fills empty text fields with the
// configured/built-in defaults. (Colours/images are left empty here; the PDF
// renderer falls back to the RCH palette for empty colours.)
func (s *Server) resolvedBranding(ctx context.Context) store.Branding {
	b, _, err := s.store.GetBranding(ctx)
	if err != nil {
		log.Printf("load branding: %v", err)
	}
	if trimField(b.Title) == "" {
		b.Title = orFallback(s.cfg.BreakGlassPDFHeader, "Emergency access")
	}
	if trimField(b.Body) == "" {
		b.Body = s.cfg.BreakGlassPDFBody
	}
	if trimField(b.Instructions) == "" {
		b.Instructions = defaultInstructions
	}
	return b
}

// effectiveCardBranding merges a code's per-code overrides over the global
// branding over the built-in defaults, producing the final content+palette for
// that code's PDF and QR.
func (s *Server) effectiveCardBranding(ctx context.Context, codeID int64) store.Branding {
	g := s.resolvedBranding(ctx) // global, with text defaults filled
	c, err := s.store.GetCodeBranding(ctx, codeID)
	if err != nil {
		log.Printf("load code branding %d: %v", codeID, err)
	}
	pick := func(override, base string) string {
		if trimField(override) != "" {
			return override
		}
		return base
	}
	out := store.Branding{
		Title:        pick(c.Title, g.Title),
		Body:         pick(c.Body, g.Body),
		Instructions: pick(c.Instructions, g.Instructions),
		HeaderColor:  pick(c.HeaderColor, g.HeaderColor),
		AccentColor:  pick(c.AccentColor, g.AccentColor),
		Bar1Color:    pick(c.Bar1Color, g.Bar1Color),
		Bar2Color:    pick(c.Bar2Color, g.Bar2Color),
		Bar3Color:    pick(c.Bar3Color, g.Bar3Color),
	}
	// Card logo: per-card override, else the PDF-default logo (typically a white
	// variant for the dark header), else the global site logo.
	if len(c.Logo) > 0 {
		out.Logo, out.LogoType = c.Logo, c.LogoType
	} else if len(g.PDFLogo) > 0 {
		out.Logo, out.LogoType = g.PDFLogo, g.PDFLogoType
	} else {
		out.Logo, out.LogoType = g.Logo, g.LogoType
	}
	if len(c.Glyph) > 0 {
		out.Glyph, out.GlyphType = c.Glyph, c.GlyphType
	} else {
		out.Glyph, out.GlyphType = g.Glyph, g.GlyphType
	}
	return out
}

func orFallback(v, def string) string {
	if trimField(v) == "" {
		return def
	}
	return v
}

// maxBreakGlassTTL caps how long an emergency session may last, regardless of
// the source (admin-saved setting or BREAKGLASS_SESSION_TTL env default). It is
// the only real bound on a leaked or misused card: break-glass sessions are
// never renewed AND cannot be revoked once issued — the stateless model has no
// per-session kill switch, so revoking a code only blocks *new* grants. Keep it
// short so an abused card self-expires quickly.
const maxBreakGlassTTL = 12 * time.Hour

// effectiveSettings resolves the break-glass session TTL, notification email
// recipients, and webhook URL from the admin-saved settings, falling back to the
// environment defaults when nothing has been saved. The resolved TTL is clamped
// to maxBreakGlassTTL on every path (env or DB), so no configuration can mint a
// longer-lived emergency session than the model allows.
func (s *Server) effectiveSettings(ctx context.Context) (ttl time.Duration, notifyEmails []string, webhookURL string) {
	defer func() {
		if ttl > maxBreakGlassTTL {
			ttl = maxBreakGlassTTL
		}
	}()
	ttl = s.cfg.BreakGlassSessionTTL
	notifyEmails = s.cfg.BreakGlassNotifyEmails
	webhookURL = s.cfg.BreakGlassWebhookURL

	as, err := s.store.GetAppSettings(ctx)
	if err != nil {
		log.Printf("load app settings: %v", err)
		return
	}
	if !as.Exists {
		return
	}
	// Once saved, the DB row fully governs (an empty value means "disabled").
	if as.BreakGlassSecs > 0 {
		ttl = time.Duration(as.BreakGlassSecs) * time.Second
	}
	notifyEmails = splitEmails(as.NotifyEmails)
	webhookURL = trimField(as.WebhookURL)
	return
}

// splitEmails parses a comma/space/newline-separated email list, normalised.
func splitEmails(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == ';'
	}) {
		if e := normalizeEmail(f); e != "" {
			out = append(out, e)
		}
	}
	return out
}

// --- Branding admin page ---

func (s *Server) handleAdminBranding(w http.ResponseWriter, r *http.Request) {
	b, _, err := s.store.GetBranding(r.Context())
	if err != nil {
		s.adminError(w, r)
		return
	}
	def := s.resolvedBranding(r.Context())
	pal := breakglass.DefaultPalette
	s.renderAdmin(w, r, http.StatusOK, "admin_branding", adminData{
		Title: "Branding",
		Branding: brandingView{
			Title:        b.Title,
			Body:         b.Body,
			Instructions: b.Instructions,
			Placeholder:  def,
			HasLogo:      len(b.Logo) > 0,
			HasPDFLogo:   len(b.PDFLogo) > 0,
			HasGlyph:     len(b.Glyph) > 0,
			HeaderColor:  orFallback(b.HeaderColor, pal.Header),
			AccentColor:  orFallback(b.AccentColor, pal.Accent),
			Bar1Color:    orFallback(b.Bar1Color, pal.Bar1),
			Bar2Color:    orFallback(b.Bar2Color, pal.Bar2),
			Bar3Color:    orFallback(b.Bar3Color, pal.Bar3),
		},
	})
}

func (s *Server) handleAdminSaveBranding(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBrandingUpload+64<<10)
	if err := r.ParseMultipartForm(maxBrandingUpload); err != nil {
		s.renderAdmin(w, r, http.StatusRequestEntityTooLarge, "admin_message", adminData{
			Title: "Upload too large", Message: "Logo and glyph uploads must be under 2 MB.",
		})
		return
	}
	if !s.checkCSRF(w, r) {
		return
	}
	if err := s.store.SaveBrandingText(r.Context(),
		trimField(r.PostFormValue("title")),
		trimField(r.PostFormValue("body")),
		trimField(r.PostFormValue("instructions"))); err != nil {
		s.adminError(w, r)
		return
	}
	pal := breakglass.DefaultPalette
	if err := s.store.SaveBrandingColors(r.Context(),
		hexOrDefault(r.PostFormValue("header_color"), pal.Header),
		hexOrDefault(r.PostFormValue("accent_color"), pal.Accent),
		hexOrDefault(r.PostFormValue("bar1_color"), pal.Bar1),
		hexOrDefault(r.PostFormValue("bar2_color"), pal.Bar2),
		hexOrDefault(r.PostFormValue("bar3_color"), pal.Bar3)); err != nil {
		s.adminError(w, r)
		return
	}
	if err := s.applyImageField(r, store.BrandingLogo, "logo"); err != nil {
		s.brandingUploadError(w, r)
		return
	}
	if err := s.applyImageField(r, store.BrandingPDFLogo, "pdflogo"); err != nil {
		s.brandingUploadError(w, r)
		return
	}
	if err := s.applyImageField(r, store.BrandingGlyph, "glyph"); err != nil {
		s.brandingUploadError(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionBrandingUpdate, "global", "")
	http.Redirect(w, r, "/admin/branding", http.StatusFound)
}

// applyImageField stores an uploaded global-branding image, or clears it when
// the matching remove checkbox is ticked. A missing file with no remove flag is
// a no-op.
func (s *Server) applyImageField(r *http.Request, which store.BrandingImage, field string) error {
	if r.PostFormValue("remove_"+field) != "" {
		return s.store.ClearBrandingImage(r.Context(), which)
	}
	data, mime, present, err := readUploadedImage(r, field)
	if err != nil || !present {
		return err
	}
	return s.store.SetBrandingImage(r.Context(), which, data, mime)
}

// applyCodeImageField is applyImageField for a single code's override image.
func (s *Server) applyCodeImageField(r *http.Request, codeID int64, which store.BrandingImage, field string) error {
	if r.PostFormValue("remove_"+field) != "" {
		return s.store.ClearCodeBrandingImage(r.Context(), codeID, which)
	}
	data, mime, present, err := readUploadedImage(r, field)
	if err != nil || !present {
		return err
	}
	return s.store.SetCodeBrandingImage(r.Context(), codeID, which, data, mime)
}

// readUploadedImage reads and validates an uploaded image from a multipart
// field. present is false (with nil error) when no file was supplied.
func readUploadedImage(r *http.Request, field string) (data []byte, mime string, present bool, err error) {
	file, hdr, err := r.FormFile(field)
	if err != nil {
		return nil, "", false, nil // no file uploaded
	}
	defer file.Close()
	data = make([]byte, 0, hdr.Size)
	buf := make([]byte, 32<<10)
	for {
		n, rerr := file.Read(buf)
		data = append(data, buf[:n]...)
		if rerr != nil {
			break
		}
		if len(data) > maxBrandingUpload {
			return nil, "", false, errUploadTooLarge
		}
	}
	mime = hdr.Header.Get("Content-Type")
	kind := breakglass.ImageKind(data, mime)
	if kind == "" {
		return nil, "", false, errUnsupportedImage
	}
	if mime == "" || mime == "application/octet-stream" {
		mime = "image/" + kind
	}
	return data, mime, true, nil
}

var (
	errUploadTooLarge   = &uploadErr{"too large"}
	errUnsupportedImage = &uploadErr{"unsupported type"}
)

type uploadErr struct{ msg string }

func (e *uploadErr) Error() string { return e.msg }

func (s *Server) brandingUploadError(w http.ResponseWriter, r *http.Request) {
	s.renderAdmin(w, r, http.StatusBadRequest, "admin_message", adminData{
		Title:   "Could not save image",
		Message: "Logos and glyphs must be PNG, JPEG, or SVG and under 2 MB.",
	})
}

// --- Runtime settings (break-glass TTL + notifications) ---

func (s *Server) handleAdminSettings(w http.ResponseWriter, r *http.Request) {
	ttl, emails, webhook := s.effectiveSettings(r.Context())
	s.renderAdmin(w, r, http.StatusOK, "admin_settings", adminData{
		Title: "Settings",
		Settings: settingsView{
			BreakGlassHours: strconv.FormatFloat(ttl.Hours(), 'g', -1, 64),
			NotifyEmails:    strings.Join(emails, ", "),
			WebhookURL:      webhook,
			WebhookTimeout:  s.cfg.BreakGlassWebhookTimeout.String(),
		},
	})
}

func (s *Server) handleAdminSaveSettings(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	hours, err := strconv.ParseFloat(trimField(r.PostFormValue("hours")), 64)
	if err != nil || hours <= 0 || hours > maxBreakGlassTTL.Hours() {
		s.settingsError(w, r, "Session duration must be a number of hours between 0 and 12.")
		return
	}
	emails := splitEmails(r.PostFormValue("emails"))
	for _, e := range emails {
		if !validEmail(e) {
			s.settingsError(w, r, "One of the notification emails is not a valid address.")
			return
		}
	}
	webhook := trimField(r.PostFormValue("webhook"))
	if webhook != "" {
		u, err := url.Parse(webhook)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			s.settingsError(w, r, "The webhook URL must be an absolute http(s) URL, or left blank.")
			return
		}
		// Block the SSRF vector a compromised admin could point the notification
		// POST at: cloud metadata (link-local 169.254/16, fe80::/10) and loopback.
		// Private ranges (10/8, 192.168/16, 172.16/12) are intentionally allowed —
		// notifications legitimately target internal services on this stack.
		if ip := net.ParseIP(u.Hostname()); ip != nil && (ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()) {
			s.settingsError(w, r, "The webhook host may not be a loopback or link-local address.")
			return
		}
	}
	secs := int(hours * 3600)
	if err := s.store.SaveAppSettings(r.Context(), secs, strings.Join(emails, ","), webhook); err != nil {
		s.adminError(w, r)
		return
	}
	// Record whether a webhook is set, not the URL itself (it may carry a token).
	s.auditAdmin(r, store.AdminActionSettingsUpdate, "break_glass",
		fmt.Sprintf("ttl=%gh notify_emails=%d webhook=%t", hours, len(emails), webhook != ""))
	http.Redirect(w, r, "/admin/settings", http.StatusFound)
}

func (s *Server) settingsError(w http.ResponseWriter, r *http.Request, msg string) {
	s.renderAdmin(w, r, http.StatusBadRequest, "admin_message", adminData{
		Title: "Could not save settings", Message: msg,
	})
}

// handleAdminBrandingImage serves the stored logo or glyph for preview.
func (s *Server) handleAdminBrandingImage(w http.ResponseWriter, r *http.Request) {
	b, ok, err := s.store.GetBranding(r.Context())
	if err != nil {
		s.adminError(w, r)
		return
	}
	var data []byte
	var mime string
	switch r.PathValue("which") {
	case "logo":
		data, mime = b.Logo, b.LogoType
	case "pdflogo":
		data, mime = b.PDFLogo, b.PDFLogoType
	case "glyph":
		data, mime = b.Glyph, b.GlyphType
	default:
		http.NotFound(w, r)
		return
	}
	if !ok || len(data) == 0 {
		http.NotFound(w, r)
		return
	}
	writeImage(w, mime, data)
}

// requireAdmin gates the admin subtree: a valid session whose groups include
// "admin". When TOTP is enabled, an admin session already implies TOTP was
// satisfied at login. Non-admins are sent to the login flow.
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.sessions.ReadSession(r, s.now())
		// A break-glass session must never reach the admin UI, even if its
		// target group is somehow "admin": the admin tier requires a real login
		// (and TOTP when enabled), not a bearer QR scan.
		admin := ok && id.Kind != session.KindBreakGlass && authz.HasGroup(id.Groups, authz.RoleAdmin)
		// A first-factor-only admin session (minted before TOTP was enabled) is
		// bounced to a fresh login so the TOTP step runs, rather than being
		// honoured here. needsAdminStepUp is only evaluated once admin is true, so
		// id is non-nil. See handleVerify for the same enforcement on /verify.
		if !admin || s.needsAdminStepUp(admin, id.TOTP) {
			rd := s.cfg.PublicURL + r.URL.RequestURI()
			http.Redirect(w, r, s.cfg.PublicURL+"/login?rd="+url.QueryEscape(rd), http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// csrfTTL bounds the lifetime of the CSRF cookie.
const csrfTTL = 12 * time.Hour

// checkCSRF verifies the submitted token; on failure it writes a 403 and
// returns false.
func (s *Server) checkCSRF(w http.ResponseWriter, r *http.Request) bool {
	if !s.sessions.VerifyCSRF(r, r.PostFormValue("csrf")) {
		s.renderAdmin(w, r, http.StatusForbidden, "admin_message", adminData{
			Title: "Request rejected", Message: "Invalid or expired form token. Please try again.",
		})
		return false
	}
	return true
}

// auditAdmin records an attributable administrative action. The actor is taken
// from the already-validated admin session (this only runs behind requireAdmin).
// Best-effort: a write failure is logged but does not undo the action that has
// already happened. Call it AFTER the mutation succeeds.
func (s *Server) auditAdmin(r *http.Request, action, target, detail string) {
	actor := ""
	if id, ok := s.sessions.ReadSession(r, s.now()); ok {
		actor = id.Email
	}
	if err := s.store.RecordAdminEvent(r.Context(), store.AdminEvent{
		Actor:     actor,
		Action:    action,
		Target:    target,
		Detail:    detail,
		ClientIP:  clientIP(r),
		UserAgent: clampUserAgent(r.UserAgent()),
		CreatedAt: s.now(),
	}); err != nil {
		log.Printf("record admin event %s (actor=%s target=%q): %v", action, actor, target, err)
	}
}

// --- Home ---

func (s *Server) handleAdminHome(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/admin/break", http.StatusFound)
}

// --- Login & access audit ---

// handleAdminAccess shows the login-attempt log and the deduplicated app-access
// log, optionally filtered to one email. It answers "did X get in, and which
// apps has X reached, when" — without exposing per-request paths.
func (s *Server) handleAdminAccess(w http.ResponseWriter, r *http.Request) {
	email := normalizeEmail(r.URL.Query().Get("email"))
	const limit = 250
	logins, err := s.store.ListAuthEvents(r.Context(), email, limit, 0)
	if err != nil {
		s.adminError(w, r)
		return
	}
	access, err := s.store.ListAppAccess(r.Context(), email, limit, 0)
	if err != nil {
		s.adminError(w, r)
		return
	}
	s.renderAdmin(w, r, http.StatusOK, "admin_access", adminData{
		Title:       "Access log",
		FilterEmail: email,
		AuthEvents:  s.toAuthEventViews(logins),
		AppAccess:   s.toAppAccessViews(access),
	})
}

// handleAdminAudit shows the administrative-action audit trail: which admin
// minted/revoked a break-glass code, changed groups, removed another admin's
// 2FA, or edited settings — the attributable record of privileged mutations.
func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	const limit = 250
	events, err := s.store.ListAdminEvents(r.Context(), limit, 0)
	if err != nil {
		s.adminError(w, r)
		return
	}
	s.renderAdmin(w, r, http.StatusOK, "admin_audit", adminData{
		Title:       "Admin audit",
		AdminEvents: s.toAdminEventViews(events),
	})
}

// --- Groups ---

func (s *Server) handleAdminGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.store.ListGroups(r.Context())
	if err != nil {
		s.adminError(w, r)
		return
	}
	view := make([]groupView, 0, len(groups))
	for _, g := range groups {
		members, err := s.store.ListGroupMembers(r.Context(), g.Name)
		if err != nil {
			s.adminError(w, r)
			return
		}
		view = append(view, groupView{Name: g.Name, Label: g.Label, Members: members})
	}
	s.renderAdmin(w, r, http.StatusOK, "admin_groups", adminData{Title: "Groups", Groups: view})
}

func (s *Server) handleAdminCreateGroup(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	name := normalizeGroupName(r.PostFormValue("name"))
	if authz.IsReservedGroup(name) {
		s.renderAdmin(w, r, http.StatusBadRequest, "admin_message", adminData{
			Title:   "Reserved group name",
			Message: "The names \"admin\" and \"user\" are reserved roles and cannot be used as group names.",
		})
		return
	}
	if !authz.ValidGroupName(name) {
		s.renderAdmin(w, r, http.StatusBadRequest, "admin_message", adminData{
			Title:   "Invalid group name",
			Message: "Group names may use only lowercase letters, numbers, hyphens, and underscores — no spaces, commas, or other punctuation. Use the label field for a friendly display name.",
		})
		return
	}
	if err := s.store.CreateGroup(r.Context(), name, r.PostFormValue("label")); err != nil {
		s.adminError(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionGroupCreate, name, "")
	http.Redirect(w, r, "/admin/groups", http.StatusFound)
}

func (s *Server) handleAdminDeleteGroup(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	if err := s.store.DeleteGroup(r.Context(), r.PathValue("name")); err != nil {
		s.adminError(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionGroupDelete, r.PathValue("name"), "")
	http.Redirect(w, r, "/admin/groups", http.StatusFound)
}

func (s *Server) handleAdminAddMember(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	group := r.PathValue("name")
	emailAddr := normalizeEmail(r.PostFormValue("email"))
	if validEmail(emailAddr) {
		if err := s.store.AddGroupMember(r.Context(), group, emailAddr); err != nil {
			s.adminError(w, r)
			return
		}
		s.auditAdmin(r, store.AdminActionGroupAddMember, group, emailAddr)
	}
	http.Redirect(w, r, "/admin/groups", http.StatusFound)
}

func (s *Server) handleAdminRemoveMember(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	group := r.PathValue("name")
	emailAddr := normalizeEmail(r.PostFormValue("email"))
	if err := s.store.RemoveGroupMember(r.Context(), group, emailAddr); err != nil {
		s.adminError(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionGroupRemoveMember, group, emailAddr)
	http.Redirect(w, r, "/admin/groups", http.StatusFound)
}

// --- Break-glass codes ---

func (s *Server) handleAdminBreakList(w http.ResponseWriter, r *http.Request) {
	codes, err := s.store.ListBreakGlassCodes(r.Context())
	if err != nil {
		s.adminError(w, r)
		return
	}
	view := make([]codeView, 0, len(codes))
	for _, c := range codes {
		view = append(view, s.toCodeView(c))
	}
	s.renderAdmin(w, r, http.StatusOK, "admin_codes", adminData{Title: "Break-glass codes", Codes: view})
}

func (s *Server) handleAdminBreakCreate(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	label := trimField(r.PostFormValue("label"))
	group := normalizeGroupName(r.PostFormValue("group"))
	if label == "" || group == "" {
		s.renderAdmin(w, r, http.StatusBadRequest, "admin_message", adminData{
			Title: "Missing fields", Message: "A label and a target group are both required.",
		})
		return
	}
	if authz.IsReservedGroup(group) {
		s.renderAdmin(w, r, http.StatusBadRequest, "admin_message", adminData{
			Title:   "Reserved target group",
			Message: "A break-glass code cannot target the reserved roles \"admin\" or \"user\". Use a dedicated group instead.",
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
	tokenEnc, tokenHash, err := s.newToken()
	if err != nil {
		s.adminError(w, r)
		return
	}
	rd := authz.SafeRedirect(trimField(r.PostFormValue("redirect")), s.cfg.Domain, "")
	_, err = s.store.CreateBreakGlassCode(r.Context(), store.BreakGlassCode{
		Label:       label,
		Note:        trimField(r.PostFormValue("note")),
		TargetGroup: group,
		TokenEnc:    tokenEnc,
		TokenHash:   tokenHash,
		Redirect:    rd,
	})
	if err != nil {
		// Most likely a duplicate label (UNIQUE constraint).
		s.renderAdmin(w, r, http.StatusConflict, "admin_message", adminData{
			Title: "Could not create code", Message: "A code with that label already exists. Labels must be unique.",
		})
		return
	}
	s.auditAdmin(r, store.AdminActionBreakCreate, label, "group="+group)
	http.Redirect(w, r, "/admin/break", http.StatusFound)
}

func (s *Server) handleAdminBreakDetail(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	code, found, err := s.store.GetBreakGlassCode(r.Context(), id)
	if err != nil {
		s.adminError(w, r)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	events, err := s.store.ListBreakGlassEvents(r.Context(), id, 100, 0)
	if err != nil {
		s.adminError(w, r)
		return
	}
	s.renderAdmin(w, r, http.StatusOK, "admin_code_detail", adminData{
		Title: code.Label, Code: s.toCodeView(code), Events: events,
		CodeBranding: s.codeBrandingView(r.Context(), id),
	})
}

// codeBrandingView builds the per-code customisation form data: the override
// values, the inherited (global) values shown as placeholders, and the
// effective colours used to prefill the pickers.
func (s *Server) codeBrandingView(ctx context.Context, codeID int64) codeBrandingView {
	ov, err := s.store.GetCodeBranding(ctx, codeID)
	if err != nil {
		log.Printf("code branding %d: %v", codeID, err)
	}
	global := s.resolvedBranding(ctx)
	eff := s.effectiveCardBranding(ctx, codeID)
	pal := breakglass.DefaultPalette
	return codeBrandingView{
		Title:        ov.Title,
		Body:         ov.Body,
		Instructions: ov.Instructions,
		InhTitle:     global.Title,
		InhBody:      global.Body,
		InhInstr:     global.Instructions,
		CustomColors: trimField(ov.HeaderColor) != "" || trimField(ov.AccentColor) != "" ||
			trimField(ov.Bar1Color) != "" || trimField(ov.Bar2Color) != "" || trimField(ov.Bar3Color) != "",
		HeaderColor: orFallback(eff.HeaderColor, pal.Header),
		AccentColor: orFallback(eff.AccentColor, pal.Accent),
		Bar1Color:   orFallback(eff.Bar1Color, pal.Bar1),
		Bar2Color:   orFallback(eff.Bar2Color, pal.Bar2),
		Bar3Color:   orFallback(eff.Bar3Color, pal.Bar3),
		HasLogo:     len(ov.Logo) > 0,
		HasGlyph:    len(ov.Glyph) > 0,
	}
}

// handleAdminSaveCodeBranding stores a code's per-code branding overrides.
func (s *Server) handleAdminSaveCodeBranding(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBrandingUpload+64<<10)
	if err := r.ParseMultipartForm(maxBrandingUpload); err != nil {
		s.renderAdmin(w, r, http.StatusRequestEntityTooLarge, "admin_message", adminData{
			Title: "Upload too large", Message: "Logo and glyph uploads must be under 2 MB.",
		})
		return
	}
	if !s.checkCSRF(w, r) {
		return
	}
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	// Colours only apply when the admin opts in; otherwise they inherit (empty).
	var header, accent, bar1, bar2, bar3 string
	if r.PostFormValue("custom_colors") != "" {
		header = hexOrDefault(r.PostFormValue("header_color"), breakglass.DefaultPalette.Header)
		accent = hexOrDefault(r.PostFormValue("accent_color"), breakglass.DefaultPalette.Accent)
		bar1 = hexOrDefault(r.PostFormValue("bar1_color"), breakglass.DefaultPalette.Bar1)
		bar2 = hexOrDefault(r.PostFormValue("bar2_color"), breakglass.DefaultPalette.Bar2)
		bar3 = hexOrDefault(r.PostFormValue("bar3_color"), breakglass.DefaultPalette.Bar3)
	}
	if err := s.store.SaveCodeBrandingMeta(r.Context(), id,
		trimField(r.PostFormValue("title")),
		trimField(r.PostFormValue("body")),
		trimField(r.PostFormValue("instructions")),
		header, accent, bar1, bar2, bar3); err != nil {
		s.adminError(w, r)
		return
	}
	if err := s.applyCodeImageField(r, id, store.BrandingLogo, "logo"); err != nil {
		s.brandingUploadError(w, r)
		return
	}
	if err := s.applyCodeImageField(r, id, store.BrandingGlyph, "glyph"); err != nil {
		s.brandingUploadError(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionCodeBranding, "code#"+strconv.FormatInt(id, 10), "")
	http.Redirect(w, r, "/admin/break/"+strconv.FormatInt(id, 10), http.StatusFound)
}

// handleAdminCodeBrandingImage serves a code's override logo or glyph preview.
func (s *Server) handleAdminCodeBrandingImage(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	b, err := s.store.GetCodeBranding(r.Context(), id)
	if err != nil {
		s.adminError(w, r)
		return
	}
	var data []byte
	var mime string
	switch r.PathValue("which") {
	case "logo":
		data, mime = b.Logo, b.LogoType
	case "glyph":
		data, mime = b.Glyph, b.GlyphType
	default:
		http.NotFound(w, r)
		return
	}
	if len(data) == 0 {
		http.NotFound(w, r)
		return
	}
	writeImage(w, mime, data)
}

func (s *Server) handleAdminBreakRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := s.store.RevokeBreakGlassCode(r.Context(), id); err != nil {
		s.adminError(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionBreakRevoke, "code#"+strconv.FormatInt(id, 10), "")
	http.Redirect(w, r, "/admin/break/"+strconv.FormatInt(id, 10), http.StatusFound)
}

func (s *Server) handleAdminBreakRemint(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	tokenEnc, tokenHash, err := s.newToken()
	if err != nil {
		s.adminError(w, r)
		return
	}
	if err := s.store.RemintBreakGlassCode(r.Context(), id, tokenEnc, tokenHash); err != nil {
		s.adminError(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionBreakRemint, "code#"+strconv.FormatInt(id, 10), "")
	http.Redirect(w, r, "/admin/break/"+strconv.FormatInt(id, 10), http.StatusFound)
}

func (s *Server) handleAdminBreakQR(w http.ResponseWriter, r *http.Request) {
	png, _, ok := s.codeImage(w, r)
	if !ok {
		return
	}
	writeImage(w, "image/png", png)
}

func (s *Server) handleAdminBreakPDF(w http.ResponseWriter, r *http.Request) {
	png, code, ok := s.codeImage(w, r)
	if !ok {
		return
	}
	b := s.effectiveCardBranding(r.Context(), code.ID)
	card := breakglass.Card{
		Title:        b.Title,
		Label:        code.Label,
		Body:         b.Body,
		Instructions: b.Instructions,
		Note:         code.Note,
		QRPNG:        png,
		LogoData:     b.Logo,
		LogoType:     b.LogoType,
		GlyphData:    b.Glyph,
		GlyphType:    b.GlyphType,
		// Empty colours fall back to the RCH palette inside the renderer.
		HeaderColor: b.HeaderColor,
		AccentColor: b.AccentColor,
		Bar1Color:   b.Bar1Color,
		Bar2Color:   b.Bar2Color,
		Bar3Color:   b.Bar3Color,
	}
	pdf, err := card.PDF()
	if err != nil {
		s.adminError(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="`+pdfFilename(code.Label)+`"`)
	w.Write(pdf)
}

// codeImage loads a code, decrypts its token, and renders the QR PNG of its
// scan URL. Returns ok=false having already written a response on any failure
// (including a revoked code, whose QR is not served).
func (s *Server) codeImage(w http.ResponseWriter, r *http.Request) ([]byte, store.BreakGlassCode, bool) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return nil, store.BreakGlassCode{}, false
	}
	code, found, err := s.store.GetBreakGlassCode(r.Context(), id)
	if err != nil {
		s.adminError(w, r)
		return nil, store.BreakGlassCode{}, false
	}
	if !found {
		http.NotFound(w, r)
		return nil, store.BreakGlassCode{}, false
	}
	// Do not render (QR/PDF) a revoked code: scanning it is denied at /break, and
	// serving its live token as an image would only hand back a dead credential.
	if code.Status != store.BreakGlassActive {
		http.NotFound(w, r)
		return nil, store.BreakGlassCode{}, false
	}
	token, err := s.secrets.Open(code.TokenEnc)
	if err != nil {
		s.adminError(w, r)
		return nil, store.BreakGlassCode{}, false
	}
	// High resolution so the printed PDF (QR at ~76mm) stays crisp (~340 DPI);
	// the on-screen preview just downscales it.
	png, err := breakglass.QRPNG(s.breakURL(token), 1024)
	if err != nil {
		s.adminError(w, r)
		return nil, store.BreakGlassCode{}, false
	}
	return png, code, true
}

// newToken mints a fresh token and returns its ciphertext and lookup hash.
func (s *Server) newToken() (tokenEnc, tokenHash string, err error) {
	token, err := breakglass.GenerateToken()
	if err != nil {
		return "", "", err
	}
	tokenEnc, err = s.secrets.Seal(token)
	if err != nil {
		return "", "", err
	}
	return tokenEnc, otp.Hash(token), nil
}

func (s *Server) breakURL(token string) string {
	return s.cfg.PublicURL + "/break/" + token
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}
