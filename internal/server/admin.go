package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/breakglass"
	"github.com/uppertoe/vps-scaffold-auth/internal/otp"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
	"github.com/uppertoe/vps-scaffold-auth/internal/totp"
)

// adminRoutes registers the admin subtree on its own mux. The whole tree is
// wrapped by requireAdmin in routes(); handlers here can assume an admin caller.
func (s *Server) adminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/{$}", s.handleAdminHome)
	mux.HandleFunc("GET /admin/apps", s.handleAdminApps)
	mux.HandleFunc("GET /admin/apps/{app}", s.handleAdminApp)
	mux.HandleFunc("POST /admin/apps/{app}/review", s.handleAdminAppReview)
	mux.HandleFunc("POST /admin/apps/{app}/edit", s.handleAdminAppEdit)
	mux.HandleFunc("POST /admin/apps/{app}/save", s.handleAdminAppSave)
	mux.HandleFunc("GET /admin/groups", s.handleAdminGroups)
	mux.HandleFunc("GET /admin/groups/new", s.handleAdminNewGroup)
	mux.HandleFunc("POST /admin/groups/{name}/domains", s.handleAdminAddDomain)
	mux.HandleFunc("POST /admin/groups/{name}/domains/delete", s.handleAdminRemoveDomain)
	mux.HandleFunc("POST /admin/groups", s.handleAdminCreateGroup)
	mux.HandleFunc("GET /admin/groups/{name}", s.handleAdminGroup)
	mux.HandleFunc("POST /admin/groups/{name}/delete", s.handleAdminDeleteGroup)
	mux.HandleFunc("POST /admin/groups/{name}/label", s.handleAdminGroupLabel)
	mux.HandleFunc("POST /admin/groups/{name}/members", s.handleAdminAddMember)
	mux.HandleFunc("POST /admin/groups/{name}/members/confirm", s.handleAdminConfirmMembers)
	mux.HandleFunc("POST /admin/groups/{name}/includes", s.handleAdminAddInclude)
	mux.HandleFunc("POST /admin/groups/{name}/sync", s.handleAdminSyncGroup)
	mux.HandleFunc("POST /admin/groups/{name}/keep", s.handleAdminKeepMembers)
	mux.HandleFunc("POST /admin/groups/{name}/includes/delete", s.handleAdminRemoveInclude)
	mux.HandleFunc("POST /admin/groups/{name}/members/delete", s.handleAdminRemoveMember)
	mux.HandleFunc("GET /admin/access", s.handleAdminAccess)
	mux.HandleFunc("GET /admin/audit", s.handleAdminAudit)
	mux.HandleFunc("GET /admin/break", s.handleAdminBreakList)
	mux.HandleFunc("POST /admin/break", s.handleAdminBreakCreate)
	mux.HandleFunc("GET /admin/break/new", s.handleAdminBreakNew)
	mux.HandleFunc("GET /admin/break/preview.svg", s.handleAdminBreakPreview)
	mux.HandleFunc("GET /admin/break/{id}", s.handleAdminBreakDetail)
	mux.HandleFunc("POST /admin/break/{id}/revoke", s.handleAdminBreakRevoke)
	mux.HandleFunc("POST /admin/break/{id}/remint", s.handleAdminBreakRemint)
	mux.HandleFunc("POST /admin/break/{id}/design", s.handleAdminBreakDesign)
	// pdf, qr.png and card.svg (see handleAdminBreakFile).
	mux.HandleFunc("GET /admin/break/{id}/{file}", s.handleAdminBreakFile)
	mux.HandleFunc("GET /admin/break/designs", s.handleAdminDesigns)
	mux.HandleFunc("POST /admin/break/designs", s.handleAdminDesignCreate)
	mux.HandleFunc("GET /admin/break/designs/new", s.handleAdminDesignNew)
	mux.HandleFunc("GET /admin/break/designs/preview.svg", s.handleAdminDesignPreview)
	mux.HandleFunc("GET /admin/break/designs/{id}", s.handleAdminDesign)
	mux.HandleFunc("GET /admin/break/designs/{id}/card.svg", s.handleAdminDesignSVG)
	mux.HandleFunc("POST /admin/break/designs/{id}/save", s.handleAdminDesignSave)
	mux.HandleFunc("POST /admin/break/designs/{id}/delete", s.handleAdminDesignDelete)
	mux.HandleFunc("GET /admin/branding", s.handleAdminBranding)
	mux.HandleFunc("POST /admin/branding", s.handleAdminSaveBranding)
	mux.HandleFunc("GET /admin/branding/{which}/img", s.handleAdminBrandingImage)
	mux.HandleFunc("GET /admin/settings", s.handleAdminSettings)
	mux.HandleFunc("POST /admin/settings", s.handleAdminSaveSettings)
	mux.HandleFunc("GET /admin/totp", s.handleAdminTOTP)
	mux.HandleFunc("POST /admin/totp/generate", s.handleAdminTOTPGenerate)
	mux.HandleFunc("POST /admin/totp/remove", s.handleAdminTOTPRemove)
	mux.HandleFunc("POST /admin/passkeys/remove", s.handleAdminRemovePasskeys)
	mux.HandleFunc("POST /admin/sessions/end", s.handleAdminEndSessions)
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
	_, replacing, err := s.store.GetTOTPSecret(r.Context(), emailAddr)
	if err != nil {
		s.adminError(w, r)
		return
	}
	if err := s.setTOTPSecret(r.Context(), emailAddr, en.Secret); err != nil {
		s.adminError(w, r)
		return
	}
	// A secret is replaced when the old authenticator is lost or may be in
	// someone else's hands: every session it passed ends now.
	if replacing {
		if err := s.endSessions(r.Context(), emailAddr, s.now()); err != nil {
			s.adminError(w, r)
			return
		}
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
	// The authenticator may be lost or in someone else's hands: every
	// session it passed ends now.
	if err := s.endSessions(r.Context(), emailAddr, s.now()); err != nil {
		s.adminError(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionTOTPRemove, emailAddr, "")
	http.Redirect(w, r, "/admin/totp", http.StatusFound)
}

// handleAdminEndSessions signs a person out on every device: every session
// they have, wherever it is, ends at its next request.
func (s *Server) handleAdminEndSessions(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	emailAddr := normalizeEmail(r.PostFormValue("email"))
	if !plainAddress(emailAddr) {
		http.Redirect(w, r, "/admin/access", http.StatusFound)
		return
	}
	if err := s.endSessions(r.Context(), emailAddr, s.now()); err != nil {
		s.adminError(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionSessionsEnd, emailAddr, "")
	http.Redirect(w, r, "/admin/access?email="+url.QueryEscape(emailAddr)+"&sessions_ended=1", http.StatusFound)
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

// maxBrandingUpload caps logo upload size.
const maxBrandingUpload = 2 << 20 // 2 MiB

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

// --- The site logo ---

// handleAdminBranding sends the old branding page to Settings, where the site
// logo is now set. The card's colours, wording and logo are set by card
// designs (admin_designs.go).
func (s *Server) handleAdminBranding(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/admin/settings#logo", http.StatusSeeOther)
}

// handleAdminSaveBranding stores or removes the site logo, which the sign-in
// pages, the favicon and cards whose design uses the site logo all show.
func (s *Server) handleAdminSaveBranding(w http.ResponseWriter, r *http.Request) {
	allowSlowUpload(w)
	// Whatever this request changes, the sign-in pages and emails read the
	// branding afresh.
	defer s.forgetBranding()
	r.Body = http.MaxBytesReader(w, r.Body, maxBrandingUpload+64<<10)
	if err := r.ParseMultipartForm(maxBrandingUpload); err != nil {
		s.renderAdmin(w, r, http.StatusRequestEntityTooLarge, "admin_message", adminData{
			Title: "Upload too large", Message: "The images in one upload must total less than 2 MB.",
		})
		return
	}
	if !s.checkCSRF(w, r) {
		return
	}
	if err := s.applyImageField(r, store.BrandingLogo, "logo"); err != nil {
		s.brandingUploadError(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionBrandingUpdate, "global", "site logo")
	s.redirectDone(w, r, "/admin/settings", "branding-saved", "")
}

// allowSlowUpload gives an admin's branding upload two minutes to arrive. The
// server's 15-second read and write timeouts would otherwise cut off a 2 MB
// upload on a link slower than about 1 Mbit/s: the write deadline also runs
// from when the request began, so it is extended past the read deadline or
// the admin would see an error after the upload had in fact been saved. Only
// admin routes call it, after requireAdmin, so an anonymous client cannot use
// it to hold connections open.
func allowSlowUpload(w http.ResponseWriter) {
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(2 * time.Minute))
	_ = rc.SetWriteDeadline(time.Now().Add(2*time.Minute + 15*time.Second))
}

// validateImageFields checks each named upload (one being removed is skipped)
// without storing anything.
func validateImageFields(r *http.Request, fields ...string) error {
	for _, f := range fields {
		if r.PostFormValue("remove_"+f) != "" {
			continue
		}
		if _, _, _, err := readUploadedImage(r, f); err != nil {
			return err
		}
	}
	return nil
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
	// The stored type follows what the bytes are, not what the browser said,
	// so /logo.img always serves the right Content-Type.
	mime = map[string]string{"png": "image/png", "jpeg": "image/jpeg", "svg": "image/svg+xml"}[kind]
	// Raster images are checked for dimensions and bit depth before they are
	// stored (see breakglass.CheckRaster).
	if kind == "svg" {
		if err := breakglass.CheckSVG(data); err != nil {
			return nil, "", false, errUnsupportedImage
		}
	} else {
		if err := breakglass.CheckRaster(data); errors.Is(err, breakglass.ErrImageTooLarge) {
			return nil, "", false, errImageTooLarge
		} else if err != nil {
			return nil, "", false, errUnsupportedImage
		}
	}
	// A PNG is stored as Go re-encoded it, so the stored bytes never carry
	// chunks that the PDF library would read differently (see
	// breakglass.CanonicalPNG).
	if kind == "png" {
		canon, err := breakglass.CanonicalPNG(data)
		if err != nil {
			return nil, "", false, errUnsupportedImage
		}
		data, mime = canon, "image/png"
	}
	return data, mime, true, nil
}

var (
	errUploadTooLarge   = &uploadErr{"too large"}
	errUnsupportedImage = &uploadErr{"unsupported type"}
	errImageTooLarge    = &uploadErr{"dimensions too large"}
)

type uploadErr struct{ msg string }

func (e *uploadErr) Error() string { return e.msg }

func (s *Server) brandingUploadError(w http.ResponseWriter, r *http.Request) {
	s.renderAdmin(w, r, http.StatusBadRequest, "admin_message", adminData{
		Title:   "Could not save image",
		Message: "Logos and glyphs must be PNG, JPEG or SVG files under 2 MB, and no more than 1,000 pixels wide or high.",
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
			HasLogo:         s.hasSiteLogo(r.Context()),
		},
	})
}

func (s *Server) hasSiteLogo(ctx context.Context) bool {
	logo, _, _, err := s.siteLogo(ctx)
	return err == nil && len(logo) > 0
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
		// The notifier re-checks the RESOLVED address at connection time (and
		// follows no redirects), so a hostname pointing at one of these is
		// refused there; this literal check only gives the admin an early answer.
		if ip := net.ParseIP(u.Hostname()); ip != nil && (ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()) {
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
	s.redirectDone(w, r, "/admin/settings", "settings-saved", "")
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

// requireAdmin gates the admin subtree: a normal session of a current
// administrator that holds the admin tier, which with TOTP enabled means a
// second step within adminStepMaxAge. Non-admins are sent to the login flow;
// an administrator without a recent second step is sent to the admin door.
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.readSession(r, s.now())
		// A break-glass or guest session must never reach the admin UI, even if
		// its groups somehow include "admin": the admin tier requires a real
		// login (and TOTP when enabled), not a bearer QR scan or a stranger's
		// sign-in. isAdminSession admits only the normal session kind.
		// The cookie's groups were true when it was minted; the admin UI never
		// passes through /verify, where renewal re-checks policy, so an admin
		// removed from ADMIN_EMAILS would otherwise keep this door until the
		// cookie expired. Re-check the current policy on every admin request.
		// A session started with a passkey that has since been removed is
		// refused here at once, since the admin pages never pass through the
		// renewal in /verify that would otherwise end it.
		admin := ok && id.Kind == "" && s.policy.Role(id.Email) == authz.RoleAdmin && s.passkeyStillValid(r, id)
		rd := s.cfg.PublicURL + r.URL.RequestURI()
		if !admin {
			http.Redirect(w, r, s.cfg.PublicURL+"/login?rd="+url.QueryEscape(rd), http.StatusFound)
			return
		}
		// An administrator holds the admin pages only with a recent second step
		// (adminTierHeld); without one they are sent to the admin door, which
		// brings them back here.
		// A session whose step is recent but whose groups predate a promotion
		// (or, with TOTP off, any promoted administrator) is renewed here, so
		// the admin group is added rather than the door asking for a step
		// that has already been taken.
		if !s.adminTierHeld(id) && s.adminStepFresh(id) {
			if !s.renewSession(w, r, id, s.now()) {
				return
			}
		}
		if !s.adminTierHeld(id) {
			http.Redirect(w, r, s.stepUpURL(rd), http.StatusFound)
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
	if !s.sessions.VerifyCSRF(r, r.PostFormValue("csrf"), s.now()) {
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
	// The raw read, not readSession: requireAdmin has already admitted this
	// request, and an administrator who has just ended their own sessions
	// (replacing their authenticator, say) must still be named as the actor.
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

// handleAdminHome is the overview: what needs an administrator's attention,
// and a count of what the gateway holds.
func (s *Server) handleAdminHome(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	groups, err := s.store.ListGroups(ctx)
	if err != nil {
		s.adminError(w, r)
		return
	}
	codes, err := s.store.ListBreakGlassCodes(ctx)
	if err != nil {
		s.adminError(w, r)
		return
	}
	ov := &overviewView{Apps: len(s.appRoles.Apps), Groups: len(groups), TOTPEnabled: s.cfg.TOTPEnabled}
	cardTargets := map[string]bool{}
	for _, c := range codes {
		cardTargets[normalizeGroupName(c.TargetGroup)] = true
		if c.Status == "active" {
			ov.ActiveCards++
		}
	}
	routeGroups, routeGroupsOn := s.routeGroups()
	ov.RouteGroupsOn = routeGroupsOn
	includes, err := s.store.ListGroupIncludes(ctx)
	if err != nil {
		s.adminError(w, r)
		return
	}
	includedSomewhere := map[string]bool{}
	for _, incs := range includes {
		for _, i := range incs {
			includedSomewhere[i] = true
		}
	}
	existing := map[string]bool{}
	for _, g := range groups {
		existing[g.Name] = true
		members, err := s.store.ListGroupMembers(ctx, g.Name)
		if err != nil {
			s.adminError(w, r)
			return
		}
		ov.Members += len(members)
		if routeGroupsOn && len(routeGroups[g.Name]) == 0 && !cardTargets[g.Name] && !includedSomewhere[g.Name] {
			ov.UnusedGroups = append(ov.UnusedGroups, g.Name)
		}
	}
	for name := range routeGroups {
		if !existing[name] && !cardTargets[name] {
			ov.MissingGroups = append(ov.MissingGroups, name)
		}
	}
	sort.Strings(ov.MissingGroups)
	if states, err := s.store.ListGroupSyncStates(ctx); err == nil {
		for g := range s.feeds.feeds {
			if st, ok := states[g]; ok && st.Status != store.GroupSyncOK {
				ov.FeedProblems = append(ov.FeedProblems, g)
			}
		}
		sort.Strings(ov.FeedProblems)
	}
	for g := range s.feeds.feeds {
		if len(includes[g]) > 0 {
			ov.FeedIncludes = append(ov.FeedIncludes, g)
		}
	}
	sort.Strings(ov.FeedIncludes)
	if s.cfg.TOTPEnabled {
		for _, a := range s.totpAdminViews(ctx) {
			if !a.Enrolled {
				ov.AdminsWithoutTOTP = append(ov.AdminsWithoutTOTP, a.Email)
			}
		}
	}
	ov.Sites = s.routeAccess()
	s.renderAdmin(w, r, http.StatusOK, "admin_home", adminData{Title: "Overview", Overview: ov})
}

// --- Login & access audit ---

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

// handleAdminGroups lists the groups. A link from before groups had their own
// pages (?open=name) goes to that group's page.
func (s *Server) handleAdminGroups(w http.ResponseWriter, r *http.Request) {
	view, missing, routeGroupsOn, err := s.groupViews(r)
	if err == nil {
		err = s.fillGroupRoles(r, view)
	}
	if err != nil {
		s.adminError(w, r)
		return
	}
	if open := normalizeGroupName(r.URL.Query().Get("open")); open != "" {
		for _, g := range view {
			if g.Name == open {
				http.Redirect(w, r, "/admin/groups/"+open, http.StatusFound)
				return
			}
		}
	}
	s.renderAdmin(w, r, http.StatusOK, "admin_groups", adminData{
		Title: "Groups", Groups: view,
		MissingGroups: missing, RouteGroupsOn: routeGroupsOn,
	})
}

// handleAdminGroup shows one group: its source, members, includes and label,
// or a domain group's domains, and the app roles it holds.
func (s *Server) handleAdminGroup(w http.ResponseWriter, r *http.Request) {
	s.renderGroup(w, r, http.StatusOK, normalizeGroupName(r.PathValue("name")), "")
}

// groupViews builds every group's view, the groups the routes require that
// do not exist, and whether the route manifest was read.
func (s *Server) groupViews(r *http.Request) ([]groupView, []missingGroupView, bool, error) {
	groups, err := s.store.ListGroups(r.Context())
	if err != nil {
		return nil, nil, false, err
	}
	routeGroups, routeGroupsOn := s.routeGroups()
	cardTargets := map[string]bool{}
	if routeGroupsOn {
		codes, err := s.store.ListBreakGlassCodes(r.Context())
		if err != nil {
			return nil, nil, false, err
		}
		for _, c := range codes {
			cardTargets[normalizeGroupName(c.TargetGroup)] = true
		}
	}
	includes, err := s.store.ListGroupIncludes(r.Context())
	if err != nil {
		return nil, nil, false, err
	}
	syncStates, err := s.store.ListGroupSyncStates(r.Context())
	if err != nil {
		return nil, nil, false, err
	}
	includedIn := map[string][]string{}
	for g, incs := range includes {
		for _, inc := range incs {
			includedIn[inc] = append(includedIn[inc], g)
		}
	}
	existing := make(map[string]bool, len(groups))
	view := make([]groupView, 0, len(groups))
	for _, g := range groups {
		existing[g.Name] = true
		members, err := s.store.ListGroupMembers(r.Context(), g.Name)
		if err != nil {
			return nil, nil, false, err
		}
		var addedFrom map[string]string
		if _, fed := s.feedFor(g.Name); fed {
			addedFrom = syncStates[g.Name].AddedFrom
		}
		mv := make([]memberView, 0, len(members))
		for _, m := range members {
			mv = append(mv, memberView{Email: m, Permitted: s.policy.Allowed(m), AddedFrom: addedFrom[m]})
		}
		hosts := routeGroups[g.Name]
		inc := map[string]bool{}
		for _, i := range includes[g.Name] {
			inc[i] = true
		}
		var options []string
		for _, o := range groups {
			if o.Name != g.Name && !inc[o.Name] {
				options = append(options, o.Name)
			}
		}
		sort.Strings(includedIn[g.Name])
		view = append(view, groupView{
			Feed: s.feedViewFor(g.Name, syncStates),
			Name: g.Name, Label: g.Label, Members: mv,
			Hosts:          hosts,
			Unused:         routeGroupsOn && len(hosts) == 0 && !cardTargets[g.Name] && len(includedIn[g.Name]) == 0,
			Includes:       includes[g.Name],
			IncludedIn:     includedIn[g.Name],
			IncludeOptions: options,
		})
	}
	// A feed-filled group whose feed has never answered has no group row yet
	// (the sync creates the row once the feed has answered), but it may have a
	// sync state saying why. List it anyway, with that state and the "Sync
	// now" button, so a failed first fetch can be seen and retried here and
	// not only reported on the overview.
	unsynced := make([]string, 0)
	for g := range s.feeds.feeds {
		if !existing[g] {
			unsynced = append(unsynced, g)
		}
	}
	sort.Strings(unsynced)
	for _, g := range unsynced {
		view = append(view, groupView{
			Feed: s.feedViewFor(g, syncStates), NotYetCreated: true,
			Name: g, Members: []memberView{}, Hosts: routeGroups[g],
		})
		existing[g] = true
	}
	missing := make([]missingGroupView, 0)
	for name, hosts := range routeGroups {
		if !existing[name] {
			missing = append(missing, missingGroupView{Name: name, Hosts: hosts, CardTarget: cardTargets[name]})
		}
	}
	sort.Slice(missing, func(i, j int) bool { return missing[i].Name < missing[j].Name })
	return view, missing, routeGroupsOn, nil
}

// feedViewFor describes a feed-filled group's source and last sync for the
// Groups page, or returns nil for a group no feed fills.
func (s *Server) feedViewFor(group string, syncStates map[string]store.GroupSyncState) *feedView {
	f, ok := s.feedFor(group)
	if !ok {
		return nil
	}
	fv := &feedView{}
	if u, err := url.Parse(f.URL); err == nil {
		fv.Host = u.Host
	}
	if st, ok := syncStates[group]; ok {
		fv.Status, fv.Detail = st.Status, st.Detail
		fv.LastAttempt = s.stampMin(st.LastAttempt)
		if !st.LastSuccess.IsZero() {
			fv.LastSuccess = s.stampMin(st.LastSuccess)
			fv.Since = st.LastSuccess.In(s.tzloc()).Format("2 January")
		}
		fv.Pending = st.Status == store.GroupSyncHeld
		if fv.Pending {
			fv.PendingAdd, fv.PendingRemove = st.PendingAddList, st.PendingRemoveList
			fv.PendingHash = st.PendingHash
			if s.cfg.FeedAutoApplyAfter > 0 {
				fv.Kept = st.KeptHash != "" && st.KeptHash == st.PendingHash
				if !fv.Kept && !st.HeldSince.IsZero() {
					fv.AutoAt = s.stampMin(st.HeldSince.Add(s.cfg.FeedAutoApplyAfter))
				}
			}
		}
	}
	if r, ok := s.feeds.retryFor(group); ok {
		fv.Retry = &feedRetryView{At: s.stampMin(r.At), Next: s.stampMin(r.Next), Reason: r.Reason, Left: 1 + feedRetries - r.Attempt}
	}
	return fv
}

func (s *Server) handleAdminCreateGroup(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	if r.PostFormValue("from") == "new" {
		s.createGroupFromNewPage(w, r)
		return
	}
	name := normalizeGroupName(r.PostFormValue("name"))
	if name == "new" {
		s.renderAdmin(w, r, http.StatusBadRequest, "admin_message", adminData{Title: "Invalid group name", Message: msgGroupNameNew})
		return
	}
	if authz.IsReservedGroup(name) {
		s.renderAdmin(w, r, http.StatusBadRequest, "admin_message", adminData{
			Title:   "Reserved group name",
			Message: "The names \"admin\", \"user\" and \"guest\" are reserved roles and cannot be used as group names.",
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
	if err := s.store.CreateGroup(r.Context(), name, clampLabel(r.PostFormValue("label"))); err != nil {
		s.adminError(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionGroupCreate, name, "")
	s.redirectDone(w, r, "/admin/groups", "group-created", name)
}

func (s *Server) handleAdminDeleteGroup(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	if _, synced := s.feedFor(normalizeGroupName(r.PathValue("name"))); synced {
		s.redirectDone(w, r, "/admin/groups", "group-synced", normalizeGroupName(r.PathValue("name")))
		return
	}
	name := normalizeGroupName(r.PathValue("name"))
	if err := s.store.DeleteGroup(r.Context(), name); errors.Is(err, store.ErrGroupHoldsRoles) {
		n, err := s.store.GroupRoleCount(r.Context(), name)
		if err != nil {
			s.adminError(w, r)
			return
		}
		label := name
		if gs, err := s.store.ListGroups(r.Context()); err == nil {
			for _, g := range gs {
				if g.Name == name && g.Label != "" {
					label = g.Label
				}
			}
		}
		s.renderGroup(w, r, http.StatusConflict, name, fmt.Sprintf(msgGroupHolds, label, countWords(n, "role", "roles")))
		return
	} else if err != nil {
		s.adminError(w, r)
		return
	}
	s.markGroupsChanged(s.now())
	s.auditAdmin(r, store.AdminActionGroupDelete, name, "")
	s.redirectDone(w, r, "/admin/groups", "group-deleted", "")
}

func (s *Server) handleAdminAddMember(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	if _, synced := s.feedFor(normalizeGroupName(r.PathValue("name"))); synced {
		s.redirectDone(w, r, "/admin/groups", "group-synced", normalizeGroupName(r.PathValue("name")))
		return
	}
	group := normalizeGroupName(r.PathValue("name"))
	if !s.groupExists(r, group) {
		http.NotFound(w, r)
		return
	}
	// One field takes one address or many (pasted, one per line or separated
	// by commas or semicolons). A single valid new address is added at once;
	// anything more goes through a confirmation page.
	raw := r.PostFormValue("emails")
	if raw == "" {
		raw = r.PostFormValue("email")
	}
	plan, err := s.planBulkAdd(r, group, raw)
	if err != nil {
		s.adminError(w, r)
		return
	}
	if plan.total() == 0 || (len(plan.Invalid) > 0 && plan.total() == len(plan.Invalid)) {
		s.redirectDone(w, r, "/admin/groups", "member-invalid", group)
		return
	}
	if plan.total() == 1 && len(plan.Add) == 1 && plan.Add[0].Permitted {
		s.addMembers(w, r, group, []string{plan.Add[0].Email})
		return
	}
	s.renderAdmin(w, r, http.StatusOK, "admin_bulk_add", adminData{Title: "Add members", Bulk: plan})
}

// validCardLabel reports whether a break-glass card label may become part of
// a session's principal: no "@", no comma and no control character.
func validCardLabel(label string) bool {
	for _, r := range label {
		if r == '@' || r == ',' || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// clampLabel trims a group label and caps it at 200 characters.
func clampLabel(label string) string {
	label = trimField(label)
	if r := []rune(label); len(r) > 200 {
		label = string(r[:200])
	}
	return label
}

// handleAdminGroupLabel changes a group's display label. The label is shown to
// administrators only; apps see the group name.
func (s *Server) handleAdminGroupLabel(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	group := normalizeGroupName(r.PathValue("name"))
	label := clampLabel(r.PostFormValue("label"))
	found, err := s.store.UpdateGroupLabel(r.Context(), group, label)
	if err != nil {
		s.adminError(w, r)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionGroupLabel, group, label)
	s.redirectDone(w, r, "/admin/groups", "label-saved", group)
}

func (s *Server) handleAdminRemoveMember(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	if _, synced := s.feedFor(normalizeGroupName(r.PathValue("name"))); synced {
		s.redirectDone(w, r, "/admin/groups", "group-synced", normalizeGroupName(r.PathValue("name")))
		return
	}
	group := normalizeGroupName(r.PathValue("name"))
	emailAddr := normalizeEmail(r.PostFormValue("email"))
	if err := s.store.RemoveGroupMember(r.Context(), group, emailAddr); err != nil {
		s.adminError(w, r)
		return
	}
	s.markGroupsChanged(s.now())
	s.auditAdmin(r, store.AdminActionGroupRemoveMember, group, emailAddr)
	s.redirectDone(w, r, "/admin/groups", "member-removed", group)
}

// --- Break-glass codes ---

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
