// The admin branding and settings pages, and image uploads.

package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/breakglass"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// maxBrandingUpload caps logo upload size.
const maxBrandingUpload = 2 << 20 // 2 MiB

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
