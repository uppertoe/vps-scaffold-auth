package server

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	texttemplate "text/template"
)

//go:embed templates/*.html
var templatesFS embed.FS

// pageData carries everything any page template might need. Unused fields stay
// zero.
type pageData struct {
	Title    string
	Error    string
	Email    string
	Redirect string
	Message  string
	Remember bool
	LogoURL  string
	// Identity / LoginURL / BreakGlass drive the access-denied page.
	Identity   string
	LoginURL   string
	BreakGlass bool
	// EmergencyOffer drives the one-tap "Use emergency access" button on the
	// denial page: it appears only when the visitor arrived carrying a valid
	// break-glass offer cookie (they scanned a card while already signed in and
	// their normal identity was then refused). EmergencyLabel names the card; the
	// button POSTs to /break/activate, which mints the emergency session.
	EmergencyOffer bool
	EmergencyLabel string
	// CSRF is the double-submit token embedded in the emergency-access form on
	// the denial page; /break/activate verifies it. Necessary because the offer
	// cookie is SameSite=Lax, which is site- not origin-scoped: a sibling app on
	// the same registrable domain could otherwise forge the activation POST.
	CSRF string
	// IsAdmin surfaces an Admin link on the signed-in /welcome landing for a
	// real (non-break-glass) admin session.
	IsAdmin bool
	// HintDomains is the display string for the domain requirement (an app-set
	// label, else the enumerated domains). RequireDomains/RequireDomainLabel
	// carry the raw requirement + optional label through to /request.
	HintDomains        string
	RequireDomains     string
	RequireDomainLabel string
	// AltLoginURL/AltLoginLabel offer a small "sign in another way" link for
	// people who can't match the domain (e.g. admins via a separate route). The
	// URL is validated to be within the server domain before it's ever rendered.
	AltLoginURL   string
	AltLoginLabel string
}

// pages holds each page template composed with the shared base layout.
type pages map[string]*template.Template

func loadTemplates() (pages, error) {
	base, err := template.ParseFS(templatesFS, "templates/base.html")
	if err != nil {
		return nil, err
	}
	out := make(pages)
	for _, name := range []string{"login", "code", "totp", "message", "denied", "welcome", "logout"} {
		t, err := base.Clone()
		if err != nil {
			return nil, err
		}
		if _, err := t.ParseFS(templatesFS, "templates/"+name+".html"); err != nil {
			return nil, err
		}
		out[name] = t
	}
	return out, nil
}

// loadEmailTemplate parses the OTP email body. It uses text/template (not
// html/template) on purpose: html/template strips HTML comments, which would
// delete the `<!--[if mso]>` conditional "ghost tables" that constrain the card
// width in desktop Outlook. The template's only free-form value (the brand name)
// is HTML-escaped by the caller before rendering; every other field is numeric
// or a validated hex colour, so emitting them verbatim is safe.
func loadEmailTemplate() (*texttemplate.Template, error) {
	return texttemplate.ParseFS(templatesFS, "templates/email_code.html")
}

// render writes a page using the base layout. On error it falls back to a plain
// 500 so a template bug never leaks a stack trace.
func (s *Server) render(w http.ResponseWriter, status int, page string, data pageData) {
	t, ok := s.pages[page]
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Surface the global branding logo on the public auth pages when set.
	if data.LogoURL == "" {
		if b, ok, err := s.store.GetBranding(context.Background()); err == nil && ok && len(b.Logo) > 0 {
			data.LogoURL = "/logo.img"
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := t.ExecuteTemplate(w, "base", data); err != nil {
		// Header already written; best effort.
		fmt.Fprint(w, "internal error")
	}
}
