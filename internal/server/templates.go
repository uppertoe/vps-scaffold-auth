package server

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"strings"
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
	// LogoType is the logo's content type, for the page's icon link.
	LogoType string
	// CodePlaceholder shows the email code's length in the code box (OTP_LENGTH
	// zeros), filled in by render.
	CodePlaceholder string
	// LoginNotice is an optional operator-set instruction line rendered on the
	// sign-in page (from the LOGIN_NOTICE env var). Rendered auto-escaped as
	// plain text by html/template — never as template.HTML.
	LoginNotice string
	// Identity / LoginURL / BreakGlass / Guest drive the access-denied page.
	// LogoutURL is the sign-out link offered to a guest there, who must sign out
	// before signing in again with an approved address.
	Identity   string
	LoginURL   string
	LogoutURL  string
	BreakGlass bool
	Guest      bool
	// EmergencyOffer drives the one-tap "Use emergency access" button on the
	// denial page: it appears only when the visitor arrived carrying a valid
	// break-glass offer cookie (they scanned a card while already signed in and
	// their normal identity was then refused). EmergencyLabel names the card; the
	// button POSTs to /break/activate, which mints the emergency session.
	EmergencyOffer bool
	EmergencyLabel string
	// BreakToken is the scanned card's token, carried in the confirmation
	// page's form so that the grant is a POST (break_confirm.html).
	BreakToken string
	// Scan is a card's scan page, drawn with the card's design (card_scan.go).
	Scan *scanView
	// CSRF is the double-submit token embedded in the emergency-access form on
	// the denial page; /break/activate verifies it. Necessary because the offer
	// cookie is SameSite=Lax, which is site- not origin-scoped: a sibling app on
	// the same registrable domain could otherwise forge the activation POST.
	CSRF string
	// NameAddressExample, on the denial page, is set when the signed-in
	// address has no dot before the "@": an example firstname.lastname
	// address at the same domain, shown with a hint to sign in with one.
	NameAddressExample string
	// Invite is an invitation's page (invite_public.go).
	Invite *invitePage
	// IsAdmin surfaces an Admin link on the signed-in /welcome landing for a
	// real (non-break-glass) admin session.
	IsAdmin bool
	// HintDomains is the display string for the domain requirement (an app-set
	// label, else the enumerated domains). RequireDomains/RequireDomainLabel
	// carry the raw requirement + optional label through to /request.
	HintDomains        string
	RequireDomains     string
	RequireDomainLabel string
	// RequireGroups marks a group-gated route (admin/collaborator door) carried
	// through to the login page. It suppresses the configured-domain fallback
	// hint/placeholder: that door is deliberately for people who can't match the
	// domain, so it must neither hint a domain nor presume one in the example.
	RequireGroups string
	// RoleGuard marks a login from a role guard that may not decline early,
	// and RoleHintDomains are the domains it hints (see roleLoginHint). Both
	// are carried to /request as hidden fields.
	RoleGuard       bool
	RoleHintDomains string
	// EmailPlaceholder is the login field's example address, derived from the
	// effective domain (the route requirement, else the configured allow-list)
	// as you@<domain>; empty falls back to a generic example in the template.
	EmailPlaceholder string
	// AltLoginURL/AltLoginLabel offer a small "sign in another way" link for
	// people who can't match the domain (e.g. admins via a separate route). The
	// URL is validated to be within the server domain before it's ever rendered.
	AltLoginURL   string
	AltLoginLabel string
	// Passkey drives the passkey parts of a page (passkeys.go); nil when
	// passkeys are off. A page with one loads /passkey.js, and render widens
	// its Content-Security-Policy to allow that one same-origin script.
	Passkey *passkeyPage
	// PasskeyScript is set by render on the pages allowed to run it.
	PasskeyScript bool
}

// passkeyPages are the pages that use /passkey.js when passkeys are on.
var passkeyPages = map[string]bool{"login": true, "passkey_offer": true, "passkeys": true, "totp": true}

// pages holds each page template composed with the shared base layout.
type pages map[string]*template.Template

func loadTemplates() (pages, error) {
	base, err := template.ParseFS(templatesFS, "templates/base.html")
	if err != nil {
		return nil, err
	}
	out := make(pages)
	for _, name := range []string{"login", "code", "totp", "message", "denied", "welcome", "logout", "passkey_offer", "passkey_added", "passkeys", "passkey_confirm", "break_confirm"} {
		t, err := base.Clone()
		if err != nil {
			return nil, err
		}
		if _, err := t.ParseFS(templatesFS, "templates/"+name+".html"); err != nil {
			return nil, err
		}
		out[name] = t
	}
	if err := addPages(out, base, publicInvitePages); err != nil {
		return nil, err
	}
	return out, nil
}

// addPages parses each page, with the shared files extra, on a clone of
// base.
func addPages(out pages, base *template.Template, names []string, extra ...string) error {
	for _, name := range names {
		t, err := base.Clone()
		if err != nil {
			return err
		}
		files := []string{"templates/" + name + ".html"}
		for _, e := range extra {
			files = append(files, "templates/"+e)
		}
		if _, err := t.ParseFS(templatesFS, files...); err != nil {
			return err
		}
		out[name] = t
	}
	return nil
}

// publicInvitePages and adminInvitePages are the invitation pages.
var (
	publicInvitePages = []string{"invite"}
	adminInvitePages  = []string{"admin_invites", "admin_invite_new"}
)

// loadEmailTemplate parses the OTP email body. It uses text/template (not
// html/template) on purpose: html/template strips HTML comments, which would
// delete the `<!--[if mso]>` conditional "ghost tables" that constrain the card
// width in desktop Outlook. The template's only free-form value (the brand name)
// is HTML-escaped by the caller before rendering; every other field is numeric
// or a validated hex colour, so emitting them verbatim is safe.
func loadEmailTemplate() (*texttemplate.Template, error) {
	return texttemplate.ParseFS(templatesFS, "templates/email_code.html", "templates/email_passkey_notice.html")
}

// render writes a page using the base layout. On error it falls back to a plain
// 500 so a template bug never leaks a stack trace.
func (s *Server) render(w http.ResponseWriter, status int, page string, data pageData) {
	t, ok := s.pages[page]
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data.CodePlaceholder = strings.Repeat("0", s.cfg.OTPLength)
	// Surface the global branding logo on the public auth pages when set.
	if data.LogoURL == "" {
		if b, err := s.publicBranding(context.Background()); err == nil && b.logoVersion != "" {
			data.LogoURL = "/logo.img?v=" + b.logoVersion
			data.LogoType = b.logoType
		}
	}
	// Fill domain-derived UX fields on the login page (hint line + email
	// placeholder), so even a direct visit tells the user which domain to use.
	if page == "login" {
		data.LoginNotice = s.cfg.LoginNotice
		s.applyLoginBranding(&data)
		// Every rendering of the sign-in page carries a fresh passkey challenge,
		// so the phone can offer a saved passkey as soon as the page opens.
		if s.cfg.PasskeysEnabled {
			unknown := ""
			if data.Passkey != nil {
				unknown = data.Passkey.Unknown
			}
			data.Passkey = s.passkeyLoginOptions(w)
			if data.Passkey != nil {
				data.Passkey.Unknown = unknown
			}
		}
	}
	if s.cfg.PasskeysEnabled && passkeyPages[page] && data.Passkey != nil {
		data.PasskeyScript = true
		w.Header().Set("Content-Security-Policy", s.csp+"; script-src 'self'")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := t.ExecuteTemplate(w, "base", data); err != nil {
		// Header already written; best effort.
		fmt.Fprint(w, "internal error")
	}
}
