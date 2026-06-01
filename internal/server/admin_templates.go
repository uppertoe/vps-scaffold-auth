package server

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// adminData carries everything the admin templates might need.
type adminData struct {
	Title        string
	Message      string
	CSRF         string
	Groups       []groupView
	Codes        []codeView
	Code         codeView
	Events       []store.BreakGlassEvent
	Branding     brandingView
	Settings     settingsView
	CodeBranding codeBrandingView
}

type codeBrandingView struct {
	Title        string
	Body         string
	Instructions string
	InhTitle     string // inherited/global value, shown as placeholder
	InhBody      string
	InhInstr     string
	CustomColors bool
	HeaderColor  string
	AccentColor  string
	Bar1Color    string
	Bar2Color    string
	Bar3Color    string
	HasLogo      bool
	HasGlyph     bool
}

type brandingView struct {
	Title        string
	Body         string
	Instructions string
	Placeholder  store.Branding // resolved defaults, shown as input placeholders
	HasLogo      bool
	HasGlyph     bool
	HeaderColor  string
	AccentColor  string
	Bar1Color    string
	Bar2Color    string
	Bar3Color    string
}

type settingsView struct {
	BreakGlassHours string
	NotifyEmails    string
	WebhookURL      string
	WebhookTimeout  string
}

type groupView struct {
	Name    string
	Label   string
	Members []string
}

type codeView struct {
	ID          int64
	Label       string
	Note        string
	TargetGroup string
	Redirect    string
	Status      string
	Active      bool
	Created     string
	Updated     string
}

func toCodeView(c store.BreakGlassCode) codeView {
	return codeView{
		ID:          c.ID,
		Label:       c.Label,
		Note:        c.Note,
		TargetGroup: c.TargetGroup,
		Redirect:    c.Redirect,
		Status:      c.Status,
		Active:      c.Status == store.BreakGlassActive,
		Created:     c.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"),
		Updated:     c.UpdatedAt.UTC().Format("2006-01-02 15:04 UTC"),
	}
}

func loadAdminTemplates() (pages, error) {
	base, err := template.New("admin_base.html").ParseFS(templatesFS, "templates/admin_base.html")
	if err != nil {
		return nil, err
	}
	out := make(pages)
	for _, name := range []string{"admin_message", "admin_groups", "admin_codes", "admin_code_detail", "admin_branding", "admin_settings"} {
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

// renderAdmin renders an admin page with the relaxed (image-allowing) CSP and a
// fresh-or-existing CSRF token. The CSRF cookie is set before the status line.
func (s *Server) renderAdmin(w http.ResponseWriter, r *http.Request, status int, page string, data adminData) {
	t, ok := s.adminPages[page]
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if tok, err := s.sessions.EnsureCSRF(w, r, csrfTTL); err == nil {
		data.CSRF = tok
	}
	w.Header().Set("Content-Security-Policy", cspAdmin)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := t.ExecuteTemplate(w, "base", data); err != nil {
		fmt.Fprint(w, "internal error")
	}
}

func (s *Server) adminError(w http.ResponseWriter, r *http.Request) {
	s.renderAdmin(w, r, http.StatusInternalServerError, "admin_message", adminData{
		Title: "Something went wrong", Message: "The operation could not be completed.",
	})
}

// normalizeGroupName lowercases and trims a group name.
func normalizeGroupName(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func trimField(s string) string { return strings.TrimSpace(s) }

// hexOrDefault validates a "#rrggbb" colour, returning def if malformed.
func hexOrDefault(s, def string) string {
	s = strings.TrimSpace(s)
	if len(s) != 7 || s[0] != '#' {
		return def
	}
	for _, r := range s[1:] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return def
		}
	}
	return strings.ToLower(s)
}

// pdfFilename builds a safe download filename from a code label.
func pdfFilename(label string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(label) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			b.WriteByte('-')
		}
	}
	name := strings.Trim(b.String(), "-")
	if name == "" {
		name = "break-glass"
	}
	return name + ".pdf"
}
