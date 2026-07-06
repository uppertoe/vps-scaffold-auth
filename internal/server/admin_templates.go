package server

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/session"
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
	// Admin two-factor page.
	TOTPEnabled bool
	TOTPAdmins  []totpAdminView
	NewTOTP     *newTOTPView // freshly minted secret, shown once
	// Access-log page.
	FilterEmail string
	AuthEvents  []authEventView
	AppAccess   []appAccessView
	// Admin-action audit page.
	AdminEvents []adminEventView
}

// authEventView is one login-flow attempt row on the access-log page.
type authEventView struct {
	Time      string
	Email     string
	Type      string
	Outcome   string
	OK        bool // outcome was a success (drives the pill colour)
	ClientIP  string
	UserAgent string
}

// appAccessView is one deduplicated app-access row on the access-log page.
type appAccessView struct {
	Time       string
	Email      string
	Host       string
	Kind       string // "login" or "break-glass"
	BreakGlass bool
}

// stamp renders t in the configured display timezone (default UTC). The "MST"
// token prints the zone abbreviation (e.g. AEDT/AEST/UTC) so the offset is
// unambiguous. stampMin drops the seconds.
func (s *Server) stamp(t time.Time) string    { return t.In(s.tzloc()).Format("2006-01-02 15:04:05 MST") }
func (s *Server) stampMin(t time.Time) string { return t.In(s.tzloc()).Format("2006-01-02 15:04 MST") }

func (s *Server) tzloc() *time.Location {
	if s.loc == nil {
		return time.UTC
	}
	return s.loc
}

func (s *Server) toAuthEventViews(es []store.AuthEvent) []authEventView {
	out := make([]authEventView, 0, len(es))
	for _, e := range es {
		out = append(out, authEventView{
			Time:      s.stamp(e.CreatedAt),
			Email:     e.Email,
			Type:      e.EventType,
			Outcome:   e.Outcome,
			OK:        e.Outcome == store.AuthOutcomeOK,
			ClientIP:  e.ClientIP,
			UserAgent: e.UserAgent,
		})
	}
	return out
}

func (s *Server) toAppAccessViews(as []store.AppAccess) []appAccessView {
	out := make([]appAccessView, 0, len(as))
	for _, a := range as {
		v := appAccessView{
			Time:  s.stampMin(a.CreatedAt),
			Email: a.Email,
			Host:  a.Host,
			Kind:  "login",
		}
		if a.Kind == session.KindBreakGlass {
			v.Kind, v.BreakGlass = "break-glass", true
		}
		out = append(out, v)
	}
	return out
}

// totpAdminView is one configured admin's enrolment status on the 2FA page.
type totpAdminView struct {
	Email    string
	Enrolled bool
}

// newTOTPView carries a just-provisioned secret for one-time display.
type newTOTPView struct {
	Email string
	URL   string
	Key   string
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
	HasPDFLogo   bool
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

func (s *Server) toCodeView(c store.BreakGlassCode) codeView {
	return codeView{
		ID:          c.ID,
		Label:       c.Label,
		Note:        c.Note,
		TargetGroup: c.TargetGroup,
		Redirect:    c.Redirect,
		Status:      c.Status,
		Active:      c.Status == store.BreakGlassActive,
		Created:     s.stampMin(c.CreatedAt),
		Updated:     s.stampMin(c.UpdatedAt),
	}
}

// adminEventView is one administrative-action row on the admin audit page.
type adminEventView struct {
	Time      string
	Actor     string
	Action    string
	Target    string
	Detail    string
	ClientIP  string
	UserAgent string
}

func (s *Server) toAdminEventViews(es []store.AdminEvent) []adminEventView {
	out := make([]adminEventView, 0, len(es))
	for _, e := range es {
		out = append(out, adminEventView{
			Time:      s.stamp(e.CreatedAt),
			Actor:     e.Actor,
			Action:    e.Action,
			Target:    e.Target,
			Detail:    e.Detail,
			ClientIP:  e.ClientIP,
			UserAgent: e.UserAgent,
		})
	}
	return out
}

func loadAdminTemplates(loc *time.Location) (pages, error) {
	if loc == nil {
		loc = time.UTC
	}
	funcs := template.FuncMap{
		"fmtTime": func(t time.Time) string { return t.In(loc).Format("2006-01-02 15:04:05 MST") },
	}
	base, err := template.New("admin_base.html").Funcs(funcs).ParseFS(templatesFS, "templates/admin_base.html")
	if err != nil {
		return nil, err
	}
	out := make(pages)
	for _, name := range []string{"admin_message", "admin_groups", "admin_codes", "admin_code_detail", "admin_branding", "admin_settings", "admin_totp", "admin_access", "admin_audit"} {
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
	if tok, err := s.sessions.EnsureCSRF(w, r, csrfTTL, s.now()); err == nil {
		data.CSRF = tok
	}
	w.Header().Set("Content-Security-Policy", s.csp)
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
