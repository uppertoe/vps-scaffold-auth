package server

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"log"

	"github.com/uppertoe/vps-scaffold-auth/internal/breakglass"
	"github.com/uppertoe/vps-scaffold-auth/internal/email"
)

// codeEmailData is the view model for the OTP email template. BrandName is
// pre-HTML-escaped by buildCodeEmail (the template renders with text/template,
// which does not auto-escape); the colours are validated "#rrggbb" strings and
// Code/Minutes are server-generated, so they are safe to emit verbatim.
type codeEmailData struct {
	Code        string
	Minutes     int
	BrandName   string
	HeaderColor string
	HeaderText  string
	AccentColor string
}

// buildCodeEmail composes the OTP email (HTML + plaintext) for an address. The
// HTML uses the embedded, accent-branded template; the colours come from the
// admin branding (falling back to the default palette), matching the login page.
func (s *Server) buildCodeEmail(ctx context.Context, to, code string) email.Message {
	mins := int(s.cfg.OTPTTL.Minutes())
	if mins < 1 {
		mins = 1
	}

	header := breakglass.DefaultPalette.Header
	accent := breakglass.DefaultPalette.Accent
	if b, ok, err := s.store.GetBranding(ctx); err == nil && ok {
		header = hexOrDefault(b.HeaderColor, header)
		accent = hexOrDefault(b.AccentColor, accent)
	}

	htmlBody := s.renderCodeEmailHTML(codeEmailData{
		Code:        code,
		Minutes:     mins,
		BrandName:   html.EscapeString(s.cfg.BrandName),
		HeaderColor: header,
		HeaderText:  emailTextOn(header),
		AccentColor: accent,
	}, code, mins)

	// Plaintext alternative (raw brand name; no escaping needed).
	text := fmt.Sprintf("%s\n\nYour sign-in code is %s\n\nThis code expires in %d minute%s. "+
		"If you didn't request it, you can safely ignore this email — no one can sign in without it.",
		s.cfg.BrandName, code, mins, plural(mins))

	return email.Message{To: to, Subject: "Your sign-in code", Text: text, HTML: htmlBody}
}

// renderCodeEmailHTML executes the email template, falling back to a minimal
// inline body if rendering ever fails (so a template bug can't block a login).
func (s *Server) renderCodeEmailHTML(data codeEmailData, code string, mins int) string {
	var buf bytes.Buffer
	if err := s.emailTmpl.ExecuteTemplate(&buf, "email_code", data); err != nil {
		log.Printf("render code email: %v", err)
		// code is a server-generated numeric string, so this is injection-safe.
		return fmt.Sprintf(`<div style="font-family:sans-serif;max-width:420px;margin:auto">`+
			`<p>Your sign-in code is:</p>`+
			`<p style="font-size:28px;font-weight:700;letter-spacing:.2em">%s</p>`+
			`<p style="color:#666">It expires in %d minute%s.</p></div>`, code, mins, plural(mins))
	}
	return buf.String()
}

// plural returns "s" unless n is 1.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// emailTextOn returns a legible text colour (near-black or white) for a given
// "#rrggbb" background, by perceived luminance (ITU-R BT.601). It assumes a
// validated hex string (e.g. from hexOrDefault); anything else yields white.
func emailTextOn(hexColor string) string {
	if len(hexColor) != 7 || hexColor[0] != '#' {
		return "#ffffff"
	}
	r, ok1 := hexPair(hexColor[1], hexColor[2])
	g, ok2 := hexPair(hexColor[3], hexColor[4])
	b, ok3 := hexPair(hexColor[5], hexColor[6])
	if !ok1 || !ok2 || !ok3 {
		return "#ffffff"
	}
	lum := 0.299*float64(r) + 0.587*float64(g) + 0.114*float64(b)
	if lum > 150 {
		return "#1e2328"
	}
	return "#ffffff"
}

func hexPair(hi, lo byte) (int, bool) {
	h, ok1 := hexVal(hi)
	l, ok2 := hexVal(lo)
	if !ok1 || !ok2 {
		return 0, false
	}
	return h*16 + l, true
}

func hexVal(b byte) (int, bool) {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0'), true
	case b >= 'a' && b <= 'f':
		return int(b-'a') + 10, true
	case b >= 'A' && b <= 'F':
		return int(b-'A') + 10, true
	}
	return 0, false
}
