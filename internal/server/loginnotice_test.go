package server

import (
	"strings"
	"testing"
)

// The operator-set LOGIN_NOTICE renders on the sign-in page as visible text,
// and any HTML metacharacters are auto-escaped by html/template — a live
// <script> must never reach the page (no stored/reflected XSS via the notice).
func TestLoginNoticeRenderedAndEscaped(t *testing.T) {
	srv, _ := testServer(t)
	srv.cfg.LoginNotice = `Use your <parking> "council" email & be primary<script>alert(1)</script>`
	c := newClient(t, srv.Handler())
	body := c.get("/login", nil).Body.String()

	// The raw script tag must NOT appear verbatim — that would be executable markup.
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("LOGIN_NOTICE was not HTML-escaped — a live <script> reached the login page (XSS)")
	}
	// The escaped form must be present.
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Errorf("escaped notice not found on login page:\n%s", body)
	}
	// A benign portion is visible to users.
	if !strings.Contains(body, "be primary") {
		t.Error("login notice text was not rendered")
	}
}

// With LOGIN_NOTICE unset the notice paragraph is omitted entirely.
func TestLoginNoticeAbsentWhenUnset(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv.Handler())
	body := c.get("/login", nil).Body.String()
	if strings.Contains(body, `class="sub notice"`) {
		t.Error("notice paragraph rendered despite LOGIN_NOTICE being unset")
	}
}
