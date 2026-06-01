package server

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/breakglass"
	"github.com/uppertoe/vps-scaffold-auth/internal/otp"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// loginAs runs the full email-OTP flow and leaves the client holding a session.
func loginAs(t *testing.T, c *client, sender *captureSender, email string, form url.Values) {
	t.Helper()
	if form == nil {
		form = url.Values{}
	}
	form.Set("email", email)
	c.postForm("/request", form)
	code := sender.code()
	if code == "" {
		t.Fatalf("no code captured for %s", email)
	}
	rec := c.postForm("/verify-code", url.Values{"code": {code}})
	if rec.Code != http.StatusFound {
		t.Fatalf("verify-code status = %d", rec.Code)
	}
}

func TestRememberMeExtendsCookie(t *testing.T) {
	srv, sender := testServer(t)
	srv.cfg.SessionRememberTTL = 720 * time.Hour
	c := newClient(t, srv.Handler())

	loginAs(t, c, sender, "user@example.com", url.Values{"remember": {"1"}})
	ck := c.cookies[session.SessionCookie]
	if ck == nil {
		t.Fatal("no session cookie set")
	}
	// Remember-me should be far longer than the 1h default TTL.
	if ck.MaxAge < int((24 * time.Hour).Seconds()) {
		t.Errorf("remember-me MaxAge = %d, want >= 1 day", ck.MaxAge)
	}
}

func TestDefaultSessionShortCookie(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)
	ck := c.cookies[session.SessionCookie]
	if ck == nil || ck.MaxAge > int((2*time.Hour).Seconds()) {
		t.Errorf("default session MaxAge = %v, want ~1h", ck)
	}
}

func TestDBGroupsSurfacedInHeader(t *testing.T) {
	srv, sender := testServer(t)
	ctx := context.Background()
	if err := srv.store.CreateGroup(ctx, "whitelisted", ""); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.AddGroupMember(ctx, "whitelisted", "user@example.com"); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)
	rec := c.get("/verify", nil)
	got := rec.Header().Get("Remote-Groups")
	if got != "user,whitelisted" {
		t.Errorf("Remote-Groups = %q, want user,whitelisted", got)
	}
}

// mintCode inserts a break-glass code directly and returns its raw token.
func mintCode(t *testing.T, srv *Server, label, group string) string {
	t.Helper()
	token, err := breakglass.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := srv.secrets.Seal(token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.store.CreateBreakGlassCode(context.Background(), store.BreakGlassCode{
		Label: label, TargetGroup: group, TokenEnc: enc, TokenHash: otp.Hash(token),
	}); err != nil {
		t.Fatal(err)
	}
	return token
}

func TestBreakGlassGrantsAndLogs(t *testing.T) {
	srv, _ := testServer(t)
	token := mintCode(t, srv, "Angiography Lab 1", "code_stroke_break_glass")
	c := newClient(t, srv.Handler())

	rec := c.get("/break/"+token, nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("scan status = %d, want 302", rec.Code)
	}
	// Session granted with the break-glass group.
	rec = c.get("/verify", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/verify after scan = %d, want 200", rec.Code)
	}
	if g := rec.Header().Get("Remote-Groups"); g != "code_stroke_break_glass" {
		t.Errorf("Remote-Groups = %q", g)
	}
	// Audited.
	events, err := srv.store.ListBreakGlassEvents(context.Background(), 0, 10, 0)
	if err != nil || len(events) != 1 || events[0].Outcome != store.OutcomeGranted {
		t.Fatalf("events = %+v, err=%v", events, err)
	}
}

func TestBreakGlassRevokedDenied(t *testing.T) {
	srv, _ := testServer(t)
	token := mintCode(t, srv, "Old Card", "g")
	code, _, _ := srv.store.LookupBreakGlassByTokenHash(context.Background(), otp.Hash(token))
	if err := srv.store.RevokeBreakGlassCode(context.Background(), code.ID); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv.Handler())
	rec := c.get("/break/"+token, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("revoked scan status = %d, want 404", rec.Code)
	}
	if rec := c.get("/verify", nil); rec.Code == http.StatusOK {
		t.Error("revoked scan should not grant a session")
	}
}

func TestBreakGlassSessionNotRenewed(t *testing.T) {
	srv, _ := testServer(t)
	// Make any read past the renew threshold.
	srv.cfg.BreakGlassSessionTTL = time.Hour
	token := mintCode(t, srv, "Lab", "g")
	c := newClient(t, srv.Handler())
	c.get("/break/"+token, nil)

	before := c.cookies[session.SessionCookie].Value
	// Advance time beyond the renew window; a normal session would re-issue.
	srv.now = func() time.Time { return time.Now().Add(45 * time.Minute) }
	c.get("/verify", nil)
	after := c.cookies[session.SessionCookie]
	if after != nil && after.Value != before {
		t.Error("break-glass session was renewed; it must expire at its short TTL")
	}
}

func TestAdminRequiresAdminGroup(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())

	// Anonymous → redirected to login.
	if rec := c.get("/admin/break", nil); rec.Code != http.StatusFound {
		t.Fatalf("anon /admin/break = %d, want 302", rec.Code)
	}

	// Regular user → still redirected (no admin group).
	loginAs(t, c, sender, "user@example.com", nil)
	if rec := c.get("/admin/break", nil); rec.Code != http.StatusFound {
		t.Fatalf("user /admin/break = %d, want 302", rec.Code)
	}

	// Admin → allowed.
	ac := newClient(t, srv.Handler())
	loginAs(t, ac, sender, "admin@example.com", nil)
	rec := ac.get("/admin/break", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin /admin/break = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Break-glass codes") {
		t.Error("admin page did not render expected content")
	}
}

func TestAdminCreateCodeCSRF(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)

	// Load the page to obtain a CSRF cookie + token.
	rec := c.get("/admin/break", nil)
	tok := extractCSRF(t, rec.Body.String())

	// Missing token → 403.
	if rec := c.postForm("/admin/break", url.Values{"label": {"L"}, "group": {"g"}}); rec.Code != http.StatusForbidden {
		t.Fatalf("no-CSRF create = %d, want 403", rec.Code)
	}

	// Valid token → created.
	rec = c.postForm("/admin/break", url.Values{"csrf": {tok}, "label": {"Angio 1"}, "group": {"code_stroke_break_glass"}})
	if rec.Code != http.StatusFound {
		t.Fatalf("create = %d, want 302", rec.Code)
	}
	codes, _ := srv.store.ListBreakGlassCodes(context.Background())
	if len(codes) != 1 || codes[0].Label != "Angio 1" {
		t.Fatalf("codes = %+v", codes)
	}
	// The stored token is ciphertext, never plaintext.
	if !strings.HasPrefix(codes[0].TokenEnc, "v1:") {
		t.Errorf("token not encrypted at rest: %q", codes[0].TokenEnc)
	}
}

func TestAppSettingsOverrideBreakGlassTTL(t *testing.T) {
	srv, _ := testServer(t)
	srv.cfg.BreakGlassSessionTTL = time.Hour // env default
	// Admin saves an 8h override.
	if err := srv.store.SaveAppSettings(context.Background(), 8*3600, "", ""); err != nil {
		t.Fatal(err)
	}
	token := mintCode(t, srv, "Lab", "g")
	c := newClient(t, srv.Handler())
	c.get("/break/"+token, nil)
	ck := c.cookies[session.SessionCookie]
	if ck == nil {
		t.Fatal("no break-glass session issued")
	}
	// The cookie MaxAge should reflect the 8h override, not the 1h env default.
	if ck.MaxAge < int((7 * time.Hour).Seconds()) {
		t.Errorf("break-glass MaxAge = %d, want ~8h (override not applied)", ck.MaxAge)
	}
}

func TestBrandingColorsPersistAndLogoServed(t *testing.T) {
	srv, sender := testServer(t)
	ctx := context.Background()
	if err := srv.store.SaveBrandingColors(ctx, "#111111", "#222222", "#333333", "#444444", "#555555"); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.SetBrandingImage(ctx, store.BrandingLogo, []byte{0x89, 'P', 'N', 'G', 1, 2}, "image/png"); err != nil {
		t.Fatal(err)
	}

	// Public logo route serves it.
	c := newClient(t, srv.Handler())
	rec := c.get("/logo.img", nil)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("logo route: status=%d type=%q", rec.Code, rec.Header().Get("Content-Type"))
	}

	// Login page references the logo.
	if body := c.get("/login", nil).Body.String(); !strings.Contains(body, `src="/logo.img"`) {
		t.Error("login page does not show the branding logo")
	}

	// Admin branding page reflects saved colours.
	ac := newClient(t, srv.Handler())
	loginAs(t, ac, sender, "admin@example.com", nil)
	if body := ac.get("/admin/branding", nil).Body.String(); !strings.Contains(body, "#222222") {
		t.Error("admin branding page does not show saved accent colour")
	}
}

func TestPerCodeBrandingOverridesAndInherits(t *testing.T) {
	srv, _ := testServer(t)
	ctx := context.Background()
	// Global branding.
	if err := srv.store.SaveBrandingText(ctx, "Global Title", "Global body", "Global instr"); err != nil {
		t.Fatal(err)
	}
	id, err := srv.store.CreateBreakGlassCode(ctx, store.BreakGlassCode{
		Label: "Lab", TargetGroup: "g", TokenEnc: "x", TokenHash: "h",
	})
	if err != nil {
		t.Fatal(err)
	}

	// No override yet → inherits global.
	eff := srv.effectiveCardBranding(ctx, id)
	if eff.Title != "Global Title" || eff.Body != "Global body" {
		t.Fatalf("inherit failed: %+v", eff)
	}

	// Override just the title + accent colour.
	if err := srv.store.SaveCodeBrandingMeta(ctx, id, "Cardiology", "", "", "", "#123456", "", "", ""); err != nil {
		t.Fatal(err)
	}
	eff = srv.effectiveCardBranding(ctx, id)
	if eff.Title != "Cardiology" {
		t.Errorf("override title = %q, want Cardiology", eff.Title)
	}
	if eff.Body != "Global body" {
		t.Errorf("blank body should inherit, got %q", eff.Body)
	}
	if eff.AccentColor != "#123456" {
		t.Errorf("override accent = %q", eff.AccentColor)
	}

	// A different code stays on the global branding.
	id2, _ := srv.store.CreateBreakGlassCode(ctx, store.BreakGlassCode{
		Label: "Lab2", TargetGroup: "g", TokenEnc: "y", TokenHash: "h2",
	})
	if eff2 := srv.effectiveCardBranding(ctx, id2); eff2.Title != "Global Title" {
		t.Errorf("second code should inherit global, got %q", eff2.Title)
	}
}

func TestPerCodeBrandingPDFRenders(t *testing.T) {
	srv, sender := testServer(t)
	ctx := context.Background()
	id, _ := srv.store.CreateBreakGlassCode(ctx, store.BreakGlassCode{
		Label: "Cath Lab", TargetGroup: "g", TokenEnc: mustSeal(t, srv, "tok"), TokenHash: "h",
	})
	if err := srv.store.SaveCodeBrandingMeta(ctx, id, "Cardiology Emergency", "Cath lab access", "Scan me", "#7a1f2b", "#b5293a", "#fdb913", "#f26c52", "#82c341"); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	rec := c.get("/admin/break/"+strconv.FormatInt(id, 10)+"/pdf", nil)
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), "%PDF") {
		t.Fatalf("per-code PDF: status=%d prefix=%q", rec.Code, rec.Body.String()[:4])
	}
}

func mustSeal(t *testing.T, srv *Server, s string) string {
	t.Helper()
	enc, err := srv.secrets.Seal(s)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func TestAdminSettingsPageAndSave(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	tok := extractCSRF(t, c.get("/admin/settings", nil).Body.String())

	// Invalid hours rejected.
	if rec := c.postForm("/admin/settings", url.Values{"csrf": {tok}, "hours": {"999"}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("out-of-range hours = %d, want 400", rec.Code)
	}
	// Valid save.
	rec := c.postForm("/admin/settings", url.Values{
		"csrf": {tok}, "hours": {"8"}, "emails": {"oncall@example.com"}, "webhook": {"https://ntfy.sh/x"},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("save settings = %d, want 302", rec.Code)
	}
	as, err := srv.store.GetAppSettings(context.Background())
	if err != nil || !as.Exists || as.BreakGlassSecs != 8*3600 || as.WebhookURL != "https://ntfy.sh/x" {
		t.Fatalf("settings not saved: %+v err=%v", as, err)
	}
}

func extractCSRF(t *testing.T, body string) string {
	t.Helper()
	const marker = `name="csrf" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatal("no csrf field in page")
	}
	rest := body[i+len(marker):]
	j := strings.IndexByte(rest, '"')
	return rest[:j]
}
