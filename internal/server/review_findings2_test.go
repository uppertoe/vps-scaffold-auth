// Regression tests from the security review of 2026-11-04: each failed
// while its finding stood.
package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/session"
)

// P6: legacy and odd cookie shapes never hold the admin tier.
func TestReviewLegacyAdminCookies(t *testing.T) {
	srv, _ := testServer(t)
	srv.cfg.TOTPEnabled = true
	now := time.Now()
	cases := []struct {
		name string
		g    session.Identity
		want bool
	}{
		{"main TOTP=true Auth 1h", session.Identity{Email: "admin@example.com", Groups: "admin", TOTP: true, Auth: now.Add(-time.Hour).Unix()}, true},
		{"main TOTP=true Auth 13h", session.Identity{Email: "admin@example.com", Groups: "admin", TOTP: true, Auth: now.Add(-13 * time.Hour).Unix()}, false},
		{"TOTP=true Auth=1", session.Identity{Email: "admin@example.com", Groups: "admin", TOTP: true, Auth: 1}, false},
		{"TOTP=false Step now", session.Identity{Email: "admin@example.com", Groups: "admin", Step: now.Unix(), Auth: now.Unix()}, false},
		{"TOTP=true Step 13h Auth now", session.Identity{Email: "admin@example.com", Groups: "admin", TOTP: true, Step: now.Add(-13 * time.Hour).Unix(), Auth: now.Unix()}, false},
		{"TOTP=false Auth now", session.Identity{Email: "admin@example.com", Groups: "admin", Auth: now.Unix()}, false},
	}
	for _, tc := range cases {
		c := mintSession(t, srv, tc.g, time.Hour)
		a := c.get("/admin/", nil)
		v := c.get("/verify", anyGuard(t, srv))
		got := strings.HasPrefix(sessionOf(t, srv, c).Groups, "admin") && a.Code == http.StatusOK
		t.Logf("%-30s admin=%d verify=%d groups=%q", tc.name, a.Code, v.Code, sessionOf(t, srv, c).Groups)
		if got != tc.want {
			t.Errorf("%s: admin tier held=%v, want %v", tc.name, got, tc.want)
		}
	}
}

// P7: the admin door's rd cannot leave the domain.
func TestReviewDoorRedirects(t *testing.T) {
	srv, sender := testServer(t)
	srv.cfg.TOTPEnabled = true
	secret := provisionTOTP(t, srv, "admin@example.com")
	anon := newClient(t, srv.Handler())
	for _, rd := range []string{"https://evil.com/", "//evil.com", "https://example.com.evil.com/", "javascript:alert(1)"} {
		rec := anon.get("/totp?rd="+url.QueryEscape(rd), nil)
		t.Logf("anon rd=%q -> %d %q", rd, rec.Code, rec.Header().Get("Location"))
		if strings.Contains(rec.Header().Get("Location"), "evil.com") || strings.Contains(rec.Header().Get("Location"), "javascript") {
			t.Errorf("rd %q carried", rd)
		}
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	rec := stepUp(t, c, totpNow(t, secret, time.Now()), "https://evil.com/")
	t.Logf("after code rd=evil -> %d %q", rec.Code, rec.Header().Get("Location"))
	if strings.Contains(rec.Header().Get("Location"), "evil.com") {
		t.Error("open redirect")
	}
	nested := "https://auth.example.com/totp?rd=" + url.QueryEscape("https://auth.example.com/totp?rd="+url.QueryEscape("https://evil.com"))
	loc := "/totp?rd=" + url.QueryEscape(nested)
	for i := 0; i < 5 && loc != ""; i++ {
		rec = c.get(strings.TrimPrefix(loc, "https://auth.example.com"), nil)
		loc = rec.Header().Get("Location")
		t.Logf("hop %d -> %d %q", i, rec.Code, loc)
		if !strings.Contains(loc, "auth.example.com/totp") {
			break
		}
	}
	if strings.Contains(loc, "evil.com") {
		t.Error("open redirect via nesting")
	}
}
