package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/session"
)

// requireGroups/requireDomains simulate the headers Caddy's per-app snippets
// set on the /verify subrequest via header_up.
func requireDomains(d string) map[string]string {
	return map[string]string{"X-Auth-Require-Domains": d}
}
func requireGroups(g string) map[string]string { return map[string]string{"X-Auth-Require-Groups": g} }

func TestPerAppDomainGate(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)

	// App that accepts this user's domain -> allowed.
	if rec := c.get("/verify", requireDomains("example.com")); rec.Code != http.StatusOK {
		t.Fatalf("matching domain = %d, want 200", rec.Code)
	}
	// App that accepts only another domain -> denied (sent to /denied, not login).
	rec := c.get("/verify", requireDomains("partner.com"))
	if rec.Code != http.StatusFound {
		t.Fatalf("non-matching domain = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "/denied?rd=") {
		t.Errorf("denied redirect went to %q, want /denied", loc)
	}
}

func TestPerAppGroupGate(t *testing.T) {
	srv, sender := testServer(t)
	ctx := context.Background()
	if err := srv.store.CreateGroup(ctx, "dashboard", ""); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.AddGroupMember(ctx, "dashboard", "user@example.com"); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)

	if rec := c.get("/verify", requireGroups("dashboard")); rec.Code != http.StatusOK {
		t.Fatalf("member of required group = %d, want 200", rec.Code)
	}
	if rec := c.get("/verify", requireGroups("finance")); rec.Code != http.StatusFound {
		t.Fatalf("not in required group = %d, want 302 (denied)", rec.Code)
	}
}

// A denial must not disturb the session: the user keeps access to apps they
// are allowed on, and the denial page offers a working sign-in link.
func TestDeniedPreservesSessionAndOffersLogin(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)

	// Bounce off an app that requires a different domain.
	if rec := c.get("/verify", requireDomains("partner.com")); rec.Code != http.StatusFound {
		t.Fatalf("expected 302 denied, got %d", rec.Code)
	}
	// Session cookie is untouched...
	if c.cookies[session.SessionCookie] == nil {
		t.Fatal("denial cleared the session cookie")
	}
	// ...so a plain app still grants.
	if rec := c.get("/verify", nil); rec.Code != http.StatusOK {
		t.Fatalf("plain /verify after denial = %d, want 200 (session intact)", rec.Code)
	}

	// The denial page names the user and links to sign-in (back to the app).
	rd := "https://app.example.com/secret"
	rec := c.get("/denied?rd="+url.QueryEscape(rd), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("/denied status = %d, want 403", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "user@example.com") {
		t.Error("denied page should name the signed-in account")
	}
	wantLogin := "https://auth.example.com/login?rd=" + url.QueryEscape(rd)
	if !strings.Contains(body, wantLogin) {
		t.Errorf("denied page missing sign-in link %q", wantLogin)
	}
}

// Break-glass is deny-by-default: a plain `import protected` app (no
// requirement) rejects it; only a route requiring its group accepts it. The
// denial page frames it as emergency access.
func TestBreakGlassScopedToItsGroup(t *testing.T) {
	srv, _ := testServer(t)
	token := mintCode(t, srv, "Angiography Lab 1", "bg_stroke")
	c := newClient(t, srv.Handler())
	if rec := c.get("/break/"+token, nil); rec.Code != http.StatusFound {
		t.Fatalf("scan = %d", rec.Code)
	}

	// Plain protected app (no requirement) -> denied.
	if rec := c.get("/verify", nil); rec.Code != http.StatusFound {
		t.Fatalf("break-glass on plain /verify = %d, want 302 (denied)", rec.Code)
	}
	// An app requiring a different group -> denied.
	if rec := c.get("/verify", requireGroups("bg_other")); rec.Code != http.StatusFound {
		t.Fatalf("break-glass wrong group = %d, want 302 (denied)", rec.Code)
	}
	// The route that opts into this code's group -> allowed.
	rec := c.get("/verify", requireGroups("bg_stroke"))
	if rec.Code != http.StatusOK {
		t.Fatalf("break-glass on its own route = %d, want 200", rec.Code)
	}
	if g := rec.Header().Get("Remote-Groups"); g != "bg_stroke" {
		t.Errorf("Remote-Groups = %q, want bg_stroke", g)
	}

	// Denial page frames it as emergency access and shows the card label.
	body := c.get("/denied?rd="+url.QueryEscape("https://app.example.com/"), nil).Body.String()
	if !strings.Contains(body, "emergency access") || !strings.Contains(body, "Angiography Lab 1") {
		t.Errorf("break-glass denial page missing emergency framing/label:\n%s", body)
	}
}
