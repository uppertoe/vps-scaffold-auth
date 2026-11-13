package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// Opening a card's address grants nothing. A link preview or a mail scanner
// fetches the address on its own, so the page asks for a button press, and
// the fetch is recorded only as "viewed". The button's POST grants.
func TestBreakGlassScanAsksBeforeGranting(t *testing.T) {
	srv, _ := testServer(t)
	token := mintCode(t, srv, "Lab 1", "g")
	c := newClient(t, srv.Handler())

	rec := c.get("/break/"+token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d, want the confirmation page", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"<h1>Emergency access</h1>",
		"This card gives emergency access without signing in. Each use is recorded, and the administrators are notified.",
		`<form method="post" action="/break">`,
		`name="token" value="` + token + `"`,
		"Continue with emergency access",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("confirmation page missing %q", want)
		}
	}
	if c.cookies[session.SessionCookie] != nil {
		t.Fatal("opening the address granted a session")
	}
	events, _ := srv.store.ListBreakGlassEvents(context.Background(), 0, 10, 0)
	if len(events) != 1 || events[0].Outcome != store.OutcomeViewed {
		t.Fatalf("events after GET = %+v, want one 'viewed'", events)
	}

	rec = c.postForm("/break", url.Values{"token": {token}})
	if rec.Code != http.StatusFound || c.cookies[session.SessionCookie] == nil {
		t.Fatalf("POST = %d, want a grant", rec.Code)
	}
	if rec := c.get("/verify", requireGroups("g")); rec.Code != http.StatusOK {
		t.Errorf("/verify after the button = %d, want 200", rec.Code)
	}
}

// The grant refuses a post from another site, and a post with no token or a
// wrong one gets the neutral page.
func TestBreakGlassPostRefusesCrossSiteAndBadTokens(t *testing.T) {
	srv, _ := testServer(t)
	token := mintCode(t, srv, "Lab 1", "g")
	c := newClient(t, srv.Handler())

	req := httptest.NewRequest(http.MethodPost, "/break", strings.NewReader(url.Values{"token": {token}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://planka.example.com")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	if rec := c.do(req); rec.Code != http.StatusForbidden || c.cookies[session.SessionCookie] != nil {
		t.Fatalf("cross-site POST = %d, want 403 and no session", rec.Code)
	}
	for _, tok := range []string{"", "not-a-real-token"} {
		rec := c.postForm("/break", url.Values{"token": {tok}})
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), msgCardUnknownTitle) {
			t.Errorf("POST token %q = %d, want the neutral page", tok, rec.Code)
		}
	}
	if c.cookies[session.SessionCookie] != nil {
		t.Fatal("a bad token granted a session")
	}
	if events, _ := srv.store.ListBreakGlassEvents(context.Background(), 0, 10, 0); len(events) != 0 {
		t.Errorf("events = %+v, want none", events)
	}
}

// A card made before its group became an application role grants nothing
// once the group is one, whether scanned directly or activated from the
// denial page. The scan is recorded and the administrators are told.
func TestBreakGlassCardRefusedOnceTargetIsAppRole(t *testing.T) {
	srv, sender := testServerWith(t, func(c *config.Config) {
		c.BreakGlassNotifyEmails = []string{"admin@example.com"}
	})
	token := mintCode(t, srv, "Lab 1", "airdb_admin")
	srv.cfg.BreakGlassRefusedGroups = []string{"airdb_admin"}

	c := newClient(t, srv.Handler())
	// The scan's page already shows the card as not available.
	if rec := c.get("/break/"+token, nil); rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "Continue with emergency access") {
		t.Fatalf("scan page = %d, want the neutral page", rec.Code)
	}
	// A page opened before the change, or the token posted from a photo,
	// is refused at the grant, recorded, and reported.
	rec := c.postForm("/break", url.Values{"token": {token}})
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), msgCardUnknownTitle) {
		t.Fatalf("grant = %d, want the neutral page", rec.Code)
	}
	if c.cookies[session.SessionCookie] != nil {
		t.Fatal("a card for an application role granted a session")
	}
	events, _ := withoutViews(srv.store.ListBreakGlassEvents(context.Background(), 0, 10, 0))
	if len(events) != 1 || events[0].Outcome != store.OutcomeRefusedTarget {
		t.Fatalf("events = %+v, want one 'refused_target'", events)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		told := false
		sender.mu.Lock()
		for _, m := range sender.notices {
			if strings.Contains(m.Subject, "Break-glass used: Lab 1") && strings.Contains(m.Text, "refused_target") {
				told = true
			}
		}
		sender.mu.Unlock()
		if told {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the administrators were not told of the refused scan")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// A second refused post is recorded but not reported again within the hour.
	c.postForm("/break", url.Values{"token": {token}})
	time.Sleep(100 * time.Millisecond)
	if events, _ := withoutViews(srv.store.ListBreakGlassEvents(context.Background(), 0, 10, 0)); len(events) != 2 {
		t.Fatalf("events after a second post = %d, want 2", len(events))
	}
	sender.mu.Lock()
	reported := 0
	for _, m := range sender.notices {
		if strings.Contains(m.Text, "refused_target") {
			reported++
		}
	}
	sender.mu.Unlock()
	if reported != 1 {
		t.Fatalf("refused posts reported %d times, want once", reported)
	}

	// Activation from the denial page goes through the same refusal.
	signedIn := newClient(t, srv.Handler())
	loginAs(t, signedIn, sender, "user@example.com", nil)
	srv.cfg.BreakGlassRefusedGroups = nil
	if rec := signedIn.scan(token); rec.Code != http.StatusFound {
		t.Fatalf("scan while signed in = %d, want the redirect with an offer", rec.Code)
	}
	csrf := extractCSRF(t, signedIn.get("/denied?rd=https://app.example.com/", nil).Body.String())
	srv.cfg.BreakGlassRefusedGroups = []string{"airdb_admin"}
	rec = signedIn.postForm("/break/activate", url.Values{"csrf": {csrf}})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("activate = %d, want the neutral page", rec.Code)
	}
	if id := sessionOf(t, srv, signedIn); id.Kind == session.KindBreakGlass {
		t.Fatal("activation granted a card for an application role")
	}
}
