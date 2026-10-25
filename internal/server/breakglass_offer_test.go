package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/otp"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// A scan by someone who already holds a normal session must NOT clobber it with
// an emergency session: they are redirected on their own identity, an offer
// cookie is set for the one-tap follow-through, and the scan is audited as
// "redirected" rather than "granted".
func TestBreakGlassScanWithSessionRedirectsNotGrants(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)
	normal := c.cookies[session.SessionCookie].Value

	token := mintCode(t, srv, "Lab 1", "g")
	rec := c.get("/break/"+token, nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("scan status = %d, want 302", rec.Code)
	}
	// Normal session preserved (not replaced by a break-glass one).
	if got := c.cookies[session.SessionCookie].Value; got != normal {
		t.Error("scan overwrote the existing normal session")
	}
	// Their normal identity is intact: /verify on a route their domain satisfies
	// returns their email (a break-glass downgrade would fail the domain gate).
	if rec := c.get("/verify", requireDomains("example.com")); rec.Header().Get("Remote-Email") != "user@example.com" {
		t.Errorf("identity after scan = %q, want the normal user", rec.Header().Get("Remote-Email"))
	}
	// Offer cookie set for the one-tap grant.
	if c.cookies[session.OfferCookie] == nil {
		t.Error("no break-glass offer cookie set")
	}
	// Audited as redirected, not granted.
	events, err := srv.store.ListBreakGlassEvents(context.Background(), 0, 10, 0)
	if err != nil || len(events) != 1 || events[0].Outcome != store.OutcomeRedirected {
		t.Fatalf("events = %+v, err=%v; want one 'redirected'", events, err)
	}
}

// After a redirect-first scan, the denial page offers one-tap emergency access
// and — deliberately, since time is critical — does NOT offer the email-login
// detour.
func TestDeniedPageOffersEmergencyOnly(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)
	mintScanToken(t, srv, c, "Lab 1", "g")

	body := c.get("/denied?rd=https://app.example.com/", nil).Body.String()
	if !strings.Contains(body, `action="/break/activate"`) || !strings.Contains(body, "Use emergency access") {
		t.Error("denied page missing the emergency-access action")
	}
	if strings.Contains(body, "Sign in to continue") || strings.Contains(body, "different account") {
		t.Error("denied page still offers the email-login flow during a break-glass emergency")
	}
}

// Activating a pending offer mints the emergency session, clears the offer, and
// audits a grant. The resulting session reaches only the card's group.
func TestBreakGlassActivateGrants(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)
	mintScanToken(t, srv, c, "Lab 1", "g")

	rec := c.postForm("/break/activate", url.Values{"csrf": {denialCSRF(t, c)}})
	if rec.Code != http.StatusFound {
		t.Fatalf("activate status = %d, want 302", rec.Code)
	}
	if c.cookies[session.OfferCookie] != nil {
		t.Error("offer cookie not cleared after activation")
	}
	rec = c.get("/verify", requireGroups("g"))
	if rec.Code != http.StatusOK || rec.Header().Get("Remote-Groups") != "g" {
		t.Fatalf("/verify after activate = %d groups=%q, want 200 g", rec.Code, rec.Header().Get("Remote-Groups"))
	}
	events, _ := srv.store.ListBreakGlassEvents(context.Background(), 0, 10, 0)
	if len(events) != 2 || events[0].Outcome != store.OutcomeGranted {
		t.Fatalf("events = %+v, want a 'granted' after the 'redirected'", events)
	}
}

// The offer cookie alone must NOT authorize activation: a same-site sibling can
// make the browser send the Lax offer cookie on a forged POST, but cannot read
// or guess the CSRF token. A missing/forged token is rejected and grants nothing.
func TestBreakGlassActivateRejectsForgedCSRF(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)
	mintScanToken(t, srv, c, "Lab 1", "g")

	rec := c.postForm("/break/activate", url.Values{"csrf": {"forged"}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("forged-csrf activate = %d, want 403", rec.Code)
	}
	if rec := c.get("/verify", requireGroups("g")); rec.Code == http.StatusOK {
		t.Error("forged-csrf activation granted access")
	}
	if c.cookies[session.OfferCookie] == nil {
		t.Error("a rejected activation should leave the offer intact")
	}
}

// With a valid CSRF token but no pending offer, activation grants nothing and
// bounces to sign-in (the normal session, if any, is left untouched).
func TestBreakGlassActivateWithoutOffer(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)
	mintScanToken(t, srv, c, "Lab 1", "g")
	csrf := denialCSRF(t, c)
	// Drop the offer but keep the valid CSRF token.
	delete(c.cookies, session.OfferCookie)

	rec := c.postForm("/break/activate", url.Values{"csrf": {csrf}})
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 to login", rec.Code)
	}
	if rec := c.get("/verify", requireGroups("g")); rec.Code == http.StatusOK {
		t.Error("activation without an offer granted access")
	}
}

// A session-less visitor (e.g. the normal session expired after the scan) is not
// offered one-tap emergency access -- the denial page hides the button, and a
// forced activation is refused and grants nothing. They must re-scan the physical
// code, which grants directly.
func TestBreakGlassActivateRequiresLiveSession(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)
	mintScanToken(t, srv, c, "Lab 1", "g")
	csrf := denialCSRF(t, c) // button + token present while signed in

	// Session expires; the offer and CSRF cookies remain.
	delete(c.cookies, session.SessionCookie)

	// The denial page no longer offers emergency access.
	body := c.get("/denied?rd=https://app.example.com/", nil).Body.String()
	if strings.Contains(body, "Use emergency access") {
		t.Error("emergency button shown to a session-less visitor")
	}
	// A forced activation grants nothing.
	rec := c.postForm("/break/activate", url.Values{"csrf": {csrf}})
	if rec.Code == http.StatusFound {
		t.Fatalf("session-less activation succeeded (status %d)", rec.Code)
	}
	if c.cookies[session.SessionCookie] != nil {
		t.Error("session-less activation minted a session")
	}
}

// A card revoked between scan and activation grants nothing.
func TestBreakGlassActivateRevokedCode(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "user@example.com", nil)
	token := mintScanToken(t, srv, c, "Lab 1", "g")

	csrf := denialCSRF(t, c)
	code, _, _ := srv.store.LookupBreakGlassByTokenHash(context.Background(), otp.Hash(token))
	if err := srv.store.RevokeBreakGlassCode(context.Background(), code.ID); err != nil {
		t.Fatal(err)
	}
	rec := c.postForm("/break/activate", url.Values{"csrf": {csrf}})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("activate revoked = %d, want 404", rec.Code)
	}
	if rec := c.get("/verify", requireGroups("g")); rec.Code == http.StatusOK {
		t.Error("activation of a revoked card granted access")
	}
}

// An existing break-glass session has no richer identity to preserve, so a
// further scan mints a fresh grant rather than deferring.
func TestBreakGlassScanOverBreakGlassGrantsFresh(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv.Handler())
	t1 := mintCode(t, srv, "Lab 1", "g1")
	if rec := c.get("/break/"+t1, nil); rec.Code != http.StatusFound {
		t.Fatalf("first scan = %d", rec.Code)
	}
	t2 := mintCode(t, srv, "Lab 2", "g2")
	if rec := c.get("/break/"+t2, nil); rec.Code != http.StatusFound {
		t.Fatalf("second scan = %d", rec.Code)
	}
	if c.cookies[session.OfferCookie] != nil {
		t.Error("scan over a break-glass session should not defer to an offer")
	}
	// The latest grant governs: the session now reaches g2.
	if rec := c.get("/verify", requireGroups("g2")); rec.Code != http.StatusOK {
		t.Fatalf("/verify g2 after re-scan = %d, want 200", rec.Code)
	}
	events, _ := srv.store.ListBreakGlassEvents(context.Background(), 0, 10, 0)
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2 grants", len(events))
	}
	for _, e := range events {
		if e.Outcome != store.OutcomeGranted {
			t.Errorf("outcome = %q, want all granted", e.Outcome)
		}
	}
}

// mintScanToken mints a card and scans it as the (already signed-in) client,
// leaving a pending offer. Returns the raw token.
func mintScanToken(t *testing.T, srv *Server, c *client, label, group string) string {
	t.Helper()
	token := mintCode(t, srv, label, group)
	if rec := c.get("/break/"+token, nil); rec.Code != http.StatusFound {
		t.Fatalf("scan status = %d, want 302", rec.Code)
	}
	if c.cookies[session.OfferCookie] == nil {
		t.Fatal("expected an offer cookie after scanning while signed in")
	}
	return token
}

// denialCSRF loads the denial page (which, with an offer pending, sets the CSRF
// cookie and embeds the token in the activation form) and returns the token.
func denialCSRF(t *testing.T, c *client) string {
	t.Helper()
	return extractCSRF(t, c.get("/denied?rd=https://app.example.com/", nil).Body.String())
}
