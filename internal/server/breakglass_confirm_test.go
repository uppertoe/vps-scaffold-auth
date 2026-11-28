package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/breakglass"
	"github.com/uppertoe/vps-scaffold-auth/internal/otp"
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
		"This card opens g-g.",
		"Each use is recorded, and the administrators are notified.",
		`<form method="post" action="/break">`,
		`name="token" value="` + token + `"`,
		"Continue to g-g",
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
	if rec := c.get("/verify", groupGuard(t, srv, "g")); rec.Code != http.StatusOK {
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

// A card made for a group before app roles names no app and opens nothing.
// Its scan page, its grant, an administrator's test scan and the one-tap
// activation are all refused with the neutral page, each scan is recorded,
// and the card is never marked tested.
func TestGroupCardOpensNothing(t *testing.T) {
	srv, sender := testServer(t)
	ctx := context.Background()
	// A list that would admit its members to an app, had the card's session
	// carried it.
	groupGuard(t, srv, "bg_ward")
	token := mintGroupCode(t, srv, "Lab 1")
	code, _, err := srv.store.LookupBreakGlassByTokenHash(ctx, otp.Hash(token))
	if err != nil {
		t.Fatal(err)
	}

	c := newClient(t, srv.Handler())
	if rec := c.get("/break/"+token, nil); rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "Continue with emergency access") {
		t.Fatalf("scan page = %d, want the neutral page", rec.Code)
	}
	rec := c.postForm("/break", url.Values{"token": {token}})
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), msgCardUnknownTitle) {
		t.Fatalf("grant = %d, want the neutral page", rec.Code)
	}
	if c.cookies[session.SessionCookie] != nil {
		t.Fatal("a card that names no app granted a session")
	}
	events, _ := srv.store.ListBreakGlassEvents(ctx, 0, 10, 0)
	if len(events) != 2 || events[0].Outcome != store.OutcomeRefusedTarget || events[1].Outcome != store.OutcomeRefusedTarget {
		t.Fatalf("events = %+v, want two 'refused_target'", events)
	}

	// An administrator's test scan is refused too, and does not mark the
	// card tested.
	admin := newClient(t, srv.Handler())
	loginAs(t, admin, sender, "admin@example.com", nil)
	if rec := admin.get("/break/"+token, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("test scan = %d, want the neutral page", rec.Code)
	}
	if got, _, _ := srv.store.GetBreakGlassCode(ctx, code.ID); !got.TestedAt.IsZero() {
		t.Error("a test scan marked a card that names no app tested")
	}

	// A signed-in person's scan is refused before any offer is made.
	signedIn := newClient(t, srv.Handler())
	loginAs(t, signedIn, sender, "user@example.com", nil)
	if rec := signedIn.postForm("/break", url.Values{"token": {token}}); rec.Code != http.StatusNotFound {
		t.Fatalf("signed-in scan = %d, want the neutral page", rec.Code)
	}
	// An offer for the card, as an earlier release could have made, is
	// refused at activation.
	offer := httptest.NewRecorder()
	if err := srv.sessions.SetOffer(offer, session.Offer{CodeID: code.ID, Label: code.Label, Gen: cardGeneration(code)}, time.Minute, srv.now()); err != nil {
		t.Fatal(err)
	}
	for _, ck := range offer.Result().Cookies() {
		signedIn.cookies[ck.Name] = ck
	}
	csrf := extractCSRF(t, signedIn.get("/denied?rd=https://app.example.com/", nil).Body.String())
	if rec := signedIn.postForm("/break/activate", url.Values{"csrf": {csrf}}); rec.Code != http.StatusNotFound {
		t.Fatalf("activate = %d, want the neutral page", rec.Code)
	}
	if id := sessionOf(t, srv, signedIn); id.Kind == session.KindBreakGlass {
		t.Fatal("activation granted a card that names no app")
	}
}

// A card session that carries a group was started by an earlier release
// from a group card. It holds nothing: not its group's roles, and not its
// card's app, even after the card was moved onto that app. A session issued
// as a scan issues one today, with no groups, holds the app's User role.
func TestOldGroupCardSessionHoldsNothing(t *testing.T) {
	srv, _ := testServer(t)
	guard := groupGuard(t, srv, "bg_ward")
	token := mintCode(t, srv, "Ward", "bg_ward")
	code, _, err := srv.store.LookupBreakGlassByTokenHash(context.Background(), otp.Hash(token))
	if err != nil {
		t.Fatal(err)
	}
	card := session.Identity{Email: "breakglass:Ward", Kind: session.KindBreakGlass, Card: code.ID, CardCode: code.TokenHash}
	old := card
	old.Groups = "bg_ward"
	if rec := mintSession(t, srv, old, time.Hour).get("/verify", guard); rec.Code == http.StatusOK {
		t.Error("a card session that carries a group was admitted")
	}
	if rec := mintSession(t, srv, card, time.Hour).get("/verify", guard); rec.Code != http.StatusOK {
		t.Errorf("a card session with no groups = %d, want 200", rec.Code)
	}
}

// mintCardAs inserts a card with the app and role given, written to the
// store directly as an older or hand-edited row could be, and returns its
// token.
func mintCardAs(t *testing.T, srv *Server, label, app, role string) string {
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
		Label: label, App: app, Role: role, TokenEnc: enc, TokenHash: otp.Hash(token),
	}); err != nil {
		t.Fatal(err)
	}
	srv.forgetRoles()
	return token
}

// assertCardRefused checks that a card's scan page and its grant are both
// refused with the neutral page, recorded as refused_target, and start no
// session.
func assertCardRefused(t *testing.T, srv *Server, token string) {
	t.Helper()
	c := newClient(t, srv.Handler())
	if rec := c.get("/break/"+token, nil); rec.Code != http.StatusNotFound {
		t.Errorf("scan page = %d, want the neutral page", rec.Code)
	}
	if rec := c.postForm("/break", url.Values{"token": {token}}); rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), msgCardUnknownTitle) {
		t.Errorf("grant = %d, want the neutral page", rec.Code)
	}
	if c.cookies[session.SessionCookie] != nil {
		t.Error("the card started a session")
	}
	events, _ := srv.store.ListBreakGlassEvents(context.Background(), 0, 10, 0)
	if len(events) != 2 || events[0].Outcome != store.OutcomeRefusedTarget || events[1].Outcome != store.OutcomeRefusedTarget {
		t.Errorf("events = %+v, want two 'refused_target'", events)
	}
}

// A card for a declared app but a role other than User is refused: a card
// holds only the User role, whatever its row says.
func TestCardForAnotherRoleIsRefused(t *testing.T) {
	srv, _, _ := cardsAdmin(t)
	assertCardRefused(t, srv, mintCardAs(t, srv, "Pharmacy", "neverdrugs", "editor"))
}

// A card with the User role but no app is refused.
func TestCardForUserWithNoAppIsRefused(t *testing.T) {
	srv, _, _ := cardsAdmin(t)
	assertCardRefused(t, srv, mintCardAs(t, srv, "Pharmacy", "", store.RoleUser))
}
