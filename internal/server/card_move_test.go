package server

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/otp"
	"github.com/uppertoe/vps-scaffold-auth/internal/roles"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// NeverDrugs live, with an admin role and two card pages; Caffeine live
// with no card pages.
const testMoveLive = testCardManifest +
	"neverdrugs\tadmin\tAdministrator\tneverdrugs.{$DOMAIN}\n" +
	"@path\tneverdrugs\t/admin/*\tadmin\n"

// NeverDrugs still on its older guard; Caffeine live.
const testMovePending = "neverdrugs\tuser\tUser\tneverdrugs.{$DOMAIN}\n" +
	"neverdrugs\tadmin\tAdministrator\tneverdrugs.{$DOMAIN}\n" +
	"@label\tneverdrugs\tNeverDrugs\n" +
	"@pending\tneverdrugs\n" +
	"caffeine\tuser\tUser\tcaffeine.{$DOMAIN}\n" +
	"@label\tcaffeine\tCaffeine\n" +
	"@path\tcaffeine\t*\tuser\n"

// olderGuard is the headers of NeverDrugs' older guard, which admits the
// group bg_nd.
var olderGuard = map[string]string{"X-Auth-Policy": "groups=bg_nd", "X-Forwarded-Host": "neverdrugs.example.com"}

// moveAdmin is a server with manifest, two administrators, a client signed
// in as the first, and a card for Theatre 3 that opens the group bg_nd.
func moveAdmin(t *testing.T, manifest string) (*Server, *captureSender, *client, int64, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app-roles.tsv")
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, sender := testServerWith(t, func(c *config.Config) {
		c.AppRolesFile = path
		c.AdminEmails = []string{"admin@example.com", "boss@example.com"}
	})
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	token := mintCode(t, srv, "Theatre 3", "bg_nd")
	code, ok, err := srv.store.LookupBreakGlassByTokenHash(context.Background(), otp.Hash(token))
	if err != nil || !ok {
		t.Fatalf("card: %v %v", ok, err)
	}
	return srv, sender, c, code.ID, token
}

// switchTo replaces the manifest, as a deploy that moves a site does.
func switchTo(srv *Server, manifest string) {
	srv.appRoles = roles.ParseManifest(strings.NewReader(manifest), "example.com", nil)
	srv.forgetRoles()
}

func postMove(t *testing.T, c *client, id int64, app, page string) *httptest.ResponseRecorder {
	t.Helper()
	sid := strconv.FormatInt(id, 10)
	form := url.Values{"csrf": {csrfOf(t, c, "/admin/break/"+sid)}, "app": {app}}
	if page != "" {
		form.Set("page."+app, page)
	}
	return c.postForm("/admin/break/"+sid+"/move", form)
}

func getCard(t *testing.T, srv *Server, id int64) store.BreakGlassCode {
	t.Helper()
	c, ok, err := srv.store.GetBreakGlassCode(context.Background(), id)
	if err != nil || !ok {
		t.Fatalf("card %d: %v %v", id, ok, err)
	}
	return c
}

// Moving a group card keeps its token, label, note and design, and points it
// at the app's user role and one of the app's card pages. The move is
// audited and emailed once to the other administrator. A later scan is
// admitted by the app's role guard as its user and nowhere else; a session
// started before the move keeps its group.
func TestMoveGroupCardToApp(t *testing.T) {
	srv, sender, c, id, token := moveAdmin(t, testMoveLive)
	ctx := context.Background()
	sid := strconv.FormatInt(id, 10)
	before := getCard(t, srv, id)

	// A scan before the move: the older guard admits it, a role guard does not.
	early := newClient(t, srv.Handler())
	if rec := early.scan(token); rec.Code != http.StatusFound {
		t.Fatalf("scan = %d", rec.Code)
	}
	if rec := early.get("/verify", olderGuard); rec.Code != http.StatusOK {
		t.Fatalf("older guard before the move = %d", rec.Code)
	}
	wantDenied(t, "a group card on a role guard", early.get("/verify", roleGuard("neverdrugs", "")))

	// The card's page offers the move, and confirms it in place.
	body := html.UnescapeString(c.get("/admin/break/"+sid, nil).Body.String())
	for _, want := range []string{msgMoveAction, fmt.Sprintf(msgMoveIntro, "bg_nd"), "?confirm=move#move"} {
		if !strings.Contains(body, want) {
			t.Errorf("card page lacks %q", want)
		}
	}
	body = html.UnescapeString(c.get("/admin/break/"+sid+"?confirm=move", nil).Body.String())
	for _, want := range []string{fmt.Sprintf(msgMoveChoose, "Theatre 3"), msgMoveKeeps, fmt.Sprintf(msgMoveNext, "bg_nd"),
		fmt.Sprintf(msgMoveSessions, renewWithin(srv.cfg.BreakGlassSessionTTL)), "Drug search", "neverdrugs.example.com/search",
		msgCardNoPages, `action="/admin/break/` + sid + `/move"`, msgMoveButton} {
		if !strings.Contains(body, want) {
			t.Errorf("move confirmation lacks %q", want)
		}
	}
	if got := getCard(t, srv, id); got.App != "" || !got.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("the confirmation changed the card: %+v", got)
	}

	// A landing page must be one of the app's card pages.
	for name, try := range map[string][2]string{
		"a page no card page names":  {"neverdrugs", "/admin/x"},
		"no page":                    {"neverdrugs", ""},
		"an app with no card pages":  {"caffeine", "/"},
		"an app not in the manifest": {"roster", "/"},
	} {
		rec := postMove(t, c, id, try[0], try[1])
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: move = %d, want 400", name, rec.Code)
		}
	}
	if got := getCard(t, srv, id); got.App != "" || got.TargetGroup != "bg_nd" {
		t.Fatalf("a refused move changed the card: %+v", got)
	}

	sender.reset()
	rec := postMove(t, c, id, "neverdrugs", "/search")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/admin/break/"+sid {
		t.Fatalf("move = %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	after := getCard(t, srv, id)
	if after.TokenHash != before.TokenHash || after.TokenEnc != before.TokenEnc || after.Label != before.Label ||
		after.Note != before.Note || after.DesignID != before.DesignID || after.Status != store.BreakGlassActive {
		t.Errorf("the move changed what it keeps: %+v, was %+v", after, before)
	}
	if after.App != "neverdrugs" || after.Role != store.RoleUser || after.TargetGroup != "" || after.Redirect != "https://neverdrugs.example.com/search" {
		t.Errorf("moved card = %+v", after)
	}
	events, _ := srv.store.ListAdminEvents(ctx, 10, 0)
	if len(events) == 0 || events[0].Action != store.AdminActionBreakMove || events[0].Target != "Theatre 3" ||
		events[0].Detail != "group=bg_nd app=neverdrugs page=/search" {
		t.Errorf("audit = %+v", events)
	}
	if adminActionLabels[store.AdminActionBreakMove] == "" {
		t.Error("the move has no audit label")
	}
	mail := mailWithSubject(sender, "The break-glass card for Theatre 3 has been moved to NeverDrugs.")
	if len(mail) != 1 || mail[0].To != "boss@example.com" || !strings.Contains(mail[0].Text, "no longer opens the group bg_nd") {
		t.Fatalf("emails = %+v", mail)
	}
	body = html.UnescapeString(c.get("/admin/break/"+sid, nil).Body.String())
	if !strings.Contains(body, adminNotices["card-moved"]) || !strings.Contains(body, "Opens NeverDrugs") || strings.Contains(body, msgMoveAction) {
		t.Errorf("card page after the move:\n%s", body)
	}

	// The session started before the move keeps its group until it ends.
	if rec := early.get("/verify", olderGuard); rec.Code != http.StatusOK {
		t.Errorf("older guard for a session started before the move = %d", rec.Code)
	}
	// That session keeps only the group: a role guard does not admit it to
	// the app the card now names.
	wantDenied(t, "a session started before the move, on the app's role guard", early.get("/verify", roleGuard("neverdrugs", "")))

	// A scan after the move: the app as its user, and nothing else.
	later := newClient(t, srv.Handler())
	if rec := later.scan(token); rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://neverdrugs.example.com/search" {
		t.Fatalf("scan after the move = %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := later.get("/verify", roleGuard("neverdrugs", "")); rec.Code != http.StatusOK || rec.Header().Get("Remote-Roles") != "user" {
		t.Fatalf("role guard after the move = %d %q", rec.Code, rec.Header().Get("Remote-Roles"))
	}
	wantDenied(t, "the app's admin role", later.get("/verify", roleGuard("neverdrugs", "admin")))
	wantDenied(t, "another app", later.get("/verify", roleGuard("caffeine", "")))
	wantDenied(t, "the older guard of the group", later.get("/verify", olderGuard))

	// The list shows the card under its app, and no longer as a group card.
	body = html.UnescapeString(c.get("/admin/break", nil).Body.String())
	if strings.Contains(body, msgLegacyHeading) || !strings.Contains(body, "New card for NeverDrugs") || !strings.Contains(body, "Theatre 3") {
		t.Errorf("cards list after the move:\n%s", body)
	}

	// A card that names an app is not moved again.
	rec = postMove(t, c, id, "neverdrugs", "/")
	if rec.Code != http.StatusFound || getCard(t, srv, id).Redirect != "https://neverdrugs.example.com/search" {
		t.Errorf("second move = %d, card %+v", rec.Code, getCard(t, srv, id))
	}
}

// The move needs the page's CSRF token and an administrator.
func TestMoveCardCSRFAndAdminOnly(t *testing.T) {
	srv, sender, c, id, _ := moveAdmin(t, testMoveLive)
	sid := strconv.FormatInt(id, 10)
	form := url.Values{"app": {"neverdrugs"}, "page.neverdrugs": {"/"}}
	if rec := c.postForm("/admin/break/"+sid+"/move", form); rec.Code != http.StatusForbidden {
		t.Errorf("no CSRF = %d, want 403", rec.Code)
	}
	form.Set("csrf", "forged")
	if rec := c.postForm("/admin/break/"+sid+"/move", form); rec.Code != http.StatusForbidden {
		t.Errorf("forged CSRF = %d, want 403", rec.Code)
	}
	// Anyone but an administrator is sent to sign in before the form is read.
	user := newClient(t, srv.Handler())
	loginAs(t, user, sender, "user@example.com", nil)
	anon := newClient(t, srv.Handler())
	for name, cl := range map[string]*client{"a signed-in user": user, "no session": anon} {
		rec := cl.postForm("/admin/break/"+sid+"/move", form)
		if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/login?") {
			t.Errorf("%s: move = %d to %q, want sign in", name, rec.Code, rec.Header().Get("Location"))
		}
	}
	if got := getCard(t, srv, id); got.App != "" || got.TargetGroup != "bg_nd" {
		t.Fatalf("card moved without an administrator: %+v", got)
	}
}

// While NeverDrugs is still on its older guard, the move is refused: a moved
// card's scan carries no group, so the older guard would refuse it. The card
// keeps working there. Once NeverDrugs moves to roles, the move is offered
// and the moved card is admitted by the role guard.
func TestMoveCardOnlyOnceTheAppIsLive(t *testing.T) {
	for _, order := range []string{"move then switch", "switch then move"} {
		t.Run(order, func(t *testing.T) {
			srv, _, c, id, token := moveAdmin(t, testMovePending)
			sid := strconv.FormatInt(id, 10)
			if order == "move then switch" {
				body := html.UnescapeString(c.get("/admin/break/"+sid+"?confirm=move", nil).Body.String())
				if !strings.Contains(body, fmt.Sprintf(msgMoveAppPending, "NeverDrugs")) {
					t.Errorf("the pending app is offered:\n%s", body)
				}
				rec := postMove(t, c, id, "neverdrugs", "/")
				if rec.Code != http.StatusBadRequest || !strings.Contains(html.UnescapeString(rec.Body.String()), fmt.Sprintf(msgMoveRefusedPending, "NeverDrugs")) {
					t.Fatalf("move to a pending app = %d", rec.Code)
				}
				if got := getCard(t, srv, id); got.App != "" || got.TargetGroup != "bg_nd" {
					t.Fatalf("card = %+v", got)
				}
				// The card still works under the older guard.
				anon := newClient(t, srv.Handler())
				anon.scan(token)
				if rec := anon.get("/verify", olderGuard); rec.Code != http.StatusOK {
					t.Fatalf("older guard before the switch = %d", rec.Code)
				}
			}
			switchTo(srv, testMoveLive)
			if rec := postMove(t, c, id, "neverdrugs", "/"); rec.Code != http.StatusFound {
				t.Fatalf("move after the switch = %d", rec.Code)
			}
			anon := newClient(t, srv.Handler())
			if rec := anon.scan(token); rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://neverdrugs.example.com/" {
				t.Fatalf("scan = %d to %q", rec.Code, rec.Header().Get("Location"))
			}
			if rec := anon.get("/verify", roleGuard("neverdrugs", "")); rec.Code != http.StatusOK || rec.Header().Get("Remote-Roles") != "user" {
				t.Fatalf("role guard = %d %q", rec.Code, rec.Header().Get("Remote-Roles"))
			}
		})
	}
}

// The legacy note says how to keep a group card working, and is not shown
// as such without app roles.
func TestLegacyNoteNamesTheMove(t *testing.T) {
	_, _, c, _, _ := moveAdmin(t, testMoveLive)
	body := html.UnescapeString(c.get("/admin/break", nil).Body.String())
	if !strings.Contains(body, msgLegacyHeading) || !strings.Contains(body, msgLegacyNote) || !strings.Contains(msgLegacyNote, msgMoveAction) {
		t.Errorf("cards list:\n%s", body)
	}
}

// A scan that read the card before a move and issued its session after it
// carries the group, and is treated as a session started before the move:
// the older guard admits it until it ends, and the app's role guard does not.
func TestMoveLandingDuringAScan(t *testing.T) {
	srv, _, c, id, _ := moveAdmin(t, testMoveLive)
	stale := getCard(t, srv, id)
	if rec := postMove(t, c, id, "neverdrugs", "/"); rec.Code != http.StatusFound {
		t.Fatalf("move = %d", rec.Code)
	}
	// The scan's grant, with the card as it read it before the move.
	req := httptest.NewRequest(http.MethodPost, "/break", nil)
	rec := httptest.NewRecorder()
	srv.grantBreakGlass(rec, req, stale, "10.0.0.1", "test", srv.now())
	if rec.Code != http.StatusFound {
		t.Fatalf("grant = %d", rec.Code)
	}
	racer := newClient(t, srv.Handler())
	for _, ck := range rec.Result().Cookies() {
		racer.cookies[ck.Name] = ck
	}
	if id := sessionOf(t, srv, racer); id.Groups != "bg_nd" {
		t.Fatalf("session = %+v", id)
	}
	if rec := racer.get("/verify", olderGuard); rec.Code != http.StatusOK {
		t.Errorf("older guard = %d, want 200", rec.Code)
	}
	wantDenied(t, "the app's role guard", racer.get("/verify", roleGuard("neverdrugs", "")))
}
