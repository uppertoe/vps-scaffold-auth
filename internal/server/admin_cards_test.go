package server

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/email"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// A manifest with card pages: NeverDrugs offers two, Caffeine none.
const testCardManifest = "neverdrugs\tuser\tUser\tneverdrugs.{$DOMAIN}\n" +
	"@label\tneverdrugs\tNeverDrugs\n" +
	"@path\tneverdrugs\t*\tuser\n" +
	"@card-page\tneverdrugs\t/\tNeverDrugs home page\n" +
	"@card-page\tneverdrugs\t/search\tDrug search\n" +
	"caffeine\tuser\tUser\tcaffeine.{$DOMAIN}\n" +
	"caffeine\tadmin\tAdministrator\tcaffeine.{$DOMAIN}\n" +
	"@label\tcaffeine\tCaffeine\n" +
	"@path\tcaffeine\t/admin/*\tadmin\n" +
	"@path\tcaffeine\t*\tuser\n"

// cardsAdmin is a server with card pages in its manifest, a domain group
// "staff" (example.com and mcri.edu.au) holding NeverDrugs, two
// administrators, and a client signed in as the first.
func cardsAdmin(t *testing.T) (*Server, *captureSender, *client) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app-roles.tsv")
	if err := os.WriteFile(path, []byte(testCardManifest), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, sender := testServerWith(t, func(c *config.Config) {
		c.AppRolesFile = path
		c.AdminEmails = []string{"admin@example.com", "boss@example.com"}
	})
	mustDomainGroup(t, srv, "staff", "example.com", "mcri.edu.au")
	mustAssign(t, srv, store.RoleAssignment{App: "neverdrugs", Role: "user", Kind: store.AssignDomainGroup, Ref: "staff"})
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	return srv, sender, c
}

func firstDesign(t *testing.T, srv *Server) store.CardDesign {
	t.Helper()
	ds, err := srv.store.ListCardDesigns(context.Background())
	if err != nil || len(ds) == 0 {
		t.Fatalf("designs %v %v", ds, err)
	}
	return ds[0]
}

// newCard creates a card through the form and returns its id and token.
func newCard(t *testing.T, srv *Server, c *client, label, page string) (int64, string) {
	t.Helper()
	d := firstDesign(t, srv)
	rec := c.postForm("/admin/break", url.Values{"csrf": {csrfOf(t, c, "/admin/break/new")}, "label": {label}, "app": {"neverdrugs"},
		"page.neverdrugs": {page}, "design": {strconv.FormatInt(d.ID, 10)}})
	if rec.Code != http.StatusFound {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	id, err := strconv.ParseInt(strings.TrimPrefix(rec.Header().Get("Location"), "/admin/break/"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	code, _, _ := srv.store.GetBreakGlassCode(context.Background(), id)
	token, err := srv.secrets.Open(code.TokenEnc)
	if err != nil {
		t.Fatal(err)
	}
	return id, token
}

// A card opens one of its app's card pages, as the app's user and nothing
// more; any other page, app or role is refused. Creation is audited and
// emailed once to the other administrator.
func TestNewCardOpensOnlyCardPagesAsUser(t *testing.T) {
	srv, sender, c := cardsAdmin(t)
	ctx := context.Background()
	d := firstDesign(t, srv)
	base := func() url.Values {
		return url.Values{"csrf": {csrfOf(t, c, "/admin/break/new")}, "label": {"PICU bed 4"}, "design": {strconv.FormatInt(d.ID, 10)}}
	}
	for name, extra := range map[string]url.Values{
		"a path no card page names":  {"app": {"neverdrugs"}, "page.neverdrugs": {"/admin"}},
		"an app with no card pages":  {"app": {"caffeine"}, "page.caffeine": {"/"}},
		"an app not in the manifest": {"app": {"roster"}, "page.roster": {"/"}},
	} {
		form := base()
		for k, v := range extra {
			form[k] = v
		}
		if rec := c.postForm("/admin/break", form); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: create = %d, want 400", name, rec.Code)
		}
	}
	if codes, _ := srv.store.ListBreakGlassCodes(ctx); len(codes) != 0 {
		t.Fatalf("refused forms stored %+v", codes)
	}

	sender.reset()
	form := base()
	form.Set("app", "neverdrugs")
	form.Set("page.neverdrugs", "/search")
	form.Set("role", "admin") // a card holds the user role whatever the form says
	form.Set("note", "Inside the drug fridge door")
	if rec := c.postForm("/admin/break", form); rec.Code != http.StatusFound {
		t.Fatalf("create = %d", rec.Code)
	}
	codes, _ := srv.store.ListBreakGlassCodes(ctx)
	if len(codes) != 1 {
		t.Fatalf("codes = %+v", codes)
	}
	got := codes[0]
	if got.App != "neverdrugs" || got.Role != store.RoleUser || got.TargetGroup != "" || got.Redirect != "https://neverdrugs.example.com/search" || got.DesignID != d.ID || got.Note != "Inside the drug fridge door" {
		t.Errorf("card = %+v", got)
	}
	events, _ := srv.store.ListAdminEvents(ctx, 10, 0)
	if len(events) == 0 || events[0].Action != store.AdminActionBreakCreate || events[0].Target != "PICU bed 4" {
		t.Errorf("audit = %+v", events)
	}
	mail := mailWithSubject(sender, "A break-glass card has been created for NeverDrugs.")
	if len(mail) != 1 || mail[0].To != "boss@example.com" {
		t.Fatalf("emails = %+v", mail)
	}
	// A second card for the same place is refused.
	if rec := c.postForm("/admin/break", form); rec.Code != http.StatusBadRequest || !strings.Contains(html.UnescapeString(rec.Body.String()), "A card for PICU bed 4 already exists.") {
		t.Errorf("duplicate = %d", rec.Code)
	}
}

// Every card page renders, and its drawings are served.
func TestCardPagesRender(t *testing.T) {
	srv, _, c := cardsAdmin(t)
	id, _ := newCard(t, srv, c, "Angiography Lab 1", "/")
	d := firstDesign(t, srv)
	sid, did := strconv.FormatInt(id, 10), strconv.FormatInt(d.ID, 10)
	pages := map[string][]string{
		"/admin/break":                             {"Break-glass cards", "New card for NeverDrugs", "has never been tested"},
		"/admin/break/new?app=neverdrugs":          {"Which page should a scan open?", "Drug search", "neverdrugs.example.com/search", "One card already", "Create the card"},
		"/admin/break/" + sid:                      {"Opens NeverDrugs for whoever holds it", "NeverDrugs home page", "Download the PDF", "Replace or withdraw the card", "Nobody has scanned this card yet."},
		"/admin/break/" + sid + "?confirm=replace": {"Replace the card for Angiography Lab 1?", "Keep the card"},
		"/admin/break/designs":                     {"Department standard", "One card uses it · A6"},
		"/admin/break/designs/" + did:              {"One active card uses this design.", "Saving changes one card.", "Easiest to read", "Postcard, 105 × 148 mm"},
		"/admin/break/designs/new":                 {"This design is not saved yet.", "Saving adds the design to the list."},
		"/admin/apps/neverdrugs":                   {"Create a break-glass card for this role", "/admin/break/new?app=neverdrugs"},
	}
	for path, wants := range pages {
		rec := c.get(path, nil)
		body := html.UnescapeString(rec.Body.String())
		if rec.Code != http.StatusOK || strings.Contains(body, "internal error") {
			t.Errorf("%s = %d", path, rec.Code)
			continue
		}
		for _, w := range wants {
			if !strings.Contains(body, w) {
				t.Errorf("%s lacks %q", path, w)
			}
		}
	}
	for _, path := range []string{"/admin/break/" + sid + "/card.svg", "/admin/break/preview.svg?design=" + did + "&label=X&app=NeverDrugs",
		"/admin/break/designs/" + did + "/card.svg", "/admin/break/designs/preview.svg?id=" + did + "&draft=1&size=A4&name=x&steps=One"} {
		rec := c.get(path, nil)
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "image/svg+xml" || !strings.HasPrefix(rec.Body.String(), "<svg") {
			t.Errorf("%s = %d %q", path, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
	// Downloading the PDF is recorded on the card's page.
	if rec := c.get("/admin/break/"+sid+"/pdf", nil); rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), "%PDF") {
		t.Fatalf("pdf = %d", rec.Code)
	}
	if code, _, _ := srv.store.GetBreakGlassCode(context.Background(), id); code.PDFAt.IsZero() {
		t.Error("the download was not recorded")
	}
	// The old branding page of one card is gone.
	if rec := c.get("/admin/break/"+sid+"/branding", nil); rec.Code != http.StatusNotFound {
		t.Errorf("old card branding route = %d", rec.Code)
	}
}

// An administrator's scan is a test: it grants nothing and marks the card
// tested. Anyone else's scan grants nothing until Continue is pressed.
func TestAdminScanIsATest(t *testing.T) {
	srv, _, c := cardsAdmin(t)
	ctx := context.Background()
	id, token := newCard(t, srv, c, "Angiography Lab 1", "/")
	before := sessionOf(t, srv, c)

	rec := c.get("/break/"+token, nil)
	body := html.UnescapeString(rec.Body.String())
	if rec.Code != http.StatusOK || !strings.Contains(body, "The card works") ||
		!strings.Contains(body, "You are signed in as an administrator, so the scan has been recorded as a test and has not given emergency access.") ||
		!strings.Contains(body, "Open the card's page") || strings.Contains(body, `action="/break"`) {
		t.Fatalf("admin scan = %d:\n%s", rec.Code, body)
	}
	if after := sessionOf(t, srv, c); after.Kind != "" || after.Email != before.Email {
		t.Fatalf("the test changed the session: %+v", after)
	}
	code, _, _ := srv.store.GetBreakGlassCode(ctx, id)
	if code.TestedAt.IsZero() {
		t.Error("the card was not marked tested")
	}
	events, _ := srv.store.ListBreakGlassEvents(ctx, id, 10, 0)
	if len(events) != 1 || events[0].Outcome != store.OutcomeTested {
		t.Fatalf("events = %+v", events)
	}

	// Anyone else: the page names the app, and nothing is granted yet.
	anon := newClient(t, srv.Handler())
	rec = anon.get("/break/"+token, nil)
	body = html.UnescapeString(rec.Body.String())
	for _, want := range []string{"This card opens NeverDrugs.", "Each use is recorded, and the administrators are notified.", "Continue to NeverDrugs", `class="band"`} {
		if !strings.Contains(body, want) {
			t.Errorf("scan page lacks %q", want)
		}
	}
	if anon.cookies[session.SessionCookie] != nil {
		t.Fatal("opening the address granted a session")
	}
	if rec := anon.postForm("/break", url.Values{"token": {token}}); rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://neverdrugs.example.com/" {
		t.Fatalf("continue = %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	if id := sessionOf(t, srv, anon); id.Kind != session.KindBreakGlass {
		t.Fatalf("session = %+v", id)
	}
	// The card's session reaching another app sees which app the card opens.
	rec = anon.get("/denied?rd="+url.QueryEscape("https://caffeine.example.com/"), nil)
	body = html.UnescapeString(rec.Body.String())
	for _, want := range []string{"This card does not open this app", "The card for Angiography Lab 1 opens NeverDrugs only.", "Go to NeverDrugs", "Sign in with your email"} {
		if !strings.Contains(body, want) {
			t.Errorf("wrong-app page lacks %q", want)
		}
	}
}

// A withdrawn or a replaced card says so by name, and offers the
// organisations whose domain groups hold a role in its app.
func TestWithdrawnAndReplacedCardPages(t *testing.T) {
	srv, sender, c := cardsAdmin(t)
	ctx := context.Background()
	mustOrg(t, srv, "staff", "RCH")
	id, token := newCard(t, srv, c, "Theatre 2", "/")
	sid := strconv.FormatInt(id, 10)
	sender.reset()
	if rec := c.postForm("/admin/break/"+sid+"/revoke", url.Values{"csrf": {csrfOf(t, c, "/admin/break/"+sid)}}); rec.Code != http.StatusFound {
		t.Fatalf("withdraw = %d", rec.Code)
	}
	if mail := mailWithSubject(sender, "The break-glass card for Theatre 2 has been withdrawn."); len(mail) != 1 || mail[0].To != "boss@example.com" {
		t.Errorf("emails = %+v", mail)
	}
	anon := newClient(t, srv.Handler())
	rec := anon.get("/break/"+token, nil)
	body := html.UnescapeString(rec.Body.String())
	for _, want := range []string{"This card no longer works", "The card for Theatre 2 has been withdrawn.", "If you have an RCH email address, you can sign in with it instead.", ">Sign in</a>"} {
		if !strings.Contains(body, want) {
			t.Errorf("withdrawn page lacks %q:\n%s", want, body)
		}
	}
	if rec.Code != http.StatusNotFound {
		t.Errorf("withdrawn page = %d", rec.Code)
	}

	id2, token2 := newCard(t, srv, c, "Theatre 6", "/")
	sid2 := strconv.FormatInt(id2, 10)
	if rec := c.postForm("/admin/break/"+sid2+"/remint", url.Values{"csrf": {csrfOf(t, c, "/admin/break/"+sid2)}}); rec.Code != http.StatusFound {
		t.Fatalf("replace = %d", rec.Code)
	}
	body = html.UnescapeString(anon.get("/break/"+token2, nil).Body.String())
	if !strings.Contains(body, "The card for Theatre 6 has been replaced.") {
		t.Errorf("replaced page:\n%s", body)
	}
	events, _ := srv.store.ListBreakGlassEvents(ctx, id2, 10, 0)
	if len(events) == 0 || events[0].Outcome != store.OutcomeReplaced {
		t.Errorf("events = %+v", events)
	}
	// An address that never was a card gets the neutral page.
	if rec := anon.get("/break/nothing-here", nil); rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "Access code not available") {
		t.Errorf("unknown = %d", rec.Code)
	}
}

// mailWithSubject waits for the notices and returns those with subject.
func mailWithSubject(sender *captureSender, subject string) []email.Message {
	var out []email.Message
	for _, m := range noticesAfter(sender, 1) {
		if m.Subject == subject {
			out = append(out, m)
		}
	}
	return out
}

// A design in use cannot be deleted; an unused one can. Saving a design is
// audited and emailed once.
func TestDesignInUseAndSave(t *testing.T) {
	srv, sender, c := cardsAdmin(t)
	ctx := context.Background()
	newCard(t, srv, c, "Theatre 6", "/")
	std := firstDesign(t, srv)
	sid := strconv.FormatInt(std.ID, 10)
	rec := c.postForm("/admin/break/designs/"+sid+"/delete", url.Values{"csrf": {csrfOf(t, c, "/admin/break/designs/"+sid)}})
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "because one card uses it") {
		t.Fatalf("delete in use = %d", rec.Code)
	}

	form := url.Values{"csrf": {csrfOf(t, c, "/admin/break/designs/new")}, "name": {"Theatres, light"}, "header": {"#eef2f5"}, "accent": {"#2f6f8f"},
		"bar1": {"#fdb913"}, "bar2": {"#f26c52"}, "bar3": {"#82c341"}, "logo_source": {"none"}, "logo_mode": {"asis"},
		"title": {"Emergency access"}, "steps": {"1. Open the camera.\n2. Tap the link."}, "size": {"A5"}}
	rec = c.postForm("/admin/break/designs", form)
	if rec.Code != http.StatusFound {
		t.Fatalf("create design = %d: %s", rec.Code, rec.Body.String())
	}
	ds, _ := srv.store.ListCardDesigns(ctx)
	if len(ds) != 2 || ds[1].Name != "Theatres, light" || ds[1].Size != "A5" || ds[1].Steps != "Open the camera.\nTap the link." || ds[1].Stripe {
		t.Fatalf("designs = %+v", ds)
	}
	// The name is unique.
	if rec := c.postForm("/admin/break/designs", form); rec.Code != http.StatusConflict {
		t.Errorf("same name = %d", rec.Code)
	}

	sender.reset()
	save := url.Values{"csrf": {csrfOf(t, c, "/admin/break/designs/"+sid)}, "name": {std.Name}, "header": {std.Header}, "header_hex": {"#9b1c1c"}, "header_was": {std.Header},
		"accent": {std.Accent}, "bar1": {std.Bar1}, "bar2": {std.Bar2}, "bar3": {std.Bar3}, "stripe": {"1"}, "logo_source": {"site"},
		"logo_mode": {"white"}, "title": {"Code blue"}, "steps": {std.Steps}, "size": {"A4"}}
	if rec := c.postForm("/admin/break/designs/"+sid+"/save", save); rec.Code != http.StatusFound {
		t.Fatalf("save = %d", rec.Code)
	}
	got, _, _ := srv.store.GetCardDesign(ctx, std.ID)
	if got.Header != "#9b1c1c" || got.Title != "Code blue" || got.Size != "A4" {
		t.Errorf("saved design = %+v", got)
	}
	mail := mailWithSubject(sender, "The card design Department standard has changed.")
	if len(mail) != 1 || !strings.Contains(mail[0].Text, "one card uses it") {
		t.Fatalf("emails = %+v", mail)
	}
	events, _ := srv.store.ListAdminEvents(ctx, 5, 0)
	if events[0].Action != store.AdminActionDesignSave {
		t.Errorf("audit = %+v", events[0])
	}

	// "Update the preview" saves nothing.
	save.Set("csrf", csrfOf(t, c, "/admin/break/designs/"+sid))
	save.Set("title", "Not saved")
	save.Set("preview", "1")
	if rec := c.postForm("/admin/break/designs/"+sid+"/save", save); rec.Code != http.StatusOK {
		t.Errorf("preview = %d", rec.Code)
	}
	if got, _, _ := srv.store.GetCardDesign(ctx, std.ID); got.Title != "Code blue" {
		t.Error("the preview saved the design")
	}

	unused := strconv.FormatInt(ds[1].ID, 10)
	if rec := c.postForm("/admin/break/designs/"+unused+"/delete", url.Values{"csrf": {csrfOf(t, c, "/admin/break/designs/"+unused)}}); rec.Code != http.StatusFound {
		t.Errorf("delete unused = %d", rec.Code)
	}
}

func mustOrg(t *testing.T, srv *Server, group, org string) {
	t.Helper()
	if ok, err := srv.store.SetGroupOrg(context.Background(), group, org); err != nil || !ok {
		t.Fatalf("set the organisation name of %s: %v %v", group, ok, err)
	}
}

// The withdrawn card's page names the organisations of the domain groups
// that hold a role in the card's app, by the names an administrator gave
// them: once each, in the groups' order, joined as a sentence. A group with
// no name is left out, and with no names the sentence is left out.
func TestWithdrawnCardNamesOrganisations(t *testing.T) {
	srv, _, c := cardsAdmin(t)
	_, token := newCard(t, srv, c, "Theatre 2", "/")
	if rec := c.postForm("/admin/break/1/revoke", url.Values{"csrf": {csrfOf(t, c, "/admin/break/1")}}); rec.Code != http.StatusFound {
		t.Fatalf("withdraw = %d", rec.Code)
	}
	page := func() string {
		srv.forgetRoles()
		return html.UnescapeString(newClient(t, srv.Handler()).get("/break/"+token, nil).Body.String())
	}
	// No group has a name: no sentence, and no name guessed from a domain.
	if body := page(); strings.Contains(body, "email address, you can sign in") || strings.Contains(body, "EXAMPLE") || strings.Contains(body, "MCRI") {
		t.Errorf("a page with no organisation names:\n%s", body)
	}
	if !strings.Contains(page(), ">Sign in</a>") {
		t.Error("the page lost its Sign in button")
	}

	mustDomainGroup(t, srv, "mcri", "mcri.edu.au")
	mustDomainGroup(t, srv, "monash", "monashhealth.org")
	mustDomainGroup(t, srv, "unnamed", "health.nsw.gov.au")
	mustDomainGroup(t, srv, "elsewhere", "elsewhere.org")
	mustDomainGroup(t, srv, "rch-too", "rch.org.au")
	for _, g := range []string{"mcri", "monash", "unnamed", "rch-too"} {
		mustAssign(t, srv, store.RoleAssignment{App: "neverdrugs", Role: "user", Kind: store.AssignDomainGroup, Ref: g})
	}
	mustOrg(t, srv, "staff", "RCH")
	mustOrg(t, srv, "rch-too", "RCH")
	mustOrg(t, srv, "mcri", "MCRI")
	if body := page(); !strings.Contains(body, "If you have an MCRI or RCH email address, you can sign in with it instead.") {
		t.Errorf("two names:\n%s", body)
	}
	mustOrg(t, srv, "monash", "Monash Health")
	mustOrg(t, srv, "elsewhere", "Elsewhere") // holds no role in the app
	body := page()
	if !strings.Contains(body, "If you have an MCRI, Monash Health or RCH email address, you can sign in with it instead.") {
		t.Errorf("three names:\n%s", body)
	}
	if strings.Contains(body, "Elsewhere") || strings.Contains(body, "HEALTH") {
		t.Errorf("a group outside the app, or a guessed name, is named:\n%s", body)
	}
	for _, g := range []string{"staff", "rch-too", "mcri", "monash"} {
		mustOrg(t, srv, g, "")
	}
	if body := page(); strings.Contains(body, "you can sign in with it instead") {
		t.Errorf("names cleared, yet:\n%s", body)
	}
}

func TestArticleFor(t *testing.T) {
	for name, want := range map[string]string{"RCH": "an", "MCRI": "an", "Monash Health": "a", "Alfred Health": "an", "NSW Health": "an", "Peter Mac": "a"} {
		if got := articleFor(name); got != want {
			t.Errorf("articleFor(%q) = %q, want %q", name, got, want)
		}
	}
}
