package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

const (
	digestToken = "digest-app-token-0123456789abcdefghij"
	otherToken  = "other-app-token-0123456789abcdefghijkl"
)

// membersServer is a test server with two reader apps: "digest" may read
// coordinators, "other" may read reviewers.
func membersServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	srv, _ := testServer(t)
	srv.members = newMembersAPI([]config.MemberReader{
		{App: "digest", Token: digestToken, Groups: []string{"coordinators", "ghost"}},
		{App: "other", Token: otherToken, Groups: []string{"reviewers"}},
	})
	ctx := context.Background()
	for _, g := range []string{"coordinators", "leads", "reviewers"} {
		if err := srv.store.CreateGroup(ctx, g, ""); err != nil {
			t.Fatal(err)
		}
	}
	// coordinators admits its own members and, through an include, the leads.
	srv.store.AddGroupMember(ctx, "coordinators", "amy@example.com")
	srv.store.AddGroupMember(ctx, "coordinators", "outsider@elsewhere.org") // not on the allow-list
	srv.store.AddGroupMember(ctx, "leads", "bob@example.com")
	srv.store.AddGroupMember(ctx, "reviewers", "cal@example.com")
	if err := srv.store.AddGroupInclude(ctx, "coordinators", "leads"); err != nil {
		t.Fatal(err)
	}
	return srv, srv.MembersHandler()
}

func membersGet(h http.Handler, path, token string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "172.18.0.5:41000"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestMembersEndpointAnswersOnlyTheAppsOwnGroups(t *testing.T) {
	srv, h := membersServer(t)

	rec := membersGet(h, "/v1/groups/coordinators/members", digestToken, nil)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("digest reading coordinators = %d %s", rec.Code, rec.Body)
	}
	var got struct {
		Group   string   `json:"group"`
		Members []string `json:"members"`
		AsOf    string   `json:"as_of"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	// Its own member and the included group's member; not the address the
	// allow-list does not admit.
	if got.Group != "coordinators" || !slices.Equal(got.Members, []string{"amy@example.com", "bob@example.com"}) || got.AsOf == "" {
		t.Errorf("answer = %+v", got)
	}
	// The answer matches what each person is told when they sign in.
	for _, e := range []string{"amy@example.com", "bob@example.com", "cal@example.com"} {
		groups, _ := srv.store.GroupsForEmail(context.Background(), e)
		if slices.Contains(groups, "coordinators") != slices.Contains(got.Members, e) {
			t.Errorf("%s: sign-in groups %v disagree with the members answer", e, groups)
		}
	}

	// One app cannot read another app's group, and a group that does not
	// exist gets the same answer as one the app may not read.
	forbidden := membersGet(h, "/v1/groups/reviewers/members", digestToken, nil)
	missing := membersGet(h, "/v1/groups/ghost/members", digestToken, nil)
	if forbidden.Code != http.StatusForbidden || missing.Code != http.StatusForbidden || forbidden.Body.String() != missing.Body.String() {
		t.Errorf("other app's group = %d %q; missing group = %d %q", forbidden.Code, forbidden.Body, missing.Code, missing.Body)
	}
	for _, reserved := range []string{"admin", "user", "guest"} {
		if rec := membersGet(h, "/v1/groups/"+reserved+"/members", digestToken, nil); rec.Code != http.StatusForbidden {
			t.Errorf("reading %s = %d", reserved, rec.Code)
		}
	}
	if rec := membersGet(h, "/v1/groups/reviewers/members", otherToken, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "cal@example.com") {
		t.Errorf("other reading reviewers = %d %s", rec.Code, rec.Body)
	}
}

func TestMembersEndpointRefusals(t *testing.T) {
	_, h := membersServer(t)
	for name, tc := range map[string]struct {
		token string
		hdr   map[string]string
		want  int
	}{
		"no token":         {"", nil, http.StatusUnauthorized},
		"wrong token":      {"not-a-token-0123456789abcdefghijklmnop", nil, http.StatusUnauthorized},
		"token prefix":     {digestToken[:20], nil, http.StatusUnauthorized},
		"basic auth":       {"", map[string]string{"Authorization": "Basic " + digestToken}, http.StatusUnauthorized},
		"through a proxy":  {digestToken, map[string]string{"X-Forwarded-For": "203.0.113.9"}, http.StatusForbidden},
		"forwarded header": {digestToken, map[string]string{"Forwarded": "for=203.0.113.9"}, http.StatusForbidden},
	} {
		rec := membersGet(h, "/v1/groups/coordinators/members", tc.token, tc.hdr)
		if rec.Code != tc.want || strings.Contains(rec.Body.String(), "amy@") {
			t.Errorf("%s = %d %s, want %d", name, rec.Code, rec.Body, tc.want)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/groups/coordinators/members", nil)
	req.RemoteAddr = "172.18.0.5:41000"
	req.Header.Set("Authorization", "Bearer "+digestToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST = %d", rec.Code)
	}
	// A port published to the internet by mistake keeps the caller's public
	// address, and is refused even with a valid token.
	for _, from := range []string{"203.0.113.9:5000", "[2001:db8::1]:5000", "8.8.8.8:443"} {
		req := httptest.NewRequest(http.MethodGet, "/v1/groups/coordinators/members", nil)
		req.RemoteAddr = from
		req.Header.Set("Authorization", "Bearer "+digestToken)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "amy@") {
			t.Errorf("from %s = %d %s", from, rec.Code, rec.Body)
		}
	}
	for _, from := range []string{"127.0.0.1:5000", "10.0.0.4:5000", "192.168.1.2:5000", "[fd00::2]:5000"} {
		req := httptest.NewRequest(http.MethodGet, "/v1/groups/coordinators/members", nil)
		req.RemoteAddr = from
		req.Header.Set("Authorization", "Bearer "+digestToken)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("from %s = %d", from, rec.Code)
		}
	}
}

// The site Caddy proxies never serves membership, whatever the token.
func TestMembersAreNotServedOnThePublicListener(t *testing.T) {
	srv, _ := membersServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/groups/coordinators/members", nil)
	req.Header.Set("Authorization", "Bearer "+digestToken)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), "amy@example.com") {
		t.Fatalf("public listener answered %d %s", rec.Code, rec.Body)
	}
}

// Every read is recorded, folded to one row per app, group and hour, and the
// access log shows it.
func TestMembersReadsAreAudited(t *testing.T) {
	srv, h := membersServer(t)
	for i := 0; i < 3; i++ {
		membersGet(h, "/v1/groups/coordinators/members", digestToken, nil)
	}
	membersGet(h, "/v1/groups/reviewers/members", digestToken, nil) // refused: not recorded
	reads, err := srv.store.SummariseMemberReads(context.Background(), srv.now().Add(-time.Hour))
	if err != nil || len(reads) != 1 || reads[0].App != "digest" || reads[0].Group != "coordinators" || reads[0].Source != "172.18.0.5" || reads[0].Reads != 3 {
		t.Fatalf("reads = %+v, %v", reads, err)
	}
	sender := srv.sender.(*captureSender)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	page := c.get("/admin/app-feeds", nil).Body.String()
	if !strings.Contains(page, "<h1>Feeds to apps</h1>") || !strings.Contains(page, `<td class="num" data-label="Reads">3</td>`) || !strings.Contains(page, `<code class="mono">172.18.0.5</code>`) {
		t.Error("the App feeds page does not show the reads")
	}
}

// Access configured by the scaffold-rendered file (MEMBER_READERS_FILE): an
// app listed there with its token reads its groups; an app listed without a
// token is refused as an unknown token, and the Access page says it has no
// usable token.
func TestMembersEndpointFromTheReadersFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "member-readers.tsv")
	if err := os.WriteFile(path, []byte("# from the scaffold-members markers\ndigest\tcoordinators\ndigest\trch-staff\nnotoken\treviewers\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"AUTH_PUBLIC_URL": "https://auth.example.com", "DOMAIN": "example.com",
		"ALLOWED_EMAIL_DOMAINS": "example.com", "ADMIN_EMAILS": "admin@example.com",
		"SESSION_SECRET": "0123456789abcdef0123456789abcdef", "EMAIL_BACKEND": "log",
		"COOKIE_INSECURE": "true", "MEMBER_READERS": "",
		"MEMBER_READERS_FILE": path, "MEMBER_READER_TOKEN_DIGEST": digestToken,
	} {
		t.Setenv(k, v)
	}
	loaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	srv, _ := testServerWith(t, func(c *config.Config) {
		c.MemberReaders, c.UnusableMemberReaders = loaded.MemberReaders, loaded.UnusableMemberReaders
	})
	ctx := context.Background()
	for _, g := range []string{"coordinators", "reviewers"} {
		if err := srv.store.CreateGroup(ctx, g, ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := srv.store.CreateGroupOfKind(ctx, "rch-staff", "", store.GroupKindDomain); err != nil {
		t.Fatal(err)
	}
	srv.store.AddGroupMember(ctx, "coordinators", "amy@example.com")
	srv.store.AddGroupMember(ctx, "reviewers", "cal@example.com")
	// The file proposes; an administrator approves (see
	// TestMembersFileReadsNeedApproval for the approval itself).
	for _, g := range []string{"coordinators", "rch-staff"} {
		srv.store.ApproveMemberReader(ctx, "digest", g, "admin@example.com", srv.now())
	}
	h := srv.MembersHandler()
	if rec := membersGet(h, "/v1/groups/rch-staff/members", digestToken, nil); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "domain group has no member list") {
		t.Errorf("digest reading a domain group = %d %s", rec.Code, rec.Body)
	}

	if rec := membersGet(h, "/v1/groups/coordinators/members", digestToken, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "amy@example.com") {
		t.Fatalf("digest reading coordinators = %d %s", rec.Code, rec.Body)
	}
	if rec := membersGet(h, "/v1/groups/reviewers/members", digestToken, nil); rec.Code != http.StatusForbidden {
		t.Errorf("digest reading reviewers = %d", rec.Code)
	}
	// Whatever the app without a token sends, the gateway does not know it.
	if rec := membersGet(h, "/v1/groups/reviewers/members", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token = %d", rec.Code)
	}

	c := newClient(t, srv.Handler())
	loginAs(t, c, srv.sender.(*captureSender), "admin@example.com", nil)
	page := c.get("/admin/app-feeds", nil).Body.String()
	if !strings.Contains(page, "<h1>Feeds to apps</h1>") || !strings.Contains(page, `<code class="mono">notoken</code>`) ||
		!strings.Contains(page, "MEMBER_READER_TOKEN_NOTOKEN") || !strings.Contains(page, "The gateway has no token for this app.") ||
		!strings.Contains(page, `<span class="l">rch-staff</span>`) || !strings.Contains(page, "This is a domain group, which has no member list to read.") ||
		strings.Count(page, `<span class="l">Not usable</span>`) != 2 {
		t.Error("the App feeds page does not show the app without a token")
	}
}

// A domain group has no member list, so a read of one is refused with a
// clear error rather than answered with nobody. The kind is checked at every
// read, so a group created as a domain group after start-up is refused too.
func TestMembersEndpointRefusesDomainGroups(t *testing.T) {
	srv, h := membersServer(t)
	ctx := context.Background()
	// "ghost" is listed for digest but does not exist yet.
	if rec := membersGet(h, "/v1/groups/ghost/members", digestToken, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("missing group = %d", rec.Code)
	}
	if err := srv.store.CreateGroupOfKind(ctx, "ghost", "", store.GroupKindDomain); err != nil {
		t.Fatal(err)
	}
	rec := membersGet(h, "/v1/groups/ghost/members", digestToken, nil)
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusConflict || body["error"] != "domain group has no member list" {
		t.Fatalf("domain group = %d %s", rec.Code, rec.Body)
	}
	// An app not listed for the group learns nothing of its kind.
	if rec := membersGet(h, "/v1/groups/ghost/members", otherToken, nil); rec.Code != http.StatusForbidden {
		t.Errorf("other reading the domain group = %d", rec.Code)
	}
	// The read is refused, so it is not recorded.
	if reads, err := srv.store.SummariseMemberReads(ctx, srv.now().Add(-time.Hour)); err != nil || len(reads) != 0 {
		t.Errorf("reads = %+v, %v", reads, err)
	}
}

// fileReadersServer is a test server whose reader "digest" comes from the
// readers file (coordinators and leads), with two administrators.
func fileReadersServer(t *testing.T) (*Server, *captureSender) {
	t.Helper()
	srv, sender := testServerWith(t, func(c *config.Config) {
		c.AdminEmails = []string{"admin@example.com", "boss@example.com"}
		c.MemberReaders = []config.MemberReader{
			{App: "digest", Token: digestToken, Groups: []string{"coordinators", "leads"}, FromFile: true},
			{App: "other", Token: otherToken, Groups: []string{"reviewers"}},
		}
	})
	ctx := context.Background()
	for _, g := range []string{"coordinators", "leads", "reviewers"} {
		if err := srv.store.CreateGroup(ctx, g, ""); err != nil {
			t.Fatal(err)
		}
	}
	srv.store.AddGroupMember(ctx, "coordinators", "amy@example.com")
	srv.store.AddGroupMember(ctx, "reviewers", "cal@example.com")
	return srv, sender
}

// A pair from the readers file is served only once an administrator has
// approved it on the Access page, and not once the approval is withdrawn.
// Before approval the app gets the answer a group it may not read gets, and
// nothing is recorded. An app in MEMBER_READERS needs no approval.
func TestMembersFileReadsNeedApproval(t *testing.T) {
	srv, sender := fileReadersServer(t)
	ctx := context.Background()
	h := srv.MembersHandler()

	waiting := membersGet(h, "/v1/groups/coordinators/members", digestToken, nil)
	notListed := membersGet(h, "/v1/groups/reviewers/members", digestToken, nil)
	if waiting.Code != http.StatusForbidden || waiting.Body.String() != notListed.Body.String() || strings.Contains(waiting.Body.String(), "amy@") {
		t.Fatalf("before approval = %d %s", waiting.Code, waiting.Body)
	}
	if rec := membersGet(h, "/v1/groups/reviewers/members", otherToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("the env reader = %d", rec.Code)
	}

	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	page := c.get("/admin/app-feeds", nil).Body.String()
	ask := `href="/admin/app-feeds?confirm=approve&amp;app=digest&amp;group=coordinators"`
	if !strings.Contains(page, "Waiting to start") || !strings.Contains(page, ask) || strings.Contains(page, `action="/admin/member-readers/approve"`) {
		t.Fatal("the App feeds page does not offer the approval")
	}
	// Asking draws the confirmation in place, and changes nothing.
	page = c.get("/admin/app-feeds?confirm=approve&app=digest&group=coordinators", nil).Body.String()
	if !strings.Contains(page, "Starting the feed sends Digest the email address of everyone in coordinators, and keeps Digest up to date as the group changes.") || strings.Count(page, `action="/admin/member-readers/approve"`) != 1 {
		t.Fatal("the App feeds page does not confirm the approval")
	}
	if list, _ := srv.store.ListMemberReaderApprovals(ctx); len(list) != 0 {
		t.Fatalf("asking approved: %+v", list)
	}
	csrf := adminCSRF(t, c, "/admin/app-feeds?confirm=approve&app=digest&group=coordinators")
	// Only a pair the file lists can be approved.
	c.postForm("/admin/member-readers/approve", url.Values{"csrf": {csrf}, "app": {"digest"}, "group": {"reviewers"}})
	c.postForm("/admin/member-readers/approve", url.Values{"csrf": {csrf}, "app": {"other"}, "group": {"reviewers"}})
	if list, _ := srv.store.ListMemberReaderApprovals(ctx); len(list) != 0 {
		t.Fatalf("approved a pair the file does not list: %+v", list)
	}

	rec := c.postForm("/admin/member-readers/approve", url.Values{"csrf": {csrf}, "app": {"digest"}, "group": {"coordinators"}})
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/admin/app-feeds" {
		t.Fatalf("approve = %d %s", rec.Code, rec.Header().Get("Location"))
	}
	page = c.get("/admin/app-feeds", nil).Body.String()
	if !strings.Contains(page, `<div class="rstrip ok" role="status"><i aria-hidden="true"></i><span>The feed of coordinators to Digest has started.</span></div>`) ||
		strings.Contains(page, `class="notice ok"`) || !strings.Contains(page, "Started by admin@example.com on ") ||
		!strings.Contains(page, `href="/admin/app-feeds?confirm=withdraw&amp;app=digest&amp;group=coordinators"`) {
		t.Error("the App feeds page does not show the approval")
	}
	if page := c.get("/admin/app-feeds?confirm=withdraw&app=digest&group=coordinators", nil).Body.String(); !strings.Contains(page, "Once the feed stops, Digest no longer receives the people in coordinators.") ||
		!strings.Contains(page, `action="/admin/member-readers/withdraw"`) {
		t.Error("the App feeds page does not confirm the withdrawal")
	}
	if rec := membersGet(h, "/v1/groups/coordinators/members", digestToken, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "amy@example.com") {
		t.Fatalf("after approval = %d %s", rec.Code, rec.Body)
	}
	// The approval covers the pair, not the app's other groups.
	if rec := membersGet(h, "/v1/groups/leads/members", digestToken, nil); rec.Code != http.StatusForbidden {
		t.Errorf("an unapproved group = %d", rec.Code)
	}

	rec = c.postForm("/admin/member-readers/withdraw", url.Values{"csrf": {csrf}, "app": {"digest"}, "group": {"coordinators"}})
	if rec.Code != http.StatusFound {
		t.Fatalf("withdraw = %d", rec.Code)
	}
	if page := c.get("/admin/app-feeds", nil).Body.String(); !strings.Contains(page, "The feed of coordinators to Digest has stopped.") {
		t.Error("no notice after withdrawing")
	}
	if rec := membersGet(h, "/v1/groups/coordinators/members", digestToken, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("after withdrawal = %d", rec.Code)
	}

	// Only the one approved read was recorded.
	reads, _ := srv.store.SummariseMemberReads(ctx, srv.now().Add(-time.Hour))
	got := 0
	for _, r := range reads {
		if r.App == "digest" {
			got += r.Reads
		}
	}
	if got != 1 {
		t.Errorf("digest reads recorded = %d, want 1", got)
	}

	// Both changes are in the admin log, with the actor, and emailed to the
	// other administrator only.
	events, _ := srv.store.ListAdminEvents(ctx, 10, 0)
	seen := map[string]bool{}
	for _, e := range events {
		if e.Target == "digest" && e.Detail == "coordinators" && e.Actor == "admin@example.com" {
			seen[e.Action] = true
		}
	}
	if !seen[store.AdminActionMemberReaderApprove] || !seen[store.AdminActionMemberReaderWithdraw] {
		t.Errorf("admin events = %+v", events)
	}
	mails := mailWithSubject(sender, "Access to the members of coordinators has changed.")
	if len(mails) != 2 {
		t.Fatalf("emails = %d", len(mails))
	}
	for _, m := range mails {
		if m.To != "boss@example.com" || !strings.Contains(m.Text, "admin@example.com made these changes") {
			t.Errorf("email to %s: %q", m.To, m.Text)
		}
	}
	if !strings.Contains(mails[0].Text+mails[1].Text, "- Approved digest to read the members of coordinators") ||
		!strings.Contains(mails[0].Text+mails[1].Text, "- Withdrew the approval for digest to read the members of coordinators") {
		t.Errorf("email lines: %q / %q", mails[0].Text, mails[1].Text)
	}
}

// Someone who is not an administrator cannot approve.
func TestMemberReaderApprovalNeedsAnAdministrator(t *testing.T) {
	srv, sender := fileReadersServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "amy@example.com", nil)
	rec := c.postForm("/admin/member-readers/approve", url.Values{"app": {"digest"}, "group": {"coordinators"}})
	if rec.Code == http.StatusFound && strings.HasPrefix(rec.Header().Get("Location"), "/admin/app-feeds") {
		t.Fatalf("a member of staff reached the handler: %d", rec.Code)
	}
	if ok, _ := srv.store.MemberReaderApproved(context.Background(), "digest", "coordinators"); ok {
		t.Fatal("a member of staff approved a reader")
	}
}

// At start-up the gateway clears an approval only when the readers file was
// read whole and no longer lists the pair, so a row removed and added again
// needs approval again. The clearing is in the admin log and emailed once.
// An unreadable file, an app whose token is unusable for now, and an app
// moved into MEMBER_READERS keep their approvals.
func TestStaleReaderApprovalsClearedAtStart(t *testing.T) {
	srv, sender := fileReadersServer(t)
	ctx := context.Background()
	for _, p := range [][2]string{{"digest", "coordinators"}, {"digest", "leads"}, {"weak", "leads"}, {"moved", "leads"}} {
		srv.store.ApproveMemberReader(ctx, p[0], p[1], "admin@example.com", srv.now())
	}
	approved := func() []string {
		var out []string
		list, _ := srv.store.ListMemberReaderApprovals(ctx)
		for _, a := range list {
			out = append(out, a.App+":"+a.Group)
		}
		return out
	}
	restart := func(read bool, pairs map[string][]string) *Server {
		cfg := *srv.cfg
		cfg.MemberReaders = []config.MemberReader{{App: "digest", Token: digestToken, Groups: pairs["digest"], FromFile: true}}
		cfg.MemberReadersFileRead, cfg.MemberReadersFilePairs = read, pairs
		cfg.MemberReadersEnvApps = []string{"moved"}
		next, err := New(&cfg, srv.store, srv.sender)
		if err != nil {
			t.Fatal(err)
		}
		return next
	}
	all := "digest:coordinators digest:leads moved:leads weak:leads"

	// The file could not be read: nothing is cleared.
	restart(false, map[string][]string{})
	if got := strings.Join(approved(), " "); got != all {
		t.Fatalf("after an unreadable file = %s", got)
	}

	// The coordinators row leaves the file. "weak" is still listed (its
	// token is unusable, so it is not a reader) and keeps its approval.
	// "moved" is now in MEMBER_READERS, which decides its groups, so its
	// file approval is cleared and cannot be served if it moves back.
	next := restart(true, map[string][]string{"digest": {"leads"}, "weak": {"leads"}, "moved": {"leads"}})
	if got := strings.Join(approved(), " "); got != "digest:leads weak:leads" {
		t.Fatalf("approvals = %s", got)
	}
	if rec := membersGet(next.MembersHandler(), "/v1/groups/coordinators/members", digestToken, nil); rec.Code != http.StatusForbidden {
		t.Errorf("a row no longer in the file = %d", rec.Code)
	}
	events, _ := srv.store.ListAdminEvents(ctx, 10, 0)
	cleared := map[string]bool{}
	for _, e := range events {
		if e.Action == store.AdminActionMemberReaderClear && e.Actor == "gateway" {
			cleared[e.Target+":"+e.Detail] = true
		}
	}
	if len(events) != 2 || !cleared["digest:coordinators"] || !cleared["moved:leads"] {
		t.Errorf("admin events = %+v", events)
	}
	mails := mailWithSubject(sender, "Approvals to read group members have been cleared.")
	if len(mails) != 2 { // one each to the two administrators
		t.Fatalf("emails = %d", len(mails))
	}
	if !strings.Contains(mails[0].Text, "The gateway made these changes") ||
		!strings.Contains(mails[0].Text, "- Cleared the approval for digest to read the members of coordinators, which the readers file no longer lists") ||
		!strings.Contains(mails[0].Text, "- Cleared the approval for moved to read the members of leads, because MEMBER_READERS now decides its groups") {
		t.Errorf("email = %q", mails[0].Text)
	}

	// The row comes back: it needs approval again.
	again := restart(true, map[string][]string{"digest": {"leads", "coordinators"}, "weak": {"leads"}})
	if rec := membersGet(again.MembersHandler(), "/v1/groups/coordinators/members", digestToken, nil); rec.Code != http.StatusForbidden {
		t.Errorf("a re-added row = %d", rec.Code)
	}
}

// An approval is for a group that exists: a pair whose group does not exist
// shows that, offers no Approve button, and the handler refuses it. Deleting
// a group deletes its approvals, and each is audited.
func TestReaderApprovalNeedsAnExistingGroup(t *testing.T) {
	srv, _ := testServerWith(t, func(c *config.Config) {
		c.MemberReaders = []config.MemberReader{{App: "digest", Token: digestToken, Groups: []string{"later", "leads"}, FromFile: true}}
	})
	ctx := context.Background()
	srv.store.CreateGroup(ctx, "leads", "")
	c := newClient(t, srv.Handler())
	loginAs(t, c, srv.sender.(*captureSender), "admin@example.com", nil)
	page := c.get("/admin/app-feeds", nil).Body.String()
	if !strings.Contains(page, "Group does not exist yet") || strings.Contains(page, "group=later") {
		t.Fatal("the App feeds page offers to approve a group that does not exist")
	}
	if page := c.get("/admin/app-feeds?confirm=approve&app=digest&group=later", nil).Body.String(); strings.Contains(page, "Starting the feed sends digest") || strings.Contains(page, `action="/admin/member-readers/approve"`) {
		t.Fatal("the App feeds page confirms a group that does not exist")
	}
	csrf := adminCSRF(t, c, "/admin/app-feeds?confirm=approve&app=digest&group=leads")
	c.postForm("/admin/member-readers/approve", url.Values{"csrf": {csrf}, "app": {"digest"}, "group": {"later"}})
	if ok, _ := srv.store.MemberReaderApproved(ctx, "digest", "later"); ok {
		t.Fatal("approved a group that does not exist")
	}

	c.postForm("/admin/member-readers/approve", url.Values{"csrf": {csrf}, "app": {"digest"}, "group": {"leads"}})
	if ok, _ := srv.store.MemberReaderApproved(ctx, "digest", "leads"); !ok {
		t.Fatal("the approval of an existing group was refused")
	}
	c.postForm("/admin/groups/leads/delete", url.Values{"csrf": {csrf}})
	if ok, _ := srv.store.MemberReaderApproved(ctx, "digest", "leads"); ok {
		t.Fatal("the approval outlived its group")
	}
	srv.store.CreateGroup(ctx, "leads", "")
	if rec := membersGet(srv.MembersHandler(), "/v1/groups/leads/members", digestToken, nil); rec.Code != http.StatusForbidden {
		t.Errorf("a recreated group = %d", rec.Code)
	}
	events, _ := srv.store.ListAdminEvents(ctx, 10, 0)
	withdrawn := false
	for _, e := range events {
		withdrawn = withdrawn || (e.Action == store.AdminActionMemberReaderWithdraw && e.Target == "digest" && e.Detail == "leads" && e.Actor == "admin@example.com")
	}
	if !withdrawn {
		t.Errorf("the deletion of the approval is not audited: %+v", events)
	}
}
