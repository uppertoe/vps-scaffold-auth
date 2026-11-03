package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
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
	page := c.get("/admin/access", nil).Body.String()
	if !strings.Contains(page, "Apps that read group members") || !strings.Contains(page, `<td class="num" data-label="Reads">3</td>`) || !strings.Contains(page, `<code class="mono">172.18.0.5</code>`) {
		t.Error("the access log does not show the reads")
	}
}
