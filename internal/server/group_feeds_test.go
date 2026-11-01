package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

const testFeedToken = "feed-token-0123456789abcdef"

// feedEndpoint serves whatever body is in *body, checking the token.
func feedEndpoint(t *testing.T, body *atomic.Value, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+testFeedToken {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		b := body.Load().(string)
		if b == "500" {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(b))
	}))
	t.Cleanup(ts.Close)
	return ts
}

func feedServer(t *testing.T, feedURL, alertURL string) (*Server, *captureSender) {
	t.Helper()
	return testServerWith(t, func(c *config.Config) {
		c.GroupFeeds = []config.GroupFeed{{Group: "rch-consultants", URL: feedURL, Token: testFeedToken}}
		c.FeedAlertURL = alertURL
	})
}

func members(t *testing.T, srv *Server) []string {
	t.Helper()
	m, err := srv.store.ListGroupMembers(context.Background(), "rch-consultants")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestFeedSyncCreatesAndUpdatesGroup(t *testing.T) {
	var body atomic.Value
	var hits atomic.Int32
	body.Store(`["A@example.com","b@example.com","b@example.com","not-an-email"]`)
	ts := feedEndpoint(t, &body, &hits)
	srv, _ := feedServer(t, ts.URL, "")
	ctx := context.Background()

	st, err := srv.syncFeed(ctx, "rch-consultants", false)
	if err != nil || st.Status != store.GroupSyncOK {
		t.Fatalf("first sync = %+v, %v", st, err)
	}
	if got := members(t, srv); !reflect.DeepEqual(got, []string{"a@example.com", "b@example.com"}) {
		t.Errorf("members = %v", got)
	}
	if !strings.Contains(st.Detail, "1 entries were not email addresses") {
		t.Errorf("detail = %q", st.Detail)
	}
	// The object form also works; one removal of two is not a large shrink
	// (the group is under the floor), so it applies.
	body.Store(`{"emails":["a@example.com","c@example.com"]}`)
	if st, _ := srv.syncFeed(ctx, "rch-consultants", false); st.Status != store.GroupSyncOK {
		t.Fatalf("second sync = %+v", st)
	}
	if got := members(t, srv); !reflect.DeepEqual(got, []string{"a@example.com", "c@example.com"}) {
		t.Errorf("members = %v", got)
	}
	events, _ := srv.store.ListAdminEvents(ctx, 5, 0)
	if len(events) == 0 || events[0].Action != store.AdminActionGroupSync || !strings.Contains(events[0].Detail, "removed 1: b@example.com") {
		t.Errorf("sync not audited: %+v", events)
	}
}

func TestFeedLargeShrinkIsHeldUntilAccepted(t *testing.T) {
	var body atomic.Value
	var hits atomic.Int32
	body.Store(`["a@example.com","b@example.com","c@example.com","d@example.com","e@example.com"]`)
	ts := feedEndpoint(t, &body, &hits)
	var alerts atomic.Int32
	alert := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { alerts.Add(1) }))
	defer alert.Close()
	srv, _ := feedServer(t, ts.URL, alert.URL)
	ctx := context.Background()
	if _, err := srv.syncFeed(ctx, "rch-consultants", false); err != nil {
		t.Fatal(err)
	}
	body.Store(`["a@example.com"]`)
	st, _ := srv.syncFeed(ctx, "rch-consultants", false)
	if st.Status != store.GroupSyncHeld || st.PendingRemove != 4 {
		t.Fatalf("shrink = %+v, want held with 4 pending removals", st)
	}
	if len(members(t, srv)) != 5 {
		t.Error("members changed while held")
	}
	srv.syncFeed(ctx, "rch-consultants", false) // still held: no second alert
	st, _ = srv.syncFeed(ctx, "rch-consultants", true)
	if st.Status != store.GroupSyncOK || len(members(t, srv)) != 1 {
		t.Errorf("accept = %+v, members %v", st, members(t, srv))
	}
	waitFor(t, func() bool { return alerts.Load() == 1 })
}

func TestFeedFailuresKeepMembers(t *testing.T) {
	var body atomic.Value
	var hits atomic.Int32
	body.Store(`["a@example.com","b@example.com"]`)
	ts := feedEndpoint(t, &body, &hits)
	srv, _ := feedServer(t, ts.URL, "")
	ctx := context.Background()
	srv.syncFeed(ctx, "rch-consultants", false)
	for _, b := range []string{"500", "[]", "not json", `{"other":1}`} {
		body.Store(b)
		st, _ := srv.syncFeed(ctx, "rch-consultants", false)
		if st.Status == store.GroupSyncOK {
			t.Errorf("body %q synced", b)
		}
		if len(members(t, srv)) != 2 {
			t.Errorf("body %q changed members", b)
		}
	}
}

func TestFeedDoesNotFollowRedirects(t *testing.T) {
	var leaked atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Add(1)
		}
		_, _ = w.Write([]byte(`["x@example.com"]`))
	}))
	defer other.Close()
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer feed.Close()
	srv, _ := feedServer(t, feed.URL, "")
	st, _ := srv.syncFeed(context.Background(), "rch-consultants", false)
	if st.Status != store.GroupSyncFailed || leaked.Load() != 0 {
		t.Errorf("redirect: status %q, token sent elsewhere %d times", st.Status, leaked.Load())
	}
}

func TestSyncedGroupIsReadOnlyOnAdminPages(t *testing.T) {
	var body atomic.Value
	var hits atomic.Int32
	body.Store(`["a@example.com"]`)
	ts := feedEndpoint(t, &body, &hits)
	srv, sender := feedServer(t, ts.URL, "")
	srv.syncFeed(context.Background(), "rch-consultants", false)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	page := c.get("/admin/groups?open=rch-consultants", nil).Body.String()
	if !strings.Contains(page, "Members come from the feed at") || strings.Contains(page, `action="/admin/groups/rch-consultants/members"`) {
		t.Error("synced group page shows edit controls or lacks the feed note")
	}
	tok := extractCSRF(t, page)
	for _, p := range []string{"/admin/groups/rch-consultants/members", "/admin/groups/rch-consultants/members/confirm", "/admin/groups/rch-consultants/members/delete", "/admin/groups/rch-consultants/delete"} {
		c.postForm(p, url.Values{"csrf": {tok}, "emails": {"z@example.com"}, "add": {"z@example.com"}, "email": {"a@example.com"}})
	}
	if got := members(t, srv); !reflect.DeepEqual(got, []string{"a@example.com"}) {
		t.Errorf("synced group edited by hand: %v", got)
	}
	// Sync now works and needs CSRF; a group without a feed is not found.
	body.Store(`["a@example.com","b@example.com"]`)
	if rec := c.postForm("/admin/groups/rch-consultants/sync", url.Values{}); rec.Code != http.StatusForbidden {
		t.Errorf("sync without CSRF = %d", rec.Code)
	}
	if rec := c.postForm("/admin/groups/rch-consultants/sync", url.Values{"csrf": {tok}}); rec.Code != http.StatusFound || len(members(t, srv)) != 2 {
		t.Errorf("sync now = %d, members %v", rec.Code, members(t, srv))
	}
	if err := srv.store.CreateGroup(context.Background(), "plain", ""); err != nil {
		t.Fatal(err)
	}
	if rec := c.postForm("/admin/groups/plain/sync", url.Values{"csrf": {tok}}); rec.Code != http.StatusNotFound {
		t.Errorf("sync of a group without a feed = %d", rec.Code)
	}
}

// waitFor polls cond for up to two seconds (the feed alert is sent from a
// goroutine).
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("condition not met in time")
}
