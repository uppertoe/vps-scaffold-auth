package server

import (
	"context"
	"errors"
	"fmt"
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

func emailsJSON(n int, prefix string) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf("%q", fmt.Sprintf("%s%02d@example.com", prefix, i))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func TestFeedSyncCreatesAndUpdatesGroup(t *testing.T) {
	var body atomic.Value
	var hits atomic.Int32
	body.Store(`["A@example.com","b@example.com","b@example.com","not-an-email","stranger@other.org"]`)
	ts := feedEndpoint(t, &body, &hits)
	srv, _ := feedServer(t, ts.URL, "")
	ctx := context.Background()

	st, err := srv.syncFeed(ctx, "rch-consultants", "group feed", "")
	if err != nil || st.Status != store.GroupSyncOK {
		t.Fatalf("first sync = %+v, %v", st, err)
	}
	if got := members(t, srv); !reflect.DeepEqual(got, []string{"a@example.com", "b@example.com"}) {
		t.Errorf("members = %v (an address off the allow-list must be dropped)", got)
	}
	if !strings.Contains(st.Detail, "2 entries were skipped") {
		t.Errorf("detail = %q", st.Detail)
	}
	body.Store(`{"emails":["a@example.com","c@example.com"]}`)
	if st, _ := srv.syncFeed(ctx, "rch-consultants", "group feed", ""); st.Status != store.GroupSyncOK {
		t.Fatalf("second sync = %+v", st)
	}
	if got := members(t, srv); !reflect.DeepEqual(got, []string{"a@example.com", "c@example.com"}) {
		t.Errorf("members = %v", got)
	}
	events, _ := srv.store.ListAdminEvents(ctx, 10, 0)
	var removedB bool
	for _, e := range events {
		if e.Action == store.AdminActionGroupRemoveMember && e.Detail == "b@example.com" && e.Actor == "group feed" {
			removedB = true
		}
	}
	if !removedB {
		t.Errorf("removal of b not audited per address: %+v", events)
	}
}

func TestFeedLargeChangesAreHeldUntilAccepted(t *testing.T) {
	var body atomic.Value
	var hits atomic.Int32
	body.Store(emailsJSON(5, "m"))
	ts := feedEndpoint(t, &body, &hits)
	var alerts atomic.Int32
	alert := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { alerts.Add(1) }))
	defer alert.Close()
	srv, _ := feedServer(t, ts.URL, alert.URL)
	ctx := context.Background()
	if st, _ := srv.syncFeed(ctx, "rch-consultants", "group feed", ""); st.Status != store.GroupSyncHeld {
		t.Fatalf("first fill of 5 = %+v, want held", st)
	}
	srv.syncFeed(ctx, "rch-consultants", "admin@example.com", heldHash(t, srv))
	waitFor(t, func() bool { return alerts.Load() == 1 }) // the first fill's alert
	alerts.Store(0)
	// Shrink: 4 of 5 removed.
	body.Store(`["m00@example.com"]`)
	st, _ := srv.syncFeed(ctx, "rch-consultants", "group feed", "")
	if st.Status != store.GroupSyncHeld || len(st.PendingRemoveList) != 4 {
		t.Fatalf("shrink = %+v, want held with 4 removals listed", st)
	}
	srv.syncFeed(ctx, "rch-consultants", "group feed", "") // same change: no second alert
	waitFor(t, func() bool { return alerts.Load() >= 1 })
	time.Sleep(100 * time.Millisecond)
	if alerts.Load() != 1 {
		t.Errorf("alerts = %d, want 1", alerts.Load())
	}
	if len(members(t, srv)) != 5 {
		t.Error("members changed while held")
	}
	// The feed changes before the accept: nothing is applied, the new change is held.
	body.Store(`["m00@example.com","m01@example.com"]`)
	st, _ = srv.syncFeed(ctx, "rch-consultants", "admin@example.com", heldHash(t, srv))
	if st.Status != store.GroupSyncHeld || len(members(t, srv)) != 5 {
		t.Fatalf("accept after the feed changed = %+v, members %d", st, len(members(t, srv)))
	}
	st, _ = srv.syncFeed(ctx, "rch-consultants", "admin@example.com", heldHash(t, srv))
	if st.Status != store.GroupSyncOK || len(members(t, srv)) != 2 {
		t.Errorf("accept = %+v, members %v", st, members(t, srv))
	}
	if _, err := srv.syncFeed(ctx, "rch-consultants", "admin@example.com", "anything"); !errors.Is(err, errNothingHeld) {
		t.Errorf("accept with nothing held = %v", err)
	}
}

func TestFeedGrowthIsHeld(t *testing.T) {
	var body atomic.Value
	var hits atomic.Int32
	body.Store(emailsJSON(4, "m"))
	ts := feedEndpoint(t, &body, &hits)
	srv, _ := feedServer(t, ts.URL, "")
	ctx := context.Background()
	fill(t, srv)
	body.Store(emailsJSON(20, "m"))
	st, _ := srv.syncFeed(ctx, "rch-consultants", "group feed", "")
	if st.Status != store.GroupSyncHeld || len(st.PendingAddList) != 16 || len(members(t, srv)) != 4 {
		t.Errorf("growth = %+v, members %d", st, len(members(t, srv)))
	}
}

func TestFeedGradualShrinkIsHeld(t *testing.T) {
	var body atomic.Value
	var hits atomic.Int32
	body.Store(emailsJSON(8, "m"))
	ts := feedEndpoint(t, &body, &hits)
	srv, _ := feedServer(t, ts.URL, "")
	ctx := context.Background()
	// The first fill of 8 is held, then accepted: baseline 8.
	if st, _ := srv.syncFeed(ctx, "rch-consultants", "group feed", ""); st.Status != store.GroupSyncHeld {
		t.Fatalf("first fill of 8 = %+v, want held", st)
	}
	srv.syncFeed(ctx, "rch-consultants", "admin@example.com", heldHash(t, srv))
	body.Store(emailsJSON(6, "m")) // two removals: small enough to apply
	if st, _ := srv.syncFeed(ctx, "rch-consultants", "group feed", ""); st.Status != store.GroupSyncOK {
		t.Fatalf("down to 6 = %+v", st)
	}
	body.Store(emailsJSON(4, "m")) // two more: small on its own, but four from the accepted 8
	if st, _ := srv.syncFeed(ctx, "rch-consultants", "group feed", ""); st.Status != store.GroupSyncHeld {
		t.Errorf("down to 4 of an accepted 8 = %+v, want held", st)
	}
}

func TestFeedFailuresKeepMembers(t *testing.T) {
	var body atomic.Value
	var hits atomic.Int32
	body.Store(`["a@example.com","b@example.com"]`)
	ts := feedEndpoint(t, &body, &hits)
	srv, _ := feedServer(t, ts.URL, "")
	ctx := context.Background()
	srv.syncFeed(ctx, "rch-consultants", "group feed", "")
	for _, b := range []string{"500", "[]", "not json", `{"other":1}`, `["x@other.org"]`, `["a\u202e@example.com"]`} {
		body.Store(b)
		st, _ := srv.syncFeed(ctx, "rch-consultants", "group feed", "")
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
	st, _ := srv.syncFeed(context.Background(), "rch-consultants", "group feed", "")
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
	srv.syncFeed(context.Background(), "rch-consultants", "group feed", "")
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
	// A synced group cannot admit a hand-managed group, but can be included.
	if err := srv.store.CreateGroup(context.Background(), "hand", ""); err != nil {
		t.Fatal(err)
	}
	c.postForm("/admin/groups/rch-consultants/includes", url.Values{"csrf": {tok}, "included": {"hand"}})
	if inc, _ := srv.store.ListGroupIncludes(context.Background()); len(inc["rch-consultants"]) != 0 {
		t.Errorf("synced group includes another group: %v", inc)
	}
	c.postForm("/admin/groups/hand/includes", url.Values{"csrf": {tok}, "included": {"rch-consultants"}})
	if inc, _ := srv.store.ListGroupIncludes(context.Background()); len(inc["hand"]) != 1 {
		t.Errorf("including a synced group into another refused: %v", inc)
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

// heldHash is the hash of the change currently held for rch-consultants, as
// the Groups page would send it back with Accept.
func heldHash(t *testing.T, srv *Server) string {
	t.Helper()
	states, err := srv.store.ListGroupSyncStates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return states["rch-consultants"].PendingHash
}

func TestFeedRollingReplacementIsHeld(t *testing.T) {
	var body atomic.Value
	var hits atomic.Int32
	body.Store(emailsJSON(5, "a"))
	ts := feedEndpoint(t, &body, &hits)
	srv, _ := feedServer(t, ts.URL, "")
	ctx := context.Background()
	fill(t, srv)
	// Swap one member per sync: each step is small, but drift accumulates.
	held := false
	for i := 1; i <= 5 && !held; i++ {
		var xs []string
		for j := 0; j < 5; j++ {
			if j < i {
				xs = append(xs, fmt.Sprintf("%q", fmt.Sprintf("b%02d@example.com", j)))
			} else {
				xs = append(xs, fmt.Sprintf("%q", fmt.Sprintf("a%02d@example.com", j)))
			}
		}
		body.Store("[" + strings.Join(xs, ",") + "]")
		st, _ := srv.syncFeed(ctx, "rch-consultants", "group feed", "")
		held = st.Status == store.GroupSyncHeld
	}
	if !held {
		t.Error("replacing the whole group one member at a time was never held")
	}
}

func TestFeedAcceptNeedsTheHashOnScreen(t *testing.T) {
	var body atomic.Value
	var hits atomic.Int32
	body.Store(emailsJSON(5, "m"))
	ts := feedEndpoint(t, &body, &hits)
	srv, _ := feedServer(t, ts.URL, "")
	ctx := context.Background()
	fill(t, srv)
	body.Store(`["m00@example.com"]`)
	srv.syncFeed(ctx, "rch-consultants", "group feed", "")
	shown := heldHash(t, srv) // the admin loads the page here
	body.Store(`["m00@example.com","m01@example.com"]`)
	srv.syncFeed(ctx, "rch-consultants", "group feed", "") // the hourly sync replaces the held change
	if _, err := srv.syncFeed(ctx, "rch-consultants", "admin@example.com", shown); !errors.Is(err, errNothingHeld) {
		t.Errorf("accept of a replaced change = %v, want refused", err)
	}
	if len(members(t, srv)) != 5 {
		t.Error("members changed on a stale accept")
	}
}

// When the last sync state cannot be read, nothing is applied or recorded.
type syncStateReadFails struct{ store.Store }

func (syncStateReadFails) ListGroupSyncStates(context.Context) (map[string]store.GroupSyncState, error) {
	return nil, errors.New("disk read error")
}

func TestFeedStopsWhenStateUnreadable(t *testing.T) {
	var body atomic.Value
	var hits atomic.Int32
	body.Store(emailsJSON(3, "m"))
	ts := feedEndpoint(t, &body, &hits)
	srv, _ := feedServer(t, ts.URL, "")
	srv.store = syncStateReadFails{srv.store}
	st, _ := srv.syncFeed(context.Background(), "rch-consultants", "group feed", "")
	if st.Status != store.GroupSyncFailed || hits.Load() != 0 {
		t.Errorf("state unreadable: status %q, feed fetched %d times", st.Status, hits.Load())
	}
}

// fill runs a sync and, if the first fill is held, accepts it, so a test can
// start from an accepted group.
func fill(t *testing.T, srv *Server) {
	t.Helper()
	ctx := context.Background()
	st, err := srv.syncFeed(ctx, "rch-consultants", "group feed", "")
	if err != nil {
		t.Fatal(err)
	}
	if st.Status == store.GroupSyncHeld {
		if st, err = srv.syncFeed(ctx, "rch-consultants", "admin@example.com", heldHash(t, srv)); err != nil || st.Status != store.GroupSyncOK {
			t.Fatalf("accepting the first fill = %+v, %v", st, err)
		}
	}
}
