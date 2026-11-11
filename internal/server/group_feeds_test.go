package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync"
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
	page := c.get("/admin/groups/rch-consultants", nil).Body.String()
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
	if _, err := srv.syncFeed(ctx, "rch-consultants", "admin@example.com", shown); !errors.Is(err, errChangeReplaced) {
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
	st, err := srv.syncFeed(context.Background(), "rch-consultants", "group feed", "")
	if !errors.Is(err, errStateUnreadable) || st.Status != store.GroupSyncFailed || hits.Load() != 0 {
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

// alertCapture records each alert's title, body and Authorization header.
type alertCapture struct {
	mu   sync.Mutex
	msgs []capturedAlert
}

type capturedAlert struct{ title, body, auth string }

func (a *alertCapture) server(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		a.mu.Lock()
		a.msgs = append(a.msgs, capturedAlert{r.Header.Get("Title"), string(b), r.Header.Get("Authorization")})
		a.mu.Unlock()
	}))
	t.Cleanup(ts.Close)
	return ts
}

func (a *alertCapture) all() []capturedAlert {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]capturedAlert(nil), a.msgs...)
}

func TestFeedAppliedChangesAreAnnounced(t *testing.T) {
	var body atomic.Value
	var hits atomic.Int32
	body.Store(emailsJSON(20, "m"))
	ts := feedEndpoint(t, &body, &hits)
	var cap alertCapture
	alert := cap.server(t)
	srv, _ := testServerWith(t, func(c *config.Config) {
		c.GroupFeeds = []config.GroupFeed{{Group: "rch-consultants", URL: ts.URL, Token: testFeedToken}}
		c.FeedAlertURL = alert.URL
		c.FeedAlertToken = "tk_alerttoken"
	})
	ctx := context.Background()
	fill(t, srv) // held first fill (one alert), then accepted (none)
	waitFor(t, func() bool { return len(cap.all()) == 1 })

	// A small change applies on its own and is announced, with the addresses.
	body.Store(strings.Replace(emailsJSON(20, "m"), "m00@example.com", "new@example.com", 1))
	if st, _ := srv.syncFeed(ctx, "rch-consultants", "group feed", ""); st.Status != store.GroupSyncOK {
		t.Fatalf("small change = %+v, want applied", st)
	}
	waitFor(t, func() bool { return len(cap.all()) == 2 })
	got := cap.all()[1]
	if got.title != "Gateway group feed changed members" {
		t.Errorf("title = %q", got.title)
	}
	want := "The gateway has updated rch-consultants from its feed. These members have been added: new@example.com. These members have been removed: m00@example.com."
	if got.body != want {
		t.Errorf("body = %q, want %q", got.body, want)
	}
	for i, m := range cap.all() {
		if m.auth != "Bearer tk_alerttoken" {
			t.Errorf("alert %d Authorization = %q", i, m.auth)
		}
	}

	// No change, no alert.
	srv.syncFeed(ctx, "rch-consultants", "group feed", "")
	time.Sleep(100 * time.Millisecond)
	if n := len(cap.all()); n != 2 {
		t.Errorf("alerts after an unchanged sync = %d, want 2", n)
	}
}

func TestAlertListNamesTenThenCounts(t *testing.T) {
	var e []string
	for i := 0; i < 13; i++ {
		e = append(e, fmt.Sprintf("p%02d@example.com", i))
	}
	got := alertList(e)
	if !strings.HasSuffix(got, "p09@example.com and 3 others") || strings.Contains(got, "p10@") {
		t.Errorf("alertList = %q", got)
	}
	if alertList(e[:2]) != "p00@example.com, p01@example.com" {
		t.Errorf("short alertList = %q", alertList(e[:2]))
	}
}

// A feed whose first fetch failed has a sync state but no group row, since
// the sync creates the row only once the feed has answered. The Groups page
// must still list it, with the reason and the Sync now button, rather than
// leaving the overview's "needs attention" notice pointing at nothing.
func TestGroupsPageListsFeedGroupBeforeFirstSuccessfulSync(t *testing.T) {
	var body atomic.Value
	var hits atomic.Int32
	body.Store("500")
	ts := feedEndpoint(t, &body, &hits)
	srv, sender := feedServer(t, ts.URL, "")
	if st, _ := srv.syncFeed(context.Background(), "rch-consultants", "group feed", ""); st.Status != store.GroupSyncFailed {
		t.Fatalf("first sync status %q, want failed", st.Status)
	}
	if exists, _ := srv.groupExistsCtx(context.Background(), "rch-consultants"); exists {
		t.Fatal("a failed first fetch should not create the group row")
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	page := c.get("/admin/groups/rch-consultants", nil).Body.String()
	for _, want := range []string{"not created yet", "The feed could not be used", `action="/admin/groups/rch-consultants/sync"`} {
		if !strings.Contains(page, want) {
			t.Errorf("groups page lacks %q", want)
		}
	}
	if strings.Contains(page, `name="name" value="rch-consultants"`) {
		t.Error("a feed-filled group is offered for manual creation")
	}
	// Once the feed answers, Sync now from that row creates and fills the group.
	body.Store(`["a@example.com","b@example.com"]`)
	tok := extractCSRF(t, page)
	c.postForm("/admin/groups/rch-consultants/sync", url.Values{"csrf": {tok}})
	if got := members(t, srv); !reflect.DeepEqual(got, []string{"a@example.com", "b@example.com"}) {
		t.Errorf("members after Sync now: %v", got)
	}
	page = c.get("/admin/groups", nil).Body.String()
	if strings.Contains(page, "not created yet") {
		t.Error("the group still reads as not created after a successful sync")
	}
}

// --- retries of a fetch that may only be waiting for the feed's host ---

// retryServer is a filled feed group with an alert sink and a short retry
// delay; the caller sets body to make the feed fail.
func retryServer(t *testing.T, delay time.Duration) (*Server, *atomic.Value, *atomic.Int32, *alertCapture) {
	t.Helper()
	body := &atomic.Value{}
	hits := &atomic.Int32{}
	body.Store(emailsJSON(20, "m"))
	ts := feedEndpoint(t, body, hits)
	cap := &alertCapture{}
	alert := cap.server(t)
	srv, _ := feedServer(t, ts.URL, alert.URL)
	srv.feeds.retryDelay = delay
	fill(t, srv)
	waitFor(t, func() bool { return len(cap.all()) == 1 }) // the held first fill
	cap.mu.Lock()
	cap.msgs = nil // count only what the test itself causes
	cap.mu.Unlock()
	return srv, body, hits, cap
}

func syncState(t *testing.T, srv *Server) store.GroupSyncState {
	t.Helper()
	states, err := srv.store.ListGroupSyncStates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return states["rch-consultants"]
}

func attention(alerts []capturedAlert) int {
	n := 0
	for _, a := range alerts {
		if a.title == "Gateway group feed needs attention" {
			n++
		}
	}
	return n
}

func retrying(srv *Server) bool {
	_, ok := srv.feeds.retryFor("rch-consultants")
	return ok
}

// A feed that stays down is tried 1+feedRetries times, then recorded as
// failed with one alert. Until then nothing is recorded and nothing is sent.
func TestFeedRetriesBeforeRecordingAFailure(t *testing.T) {
	srv, body, hits, cap := retryServer(t, 200*time.Millisecond)
	before, hit0 := syncState(t, srv), hits.Load()
	body.Store("500")
	srv.scheduledSync(context.Background(), "rch-consultants")
	if !retrying(srv) {
		t.Fatal("a 500 from the feed did not start a retry")
	}
	if got := syncState(t, srv); !reflect.DeepEqual(got, before) {
		t.Fatalf("state written before the retries ran: %+v", got)
	}
	if n := attention(cap.all()); n != 0 {
		t.Fatalf("%d alerts sent before the retries ran", n)
	}
	waitFor(t, func() bool { return !retrying(srv) })
	if n := hits.Load() - hit0; n != 1+feedRetries {
		t.Errorf("feed fetched %d times, want %d", n, 1+feedRetries)
	}
	if st := syncState(t, srv); st.Status != store.GroupSyncFailed || !strings.Contains(st.Detail, "answered 500") {
		t.Fatalf("after the retries: %+v", st)
	}
	waitFor(t, func() bool { return attention(cap.all()) == 1 })
	time.Sleep(50 * time.Millisecond)
	if n := attention(cap.all()); n != 1 {
		t.Errorf("%d alerts for one failure, want 1", n)
	}
	if got := members(t, srv); len(got) != 20 {
		t.Errorf("members changed by a failed fetch: %d", len(got))
	}
}

// A feed that comes back during the retries is synced with no alert.
func TestFeedRecoveringDuringRetriesSendsNoAlert(t *testing.T) {
	srv, body, hits, cap := retryServer(t, 30*time.Millisecond)
	hit0 := hits.Load()
	body.Store("500")
	srv.scheduledSync(context.Background(), "rch-consultants")
	body.Store(emailsJSON(20, "m"))
	waitFor(t, func() bool { return !retrying(srv) })
	if st := syncState(t, srv); st.Status != store.GroupSyncOK {
		t.Fatalf("after recovery: %+v", st)
	}
	if n := hits.Load() - hit0; n != 2 {
		t.Errorf("feed fetched %d times, want 2", n)
	}
	time.Sleep(50 * time.Millisecond)
	if n := attention(cap.all()); n != 0 {
		t.Errorf("%d alerts for a feed that recovered", n)
	}
}

// A feed that answers with unusable content is reported at once: waiting
// would not change it.
func TestFeedContentProblemsAreReportedAtOnce(t *testing.T) {
	for name, tc := range map[string]struct{ body, status string }{
		"empty list":    {"[]", store.GroupSyncEmpty},
		"not JSON":      {"<html>maintenance</html>", store.GroupSyncFailed},
		"no usable one": {`["stranger@other.org"]`, store.GroupSyncEmpty},
		"held change":   {emailsJSON(20, "z"), store.GroupSyncHeld},
	} {
		t.Run(name, func(t *testing.T) {
			srv, body, hits, _ := retryServer(t, time.Hour)
			hit0 := hits.Load()
			body.Store(tc.body)
			srv.scheduledSync(context.Background(), "rch-consultants")
			if retrying(srv) {
				t.Fatal("a content problem started a retry")
			}
			if st := syncState(t, srv); st.Status != tc.status {
				t.Fatalf("status %q, want %q", st.Status, tc.status)
			}
			if n := hits.Load() - hit0; n != 1 {
				t.Errorf("feed fetched %d times, want 1", n)
			}
		})
	}
}

// A held change and its Accept stay exactly as they were while a fetch is
// being retried, since nothing is written.
func TestFeedRetriesKeepAHeldChange(t *testing.T) {
	srv, body, _, _ := retryServer(t, time.Hour)
	body.Store(emailsJSON(20, "z"))
	srv.syncFeed(context.Background(), "rch-consultants", "group feed", "")
	held := syncState(t, srv)
	if held.Status != store.GroupSyncHeld {
		t.Fatalf("setup: %+v", held)
	}
	body.Store("500")
	srv.scheduledSync(context.Background(), "rch-consultants")
	if got := syncState(t, srv); !reflect.DeepEqual(got, held) {
		t.Fatalf("the held change was rewritten during a retry: %+v", got)
	}
	// The administrator can still accept it, once the feed answers.
	body.Store(emailsJSON(20, "z"))
	if st, err := srv.syncFeed(context.Background(), "rch-consultants", "admin@example.com", held.PendingHash); err != nil || st.Status != store.GroupSyncOK {
		t.Fatalf("accept during a retry: %+v %v", st, err)
	}
	if retrying(srv) {
		t.Error("an accepted change did not end the waiting retry")
	}
}

// Sync now records its single attempt at once, and ends a waiting retry.
func TestSyncNowDoesNotWaitAndEndsRetries(t *testing.T) {
	srv, body, hits, cap := retryServer(t, 150*time.Millisecond)
	body.Store("500")
	srv.scheduledSync(context.Background(), "rch-consultants")
	if st, _ := srv.syncFeed(context.Background(), "rch-consultants", "admin@example.com", ""); st.Status != store.GroupSyncFailed {
		t.Fatalf("Sync now did not record its attempt: %+v", st)
	}
	if retrying(srv) {
		t.Fatal("Sync now left the retry waiting")
	}
	waitFor(t, func() bool { return attention(cap.all()) == 1 })
	hit := hits.Load()
	time.Sleep(400 * time.Millisecond)
	if hits.Load() != hit {
		t.Errorf("retries continued after Sync now recorded a result")
	}
	if n := attention(cap.all()); n != 1 {
		t.Errorf("%d alerts, want 1", n)
	}
}

// The hourly round skips a group whose retries are still running, so a
// short FEED_INTERVAL cannot stack retry sequences against the feed's host.
func TestRoundSkipsAGroupStillRetrying(t *testing.T) {
	srv, body, hits, _ := retryServer(t, time.Hour)
	body.Store("500")
	srv.scheduledSync(context.Background(), "rch-consultants")
	hit := hits.Load()
	srv.scheduledSync(context.Background(), "rch-consultants")
	if hits.Load() != hit {
		t.Error("a second round fetched a feed that was still being retried")
	}
}

// A feed already recorded as failed is not alerted again when it fails
// again after its retries, as before retries existed.
func TestRetriedFailureOfAFailedFeedIsNotAlertedAgain(t *testing.T) {
	srv, body, _, cap := retryServer(t, 10*time.Millisecond)
	body.Store("500")
	srv.syncFeed(context.Background(), "rch-consultants", "group feed", "")
	waitFor(t, func() bool { return attention(cap.all()) == 1 })
	srv.scheduledSync(context.Background(), "rch-consultants")
	waitFor(t, func() bool { return !retrying(srv) })
	time.Sleep(50 * time.Millisecond)
	if n := attention(cap.all()); n != 1 {
		t.Errorf("%d alerts, want 1", n)
	}
}

// Stopping the gateway stops its retries.
func TestRetriesStopWithTheGateway(t *testing.T) {
	srv, body, hits, _ := retryServer(t, 50*time.Millisecond)
	before := syncState(t, srv)
	body.Store("500")
	ctx, cancel := context.WithCancel(context.Background())
	srv.scheduledSync(ctx, "rch-consultants")
	cancel()
	waitFor(t, func() bool { return !retrying(srv) })
	hit := hits.Load()
	time.Sleep(200 * time.Millisecond)
	if hits.Load() != hit {
		t.Error("retries ran after the gateway stopped")
	}
	// A stopping gateway records no failure it did not observe.
	if got := syncState(t, srv); !reflect.DeepEqual(got, before) {
		t.Errorf("state written after the gateway stopped: %+v", got)
	}
}

// The Groups page says a retry is waiting, and when it runs.
func TestGroupsPageShowsAWaitingRetry(t *testing.T) {
	var body atomic.Value
	var hits atomic.Int32
	body.Store("500")
	ts := feedEndpoint(t, &body, &hits)
	srv, sender := feedServer(t, ts.URL, "")
	srv.feeds.retryDelay = time.Hour
	srv.scheduledSync(context.Background(), "rch-consultants")
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	page := c.get("/admin/groups/rch-consultants", nil).Body.String()
	for _, want := range []string{"did not succeed. The feed could not be used: the feed answered 500.", "The gateway will try again at", "3 more times, before it records the failure."} {
		if !strings.Contains(page, want) {
			t.Errorf("groups page lacks %q", want)
		}
	}
}

// Found in review: Sync now ended a waiting retry without stopping its
// goroutine, so the next round started a second sequence while the first was
// asleep, and both kept fetching. Each sequence now owns its entry by number.
func TestSyncNowThenRoundRunsOneSequence(t *testing.T) {
	srv, body, hits, _ := retryServer(t, 100*time.Millisecond)
	body.Store("500")
	h0 := hits.Load()
	srv.scheduledSync(context.Background(), "rch-consultants")                     // first sequence
	srv.syncFeed(context.Background(), "rch-consultants", "admin@example.com", "") // Sync now ends it
	srv.scheduledSync(context.Background(), "rch-consultants")                     // a new one
	waitFor(t, func() bool { return !retrying(srv) })
	time.Sleep(300 * time.Millisecond)
	// One attempt, Sync now, then one full sequence.
	if n := hits.Load() - h0; n != int32(2+1+feedRetries) {
		t.Errorf("%d fetches, want %d: more than one sequence ran", n, 2+1+feedRetries)
	}
}

// Only an answer that says "try later" is retried. A refused token or a moved
// feed is reported at once, since waiting will not change it.
func TestFeedRefusalsAreReportedAtOnce(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusFound} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if code == http.StatusFound {
					w.Header().Set("Location", "https://elsewhere.example/")
				}
				w.WriteHeader(code)
			}))
			t.Cleanup(ts.Close)
			srv, _ := feedServer(t, ts.URL, "")
			srv.feeds.retryDelay = time.Hour
			srv.scheduledSync(context.Background(), "rch-consultants")
			if retrying(srv) {
				t.Fatalf("a %d was retried", code)
			}
			if st := syncState(t, srv); st.Status != store.GroupSyncFailed {
				t.Fatalf("a %d was not recorded: %+v", code, st)
			}
		})
	}
	for _, code := range []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusTooManyRequests, http.StatusRequestTimeout} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }))
			t.Cleanup(ts.Close)
			srv, _ := feedServer(t, ts.URL, "")
			srv.feeds.retryDelay = time.Hour
			srv.scheduledSync(context.Background(), "rch-consultants")
			if !retrying(srv) {
				t.Fatalf("a %d was not retried", code)
			}
		})
	}
}

// --- held changes applied after a wait (GROUP_FEED_AUTO_APPLY_AFTER) ---

// autoServer is a filled group of 20 with a 12-hour wait and a clock the
// test moves.
func autoServer(t *testing.T) (*Server, *atomic.Value, *alertCapture, *time.Time) {
	t.Helper()
	srv, body, _, cap := retryServer(t, time.Hour)
	srv.cfg.FeedAutoApplyAfter = 12 * time.Hour
	clock := time.Now()
	srv.now = func() time.Time { return clock }
	return srv, body, cap, &clock
}

func applied(alerts []capturedAlert) int {
	n := 0
	for _, a := range alerts {
		if a.title == "Gateway group feed changed members" {
			n++
		}
	}
	return n
}

// A changeover: half the group replaced. It is held and alerted at once,
// stays held through the wait, then applies on its own, is announced, and
// becomes the accepted list.
func TestHeldChangeAppliesAfterTheWait(t *testing.T) {
	srv, body, cap, clock := autoServer(t)
	start := *clock
	changeover := strings.Replace(emailsJSON(10, "m"), "]", ","+strings.Trim(emailsJSON(10, "n"), "[]")+"]", 1)
	body.Store(changeover)
	ctx := context.Background()
	st, _ := srv.syncFeed(ctx, "rch-consultants", "group feed", "")
	if st.Status != store.GroupSyncHeld || !strings.Contains(st.Detail, "It will be applied automatically at the first sync after") {
		t.Fatalf("changeover = %+v, want held with the time it applies", st)
	}
	waitFor(t, func() bool { return attention(cap.all()) == 1 })
	*clock = start.Add(11 * time.Hour)
	if st, _ := srv.syncFeed(ctx, "rch-consultants", "group feed", ""); st.Status != store.GroupSyncHeld {
		t.Fatalf("applied before the wait was over: %+v", st)
	}
	if got := members(t, srv); len(got) != 20 || got[19] != "m19@example.com" {
		t.Fatalf("members changed during the wait: %v", got)
	}
	*clock = start.Add(12 * time.Hour)
	st, _ = srv.syncFeed(ctx, "rch-consultants", "group feed", "")
	if st.Status != store.GroupSyncOK || !strings.Contains(st.Detail, "applied automatically after the change had been held for 12 hours") {
		t.Fatalf("after the wait = %+v", st)
	}
	if got := members(t, srv); !reflect.DeepEqual(got, mustList(t, changeover)) {
		t.Fatalf("members after the wait: %v", got)
	}
	waitFor(t, func() bool { return applied(cap.all()) == 1 })
	if n := attention(cap.all()); n != 1 {
		t.Errorf("%d needs-attention alerts, want 1 (at the hold)", n)
	}
	// The changeover is now the accepted list: a small change next applies
	// at once, with no drift hold.
	*clock = start.Add(13 * time.Hour)
	body.Store(strings.Replace(changeover, "n09@example.com", "late@example.com", 1))
	if st, _ := srv.syncFeed(ctx, "rch-consultants", "group feed", ""); st.Status != store.GroupSyncOK {
		t.Fatalf("a small change after the changeover was held: %+v", st)
	}
	events, _ := srv.store.ListAdminEvents(ctx, 50, 0)
	found := false
	for _, e := range events {
		if e.Action == store.AdminActionGroupSync && strings.Contains(e.Detail, "applied automatically after being held for 12 hours") {
			found = true
		}
	}
	if !found {
		t.Error("the automatic apply is not in the admin audit")
	}
}

func mustList(t *testing.T, raw string) []string {
	t.Helper()
	var l []string
	if err := json.Unmarshal([]byte(raw), &l); err != nil {
		t.Fatal(err)
	}
	sort.Strings(l)
	return l
}

// A feed that changes again during the wait starts the wait again, so the
// change that applies has always been on show for the whole wait.
func TestAChangedFeedRestartsTheWait(t *testing.T) {
	srv, body, _, clock := autoServer(t)
	start := *clock
	ctx := context.Background()
	body.Store(emailsJSON(20, "x"))
	srv.syncFeed(ctx, "rch-consultants", "group feed", "")
	*clock = start.Add(6 * time.Hour)
	body.Store(emailsJSON(20, "y"))
	srv.syncFeed(ctx, "rch-consultants", "group feed", "")
	*clock = start.Add(13 * time.Hour)
	if st, _ := srv.syncFeed(ctx, "rch-consultants", "group feed", ""); st.Status != store.GroupSyncHeld {
		t.Fatalf("the second change applied before its own wait: %+v", st)
	}
	*clock = start.Add(18 * time.Hour)
	if st, _ := srv.syncFeed(ctx, "rch-consultants", "group feed", ""); st.Status != store.GroupSyncOK {
		t.Fatalf("the second change did not apply after its wait: %+v", st)
	}
	if got := members(t, srv); got[0] != "y00@example.com" {
		t.Fatalf("members: %v", got)
	}
}

// Keep current members stops the change shown from applying on its own. It
// can still be accepted, and a stale page cannot keep a newer change.
func TestKeepCurrentMembers(t *testing.T) {
	srv, body, _, clock := autoServer(t)
	start := *clock
	ctx := context.Background()
	body.Store(emailsJSON(20, "x"))
	srv.syncFeed(ctx, "rch-consultants", "group feed", "")
	shown := heldHash(t, srv)
	if err := srv.keepHeldChange(ctx, "rch-consultants", "not-the-hash"); !errors.Is(err, errChangeReplaced) {
		t.Fatalf("keep with a stale hash: %v", err)
	}
	if err := srv.keepHeldChange(ctx, "rch-consultants", shown); err != nil {
		t.Fatal(err)
	}
	*clock = start.Add(30 * time.Hour)
	st, _ := srv.syncFeed(ctx, "rch-consultants", "group feed", "")
	if st.Status != store.GroupSyncHeld || !strings.Contains(st.Detail, "kept the current members") || strings.Contains(st.Detail, "applied automatically at the first sync after") {
		t.Fatalf("a kept change = %+v", st)
	}
	if got := members(t, srv); got[0] != "m00@example.com" {
		t.Fatalf("a kept change was applied: %v", got)
	}
	if st, err := srv.syncFeed(ctx, "rch-consultants", "admin@example.com", shown); err != nil || st.Status != store.GroupSyncOK {
		t.Fatalf("accepting a kept change: %+v %v", st, err)
	}
}

// With no wait set, a held change waits for an administrator however long.
func TestHeldChangeWaitsForAnAdministratorByDefault(t *testing.T) {
	srv, body, _, clock := autoServer(t)
	srv.cfg.FeedAutoApplyAfter = 0
	start := *clock
	body.Store(emailsJSON(20, "x"))
	srv.syncFeed(context.Background(), "rch-consultants", "group feed", "")
	*clock = start.Add(30 * 24 * time.Hour)
	st, _ := srv.syncFeed(context.Background(), "rch-consultants", "group feed", "")
	if st.Status != store.GroupSyncHeld || strings.Contains(st.Detail, "automatically") {
		t.Fatalf("with no wait set = %+v", st)
	}
}

// A held change recorded before this build has no hold time; its wait starts
// at the first sync that sees it, never in the past.
func TestAHoldFromBeforeTheWaitStartsItsWaitNow(t *testing.T) {
	srv, body, _, clock := autoServer(t)
	start := *clock
	ctx := context.Background()
	body.Store(emailsJSON(20, "x"))
	srv.syncFeed(ctx, "rch-consultants", "group feed", "")
	st := syncState(t, srv)
	st.HeldSince = time.Time{}
	if err := srv.store.SetGroupSyncState(ctx, st); err != nil {
		t.Fatal(err)
	}
	*clock = start.Add(100 * time.Hour)
	if st, _ := srv.syncFeed(ctx, "rch-consultants", "group feed", ""); st.Status != store.GroupSyncHeld {
		t.Fatalf("an old hold applied at once: %+v", st)
	}
	*clock = start.Add(112 * time.Hour)
	if st, _ := srv.syncFeed(ctx, "rch-consultants", "group feed", ""); st.Status != store.GroupSyncOK {
		t.Fatalf("an old hold did not apply after its wait: %+v", st)
	}
}

// The Groups page shows when the change applies and offers to keep the
// current members; the button records an audited keep.
func TestGroupsPageOffersKeepCurrentMembers(t *testing.T) {
	srv, body, _, _ := autoServer(t)
	body.Store(emailsJSON(20, "x"))
	srv.syncFeed(context.Background(), "rch-consultants", "group feed", "")
	sender := newCaptureSender()
	srv.sender = sender
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	page := c.get("/admin/groups/rch-consultants", nil).Body.String()
	for _, want := range []string{"It will be applied automatically at", `action="/admin/groups/rch-consultants/keep"`, "Keep current members"} {
		if !strings.Contains(page, want) {
			t.Errorf("groups page lacks %q", want)
		}
	}
	rec := c.postForm("/admin/groups/rch-consultants/keep", url.Values{"csrf": {extractCSRF(t, page)}, "hash": {heldHash(t, srv)}})
	if rec.Code != http.StatusFound {
		t.Fatalf("keep: %d", rec.Code)
	}
	page = c.get("/admin/groups/rch-consultants", nil).Body.String()
	if strings.Contains(page, `action="/admin/groups/rch-consultants/keep"`) || !strings.Contains(page, "kept the current members") {
		t.Error("the page still offers to keep a kept change")
	}
	events, _ := srv.store.ListAdminEvents(context.Background(), 10, 0)
	if len(events) == 0 || events[0].Action != store.AdminActionGroupKeep || events[0].Actor != "admin@example.com" {
		t.Errorf("keep not audited: %+v", events)
	}
}

// Found in review: switching the wait on applied a change that had sat held
// for days (the only way to refuse one before Keep existed) at the next
// round, with no alert giving a time. Its wait now starts when the setting
// is switched on, with an alert that gives the time.
func TestSwitchingTheWaitOnStartsOldHoldsAfresh(t *testing.T) {
	srv, body, cap, clock := autoServer(t)
	srv.cfg.FeedAutoApplyAfter = 0
	start := *clock
	ctx := context.Background()
	body.Store(emailsJSON(20, "x"))
	srv.syncFeed(ctx, "rch-consultants", "group feed", "")
	if !syncState(t, srv).HeldSince.IsZero() {
		t.Fatal("a hold time was stored with no wait set")
	}
	waitFor(t, func() bool { return attention(cap.all()) == 1 })
	srv.cfg.FeedAutoApplyAfter = 12 * time.Hour
	*clock = start.Add(3 * 24 * time.Hour)
	if st, _ := srv.syncFeed(ctx, "rch-consultants", "group feed", ""); st.Status != store.GroupSyncHeld {
		t.Fatalf("an old hold applied when the wait was switched on: %+v", st)
	}
	waitFor(t, func() bool { return attention(cap.all()) == 2 })
	if a := cap.all()[1]; !strings.Contains(a.body, "applied automatically at the first sync after") {
		t.Errorf("the alert for the new wait gives no time: %s", a.body)
	}
	*clock = start.Add(3*24*time.Hour + 12*time.Hour)
	if st, _ := srv.syncFeed(ctx, "rch-consultants", "group feed", ""); st.Status != store.GroupSyncOK {
		t.Fatalf("not applied after its own wait: %+v", st)
	}
}

// Found in review: the roster could undo Keep by returning something else
// for one round and then the same change again. A kept change stays kept.
func TestTheRosterCannotUndoKeep(t *testing.T) {
	srv, body, _, clock := autoServer(t)
	start := *clock
	ctx := context.Background()
	body.Store(emailsJSON(20, "x"))
	srv.syncFeed(ctx, "rch-consultants", "group feed", "")
	if err := srv.keepHeldChange(ctx, "rch-consultants", heldHash(t, srv)); err != nil {
		t.Fatal(err)
	}
	for i, b := range []string{`[]`, emailsJSON(20, "m"), "500", emailsJSON(20, "x")} {
		*clock = start.Add(time.Duration(i+1) * time.Hour)
		body.Store(b)
		srv.syncFeed(ctx, "rch-consultants", "group feed", "")
	}
	*clock = start.Add(30 * time.Hour)
	if st, _ := srv.syncFeed(ctx, "rch-consultants", "group feed", ""); st.Status != store.GroupSyncHeld || !strings.Contains(st.Detail, "kept the current members") {
		t.Fatalf("a kept change came back and applied: %+v", st)
	}
	if got := members(t, srv); got[0] != "m00@example.com" {
		t.Fatalf("members: %v", got)
	}
}

// Found in review: after a stale Accept the new hold had no time, no Keep
// button and no alert with a time, yet applied after the wait.
func TestAHoldAfterAStaleAcceptAnnouncesItsTime(t *testing.T) {
	srv, body, cap, _ := autoServer(t)
	ctx := context.Background()
	body.Store(emailsJSON(20, "x"))
	srv.syncFeed(ctx, "rch-consultants", "group feed", "")
	shown := heldHash(t, srv)
	waitFor(t, func() bool { return attention(cap.all()) == 1 })
	body.Store(emailsJSON(20, "y"))
	st, _ := srv.syncFeed(ctx, "rch-consultants", "admin@example.com", shown)
	if st.Status != store.GroupSyncHeld || syncState(t, srv).HeldSince.IsZero() || !strings.Contains(st.Detail, "applied automatically at the first sync after") {
		t.Fatalf("the new hold has no wait on show: %+v", st)
	}
	states, _ := srv.store.ListGroupSyncStates(ctx)
	if fv := srv.feedViewFor("rch-consultants", states); fv.AutoAt == "" {
		t.Error("no Keep button for the new hold")
	}
	waitFor(t, func() bool { return attention(cap.all()) == 2 })
	if !strings.Contains(cap.all()[1].body, "applied automatically at the first sync after") {
		t.Error("the new hold's alert gives no time")
	}
}

// Found in review: there was no ceiling on what the wait applies. A change
// that would more than halve or more than double the group is never applied
// on its own; a changeover that swaps people at the same size is.
func TestAChangeTooLargeWaitsForAnAdministrator(t *testing.T) {
	for name, feed := range map[string]string{
		"one address left":    `["only@example.com"]`,
		"less than half left": emailsJSON(9, "m"),
		"more than doubled":   emailsJSON(51, "z"),
	} {
		t.Run(name, func(t *testing.T) {
			srv, body, _, clock := autoServer(t)
			start := *clock
			ctx := context.Background()
			body.Store(feed)
			st, _ := srv.syncFeed(ctx, "rch-consultants", "group feed", "")
			if st.Status != store.GroupSyncHeld || !strings.Contains(st.Detail, "applied only if an administrator accepts it") {
				t.Fatalf("held = %+v", st)
			}
			states, _ := srv.store.ListGroupSyncStates(ctx)
			if fv := srv.feedViewFor("rch-consultants", states); fv.AutoAt != "" {
				t.Error("a Keep button for a change that never applies on its own")
			}
			*clock = start.Add(30 * 24 * time.Hour)
			srv.syncFeed(ctx, "rch-consultants", "group feed", "")
			if got := members(t, srv); len(got) != 20 || got[0] != "m00@example.com" {
				t.Fatalf("a change too large applied on its own: %d members", len(got))
			}
		})
	}
}

// Found in review: pressing Keep on a page left open past the automatic
// apply said nothing had been applied. It now says the change was applied.
func TestKeepAfterTheApplySaysSo(t *testing.T) {
	srv, body, _, clock := autoServer(t)
	start := *clock
	ctx := context.Background()
	body.Store(emailsJSON(20, "x"))
	srv.syncFeed(ctx, "rch-consultants", "group feed", "")
	shown := heldHash(t, srv)
	*clock = start.Add(12 * time.Hour)
	srv.syncFeed(ctx, "rch-consultants", "group feed", "")
	if err := srv.keepHeldChange(ctx, "rch-consultants", shown); !errors.Is(err, errAlreadyApplied) {
		t.Fatalf("keep after the apply: %v", err)
	}
}

// An automatic apply is the gateway's, in the audit, even when an
// administrator's Sync now happens to be the round that applies it; and its
// alert says the change had been held.
func TestAnAutomaticApplyIsAttributedToTheFeed(t *testing.T) {
	srv, body, cap, clock := autoServer(t)
	start := *clock
	ctx := context.Background()
	body.Store(emailsJSON(20, "x"))
	srv.syncFeed(ctx, "rch-consultants", "group feed", "")
	*clock = start.Add(12 * time.Hour)
	srv.syncFeed(ctx, "rch-consultants", "admin@example.com", "") // Sync now
	events, _ := srv.store.ListAdminEvents(ctx, 100, 0)
	for _, e := range events {
		if e.Action == store.AdminActionGroupAddMember && strings.HasPrefix(e.Detail, "x") && e.Actor != "group feed" {
			t.Fatalf("automatic apply attributed to %q", e.Actor)
		}
	}
	waitFor(t, func() bool { return applied(cap.all()) == 1 })
	for _, a := range cap.all() {
		if a.title == "Gateway group feed changed members" && !strings.Contains(a.body, "had been held for 12 hours") {
			t.Errorf("the applied alert does not say the change had been held: %s", a.body)
		}
	}
}

// A rotating group (registrars, fellows) is replaced wholesale at a
// changeover, sometimes through a list that briefly holds a few people or
// both batches. With no ceiling, each such change applies after the wait.
func TestARotatingGroupChangesOverAfterTheWait(t *testing.T) {
	for name, feed := range map[string]string{
		"old batch gone first": `["stays@example.com"]`,
		"both batches listed":  strings.Replace(emailsJSON(20, "m"), "]", ","+strings.Trim(emailsJSON(40, "n"), "[]")+"]", 1),
		"clean swap":           emailsJSON(20, "n"),
	} {
		t.Run(name, func(t *testing.T) {
			srv, body, _, clock := autoServer(t)
			f := srv.feeds.feeds["rch-consultants"]
			f.Rotating = true
			srv.feeds.feeds["rch-consultants"] = f
			start := *clock
			ctx := context.Background()
			body.Store(feed)
			if st, _ := srv.syncFeed(ctx, "rch-consultants", "group feed", ""); st.Status != store.GroupSyncHeld || !strings.Contains(st.Detail, "applied automatically at the first sync after") {
				t.Fatalf("held = %+v", st)
			}
			*clock = start.Add(12 * time.Hour)
			if st, _ := srv.syncFeed(ctx, "rch-consultants", "group feed", ""); st.Status != store.GroupSyncOK {
				t.Fatalf("not applied after the wait: %+v", st)
			}
			if got := members(t, srv); !reflect.DeepEqual(got, mustList(t, feed)) {
				t.Fatalf("members: %v", got)
			}
		})
	}
	// An empty list is still refused.
	srv, body, _, _ := autoServer(t)
	f := srv.feeds.feeds["rch-consultants"]
	f.Rotating = true
	srv.feeds.feeds["rch-consultants"] = f
	body.Store(`[]`)
	if st, _ := srv.syncFeed(context.Background(), "rch-consultants", "group feed", ""); st.Status != store.GroupSyncEmpty {
		t.Fatalf("an empty list for a rotating group = %+v", st)
	}
}

// A feed may say which listed addresses it made from another (roster-insights
// lists tom.darling for a roster's tom.darling2). The gateway keeps those
// labels for listed members only, never adds a member from them, and shows
// them on the group page.
func TestFeedAddedFromLabels(t *testing.T) {
	var body atomic.Value
	var hits atomic.Int32
	body.Store(`{"emails":["tom.darling2@example.com","Tom.Darling@example.com"],
		"added_from":{"tom.darling@example.com":"Tom.Darling2@example.com",
		              "ghost@example.com":"tom.darling2@example.com",
		              "tom.darling2@example.com":"tom.darling2@example.com"}}`)
	ts := feedEndpoint(t, &body, &hits)
	srv, sender := feedServer(t, ts.URL, "")
	ctx := context.Background()
	if st, err := srv.syncFeed(ctx, "rch-consultants", "group feed", ""); err != nil || st.Status != store.GroupSyncOK {
		t.Fatalf("sync = %v, %v", st.Status, err)
	}
	if got := members(t, srv); !reflect.DeepEqual(got, []string{"tom.darling2@example.com", "tom.darling@example.com"}) {
		t.Fatalf("members = %v", got)
	}
	want := map[string]string{"tom.darling@example.com": "tom.darling2@example.com"}
	if got := syncState(t, srv).AddedFrom; !reflect.DeepEqual(got, want) {
		t.Errorf("stored labels = %v, want %v", got, want)
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	page := c.get("/admin/groups/rch-consultants", nil).Body.String()
	if !strings.Contains(page, "added from tom.darling2@example.com") || strings.Contains(page, "ghost@example.com") {
		t.Error("group page does not label the added address, or shows a label for a non-member")
	}
	// A failed fetch keeps the labels; a plain list clears them.
	body.Store("500")
	srv.syncFeed(ctx, "rch-consultants", "group feed", "")
	if got := syncState(t, srv).AddedFrom; !reflect.DeepEqual(got, want) {
		t.Errorf("labels after a failed fetch = %v", got)
	}
	body.Store(`["tom.darling2@example.com","tom.darling@example.com"]`)
	srv.syncFeed(ctx, "rch-consultants", "group feed", "")
	if got := syncState(t, srv).AddedFrom; len(got) != 0 {
		t.Errorf("labels after a plain list = %v", got)
	}
}
