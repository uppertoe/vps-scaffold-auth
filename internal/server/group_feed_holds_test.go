// Tests of held feed changes: the wait, keeping current members, and attribution.

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

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
