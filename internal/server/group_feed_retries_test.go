// Tests of feed retries and of failures reported at once.

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

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
