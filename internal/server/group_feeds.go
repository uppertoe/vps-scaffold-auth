package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// Group feeds fill a gateway group from an endpoint (config.GroupFeed). Each
// sync replaces the group's members with the feed's list, except that a
// failed fetch, an empty list, or a change that would remove more than half
// of the members keeps the current members and raises an alert; a held change
// is applied only when an administrator accepts it, or, when
// GROUP_FEED_AUTO_APPLY_AFTER is set, once the same change has been held that
// long without an administrator keeping the current members. A registrar or
// fellow changeover then applies itself, after the alert and the wait. A scheduled fetch that
// cannot reach the feed, or gets an answer other than 200, is retried before
// it counts as failed (feedRetries). Members of a feed-filled
// group cannot be edited on the admin pages, since the next sync would undo
// the edit; such a group can still be included in other groups.

const (
	feedFetchTimeout = 20 * time.Second
	feedMaxBody      = 1 << 20 // 1 MiB: tens of thousands of addresses
	feedMaxAddresses = 20000
	feedFirstDelay   = time.Minute
	// A scheduled fetch that cannot reach the feed, or gets an answer other
	// than 200, is tried again feedRetries times, feedRetryDelay apart, before
	// the failure is recorded and alerted. The feed's host may simply be
	// starting: a deploy recreates every container, and the roster app can
	// take two minutes to answer. A feed that answers with unusable content
	// is not retried, since waiting would not change it.
	feedRetries    = 3
	feedRetryDelay = 5 * time.Minute
)

type feedSyncer struct {
	feeds  map[string]config.GroupFeed
	client *http.Client
	mu     sync.Mutex // one sync at a time; syncs are rare and small

	// Retries waiting to run, by group. They live only in memory: nothing is
	// written to the store until the last attempt, so a held change, the
	// accepted set and the alert rules see exactly what they saw before the
	// first failed fetch. retryMu is separate from mu so the Groups page never
	// waits on a fetch in progress.
	retryMu    sync.Mutex
	retrying   map[string]feedRetry
	retryDelay time.Duration
	retrySeq   uint64 // the last sequence number handed out
}

// feedRetry is a retry waiting to run, shown on the Groups page.
type feedRetry struct {
	At      time.Time // when the last attempt failed
	Next    time.Time // when the next attempt runs
	Reason  string    // what went wrong, in the gateway's words
	Attempt int       // attempts made so far
	Seq     uint64    // which retry sequence this is
}

// startRetry records a new sequence for group and returns its number.
func (f *feedSyncer) startRetry(group string, r feedRetry) uint64 {
	f.retryMu.Lock()
	defer f.retryMu.Unlock()
	f.retrySeq++
	r.Seq = f.retrySeq
	f.retrying[group] = r
	return r.Seq
}

// ownsRetry reports whether sequence seq is still the one waiting for group.
// Clearing the entry (a recorded result) or a newer sequence ends it.
func (f *feedSyncer) ownsRetry(group string, seq uint64) bool {
	f.retryMu.Lock()
	defer f.retryMu.Unlock()
	r, ok := f.retrying[group]
	return ok && r.Seq == seq
}

// advanceRetry updates sequence seq's entry, only if it still owns it, so a
// result recorded while an attempt was running is never undone.
func (f *feedSyncer) advanceRetry(group string, seq uint64, r feedRetry) bool {
	f.retryMu.Lock()
	defer f.retryMu.Unlock()
	if cur, ok := f.retrying[group]; !ok || cur.Seq != seq {
		return false
	}
	r.Seq = seq
	f.retrying[group] = r
	return true
}

// endRetry drops sequence seq's entry, only if it still owns it.
func (f *feedSyncer) endRetry(group string, seq uint64) {
	f.retryMu.Lock()
	defer f.retryMu.Unlock()
	if cur, ok := f.retrying[group]; ok && cur.Seq == seq {
		delete(f.retrying, group)
	}
}

func (f *feedSyncer) retryFor(group string) (feedRetry, bool) {
	f.retryMu.Lock()
	defer f.retryMu.Unlock()
	r, ok := f.retrying[group]
	return r, ok
}

// clearRetry drops a waiting retry; any recorded sync does this, so a
// result recorded meanwhile (Sync now) ends the sequence.
func (f *feedSyncer) clearRetry(group string) {
	f.retryMu.Lock()
	delete(f.retrying, group)
	f.retryMu.Unlock()
}

func newFeedSyncer(feeds []config.GroupFeed) *feedSyncer {
	m := make(map[string]config.GroupFeed, len(feeds))
	for _, f := range feeds {
		m[f.Group] = f
	}
	return &feedSyncer{
		feeds:      m,
		retrying:   map[string]feedRetry{},
		retryDelay: feedRetryDelay,
		client: &http.Client{
			Timeout: feedFetchTimeout,
			// Never follow a redirect: the token is for the configured URL only.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// feedFor returns the feed that fills group, if any.
func (s *Server) feedFor(group string) (config.GroupFeed, bool) {
	f, ok := s.feeds.feeds[group]
	return f, ok
}

// StartFeeds syncs every feed shortly after start and then every
// FeedInterval, until ctx ends.
func (s *Server) StartFeeds(ctx context.Context) {
	if len(s.feeds.feeds) == 0 {
		return
	}
	go func() {
		t := time.NewTimer(feedFirstDelay)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			groups := make([]string, 0, len(s.feeds.feeds))
			for g := range s.feeds.feeds {
				groups = append(groups, g)
			}
			sort.Strings(groups)
			for _, g := range groups {
				s.scheduledSync(ctx, g)
			}
			t.Reset(s.cfg.FeedInterval)
		}
	}()
}

// scheduledSync is one group's turn in the hourly round. A fetch that may
// only be waiting for the feed's host starts a retry sequence on its own
// goroutine, so the other groups and the next round are not delayed; a group
// whose sequence is still running is skipped by the round.
func (s *Server) scheduledSync(ctx context.Context, group string) {
	if _, busy := s.feeds.retryFor(group); busy {
		return
	}
	_, err := s.syncFeedAttempt(ctx, group, "group feed", "", true)
	var tr *feedRetryErr
	if errors.As(err, &tr) {
		log.Printf("group feed %s: attempt 1 of %d failed, retrying: %s", group, 1+feedRetries, tr.detail)
		seq := s.feeds.startRetry(group, feedRetry{At: s.now(), Next: s.now().Add(s.feeds.retryDelay), Reason: tr.detail, Attempt: 1})
		go s.retryFeed(ctx, group, seq)
		return
	}
	s.logScheduled(group, err)
}

// retryFeed runs the retries for one group. The last attempt records its
// result whatever it is, so a feed that stays down is reported after
// 1+feedRetries attempts and not before.
//
// seq identifies the sequence. A result recorded meanwhile (Sync now or
// Accept) clears the entry, and a sequence that no longer owns its entry
// stops, so a later round cannot leave two sequences running for one group.
func (s *Server) retryFeed(ctx context.Context, group string, seq uint64) {
	t := time.NewTimer(s.feeds.retryDelay)
	defer t.Stop()
	for attempt := 2; attempt <= 1+feedRetries; attempt++ {
		select {
		case <-ctx.Done():
			s.feeds.endRetry(group, seq)
			return
		case <-t.C:
		}
		if !s.feeds.ownsRetry(group, seq) {
			return
		}
		last := attempt == 1+feedRetries
		_, err := s.syncFeedAttempt(ctx, group, "group feed", "", !last)
		var tr *feedRetryErr
		if !last && errors.As(err, &tr) {
			log.Printf("group feed %s: attempt %d of %d failed, retrying: %s", group, attempt, 1+feedRetries, tr.detail)
			if !s.feeds.advanceRetry(group, seq, feedRetry{At: s.now(), Next: s.now().Add(s.feeds.retryDelay), Reason: tr.detail, Attempt: attempt}) {
				return
			}
			t.Reset(s.feeds.retryDelay)
			continue
		}
		s.feeds.endRetry(group, seq)
		s.logScheduled(group, err)
		return
	}
}

func (s *Server) logScheduled(group string, err error) {
	if err == nil {
		return
	}
	log.Printf("group feed %s: %v", group, err)
	if errors.Is(err, errStateUnreadable) {
		s.alertFeed(group, "The gateway could not read the group's last sync, so the feed has not been fetched.")
	}
}

// feedRetryErr reports that a fetch failed in a way worth retrying and that
// nothing was recorded.
type feedRetryErr struct{ detail string }

func (e *feedRetryErr) Error() string { return "will retry: " + e.detail }

// feedUnreachable marks a fetch error that may be transient: the feed could
// not be reached, did not answer 200, or broke off while sending.
type feedUnreachable struct{ msg string }

func (e *feedUnreachable) Error() string { return e.msg }

var (
	errNoFeed          = errors.New("group has no feed")
	errNothingHeld     = errors.New("no change is held for this group")
	errChangeReplaced  = errors.New("the held change has been replaced by a newer one")
	errStateUnreadable = errors.New("the last sync state could not be read")
	errAlreadyApplied  = errors.New("the held change has already been applied")
)

// feedHoldAdds and feedHoldRemoves are the largest change applied without an
// administrator: the larger of a fixed count and a quarter of the group.
func feedHoldAdds(current int) int    { return max(5, current/4) }
func feedHoldRemoves(current int) int { return max(2, current/4) }

// feedHoldDrift is the most the members may differ, in total, from the set
// last accepted before a change is held.
func feedHoldDrift(accepted int) int { return max(3, accepted/4) }

// syncFeed fetches group's feed and applies it, unless the change is large
// enough to hold for an administrator. actor is recorded in the audit ("group
// feed" for the hourly sync, the admin's email for "Sync now"). acceptHash,
// when set, accepts the held change the administrator was shown: it applies
// only if a change is held, its hash is acceptHash, and a fresh fetch still
// returns exactly that set.
func (s *Server) syncFeed(ctx context.Context, group, actor, acceptHash string) (store.GroupSyncState, error) {
	return s.syncFeedAttempt(ctx, group, actor, acceptHash, false)
}

// alertFeed posts a short notice to GROUP_FEED_ALERT_URL (an ntfy topic, for
// example) when a feed moves into a failed, empty or held state.
func (s *Server) alertFeed(group, detail string) {
	s.postFeedAlert("Gateway group feed needs attention",
		fmt.Sprintf("Group feed %s needs attention. %s The members have been kept as they were.", group, detail))
}

// alertListLimit is how many addresses an applied-change alert names before
// it gives a count of the rest.
const alertListLimit = 10

// alertApplied announces a change the gateway applied on its own.
func (s *Server) alertApplied(group, note string, add, remove []string) {
	var parts []string
	if len(add) > 0 {
		parts = append(parts, "These members have been added: "+alertList(add)+".")
	}
	if len(remove) > 0 {
		parts = append(parts, "These members have been removed: "+alertList(remove)+".")
	}
	s.postFeedAlert("Gateway group feed changed members",
		fmt.Sprintf("The gateway has updated %s from its feed. %s%s", group, note, strings.Join(parts, " ")))
}

func alertList(emails []string) string {
	if len(emails) <= alertListLimit {
		return strings.Join(emails, ", ")
	}
	return fmt.Sprintf("%s and %d others", strings.Join(emails[:alertListLimit], ", "), len(emails)-alertListLimit)
}

func (s *Server) postFeedAlert(title, msg string) {
	if s.cfg.FeedAlertURL == "" {
		return
	}
	u, err := url.Parse(s.cfg.FeedAlertURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return
	}
	token := s.cfg.FeedAlertToken
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(msg))
		if err != nil {
			return
		}
		req.Header.Set("Title", title)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := s.feeds.client.Do(req)
		if err != nil {
			log.Printf("group feed alert: %v", err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			log.Printf("group feed alert: refused with HTTP %d", resp.StatusCode)
		}
	}()
}
