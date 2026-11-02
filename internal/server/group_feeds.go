package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
// is applied only when an administrator accepts it. A scheduled fetch that
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
}

// feedRetry is a retry waiting to run, shown on the Groups page.
type feedRetry struct {
	At      time.Time // when the last attempt failed
	Next    time.Time // when the next attempt runs
	Reason  string    // what went wrong, in the gateway's words
	Attempt int       // attempts made so far
}

func (f *feedSyncer) retryFor(group string) (feedRetry, bool) {
	f.retryMu.Lock()
	defer f.retryMu.Unlock()
	r, ok := f.retrying[group]
	return r, ok
}

func (f *feedSyncer) setRetry(group string, r feedRetry) {
	f.retryMu.Lock()
	f.retrying[group] = r
	f.retryMu.Unlock()
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
		s.feeds.setRetry(group, feedRetry{At: s.now(), Next: s.now().Add(s.feeds.retryDelay), Reason: tr.detail, Attempt: 1})
		go s.retryFeed(ctx, group)
		return
	}
	s.logScheduled(group, err)
}

// retryFeed runs the retries for one group. The last attempt records its
// result whatever it is, so a feed that stays down is reported after
// 1+feedRetries attempts and not before.
func (s *Server) retryFeed(ctx context.Context, group string) {
	t := time.NewTimer(s.feeds.retryDelay)
	defer t.Stop()
	for attempt := 2; attempt <= 1+feedRetries; attempt++ {
		select {
		case <-ctx.Done():
			s.feeds.clearRetry(group)
			return
		case <-t.C:
		}
		// A result recorded meanwhile (an administrator's Sync now) ends the
		// sequence: the group's state is already current.
		if _, waiting := s.feeds.retryFor(group); !waiting {
			return
		}
		last := attempt == 1+feedRetries
		_, err := s.syncFeedAttempt(ctx, group, "group feed", "", !last)
		var tr *feedRetryErr
		if !last && errors.As(err, &tr) {
			s.feeds.setRetry(group, feedRetry{At: s.now(), Next: s.now().Add(s.feeds.retryDelay), Reason: tr.detail, Attempt: attempt})
			t.Reset(s.feeds.retryDelay)
			continue
		}
		s.feeds.clearRetry(group)
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

// syncFeedAttempt is syncFeed with one choice: when mayRetry is set and the
// fetch fails in a way that may be transient (feedUnreachable), it records
// nothing, sends no alert, and returns a *feedRetryErr. Only the scheduled
// round sets it; Sync now and Accept always record the single attempt.
func (s *Server) syncFeedAttempt(ctx context.Context, group, actor, acceptHash string, mayRetry bool) (store.GroupSyncState, error) {
	feed, ok := s.feedFor(group)
	if !ok {
		return store.GroupSyncState{}, errNoFeed
	}
	s.feeds.mu.Lock()
	defer s.feeds.mu.Unlock()
	accept := acceptHash != ""

	// Database writes get their own deadline, so a slow fetch cannot leave a
	// change applied without its record.
	dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()

	now := s.now()
	states, err := s.store.ListGroupSyncStates(dbCtx)
	if err != nil {
		// Without the last state the hold checks cannot run; change nothing
		// and record nothing.
		log.Printf("group feed %s: reading sync state: %v", group, err)
		return store.GroupSyncState{Group: group, Status: store.GroupSyncFailed}, errStateUnreadable
	}
	prev := states[group]
	if accept && prev.Status != store.GroupSyncHeld {
		return prev, errNothingHeld
	}
	if accept && acceptHash != prev.PendingHash {
		return prev, errChangeReplaced
	}
	st := store.GroupSyncState{Group: group, LastAttempt: now, AcceptedList: prev.AcceptedList}
	finish := func(status, detail string) (store.GroupSyncState, error) {
		st.Status, st.Detail = status, detail
		if status == store.GroupSyncOK {
			st.LastSuccess = now
		}
		if err := s.store.SetGroupSyncState(dbCtx, st); err != nil {
			return st, err
		}
		s.feeds.clearRetry(group)
		// Alert on entering a problem state, and again when a held change
		// is replaced by a different one.
		if status != store.GroupSyncOK && (prev.Status != status || (status == store.GroupSyncHeld && prev.PendingHash != st.PendingHash)) {
			s.alertFeed(group, detail)
		}
		return st, nil
	}

	emails, skipped, err := s.fetchFeed(ctx, feed)
	if err != nil {
		detail := "The feed could not be used: " + err.Error() + "."
		var un *feedUnreachable
		if mayRetry && errors.As(err, &un) {
			return prev, &feedRetryErr{detail: detail}
		}
		return finish(store.GroupSyncFailed, detail)
	}
	if len(emails) == 0 {
		return finish(store.GroupSyncEmpty, "The feed returned no usable addresses.")
	}
	exists, err := s.groupExistsCtx(dbCtx, group)
	if err != nil {
		return finish(store.GroupSyncFailed, "The gateway could not read groups.")
	}
	if !exists {
		if err := s.store.CreateGroup(dbCtx, group, ""); err != nil {
			return finish(store.GroupSyncFailed, "The gateway could not create the group.")
		}
	}
	current, err := s.store.ListGroupMembers(dbCtx, group)
	if err != nil {
		return finish(store.GroupSyncFailed, "The gateway could not read members.")
	}
	add, remove := diffMembers(current, emails)
	hash := feedSetHash(emails)
	skippedNote := ""
	if skipped > 0 {
		skippedNote = fmt.Sprintf(" %d entries were skipped because they were not plain email addresses or not on the allow-list.", skipped)
	}

	if accept && hash != prev.PendingHash {
		st.PendingHash, st.PendingAddList, st.PendingRemoveList = hash, add, remove
		return finish(store.GroupSyncHeld, "The feed has changed since the change was held, so the new change is held for checking instead.")
	}
	if !accept && len(add)+len(remove) > 0 {
		var reasons []string
		if len(add) > feedHoldAdds(len(current)) {
			reasons = append(reasons, fmt.Sprintf("it would add %d members", len(add)))
		}
		if len(remove) > feedHoldRemoves(len(current)) {
			reasons = append(reasons, fmt.Sprintf("it would remove %d of %d members", len(remove), len(current)))
		}
		// Drift from the last accepted set, however gradual: a feed cannot
		// replace or grow a group a little at a time unnoticed.
		inA, inB := diffMembers(prev.AcceptedList, emails)
		if drift := len(inA) + len(inB); drift > feedHoldDrift(len(prev.AcceptedList)) {
			reasons = append(reasons, fmt.Sprintf("%d members would differ from the list last accepted", drift))
		}
		if len(reasons) > 0 {
			st.PendingHash, st.PendingAddList, st.PendingRemoveList = hash, add, remove
			return finish(store.GroupSyncHeld, "The change is held for checking because "+strings.Join(reasons, ", and ")+"."+skippedNote)
		}
	}
	if len(add)+len(remove) > 0 {
		events := make([]store.AdminEvent, 0, len(add)+len(remove)+1)
		for _, e := range add {
			events = append(events, store.AdminEvent{Actor: actor, Action: store.AdminActionGroupAddMember, Target: group, Detail: e, CreatedAt: now})
		}
		for _, e := range remove {
			events = append(events, store.AdminEvent{Actor: actor, Action: store.AdminActionGroupRemoveMember, Target: group, Detail: e, CreatedAt: now})
		}
		summary := fmt.Sprintf("added %d, removed %d", len(add), len(remove))
		if accept {
			summary += " (accepted a held change)"
		}
		events = append(events, store.AdminEvent{Actor: actor, Action: store.AdminActionGroupSync, Target: group, Detail: summary, CreatedAt: now})
		if err := s.store.ApplyGroupSync(dbCtx, group, add, remove, events); err != nil {
			return finish(store.GroupSyncFailed, "The gateway could not update members.")
		}
		s.groupRecheck.forgetAll()
		// A change applied without an administrator is announced, so the
		// roster cannot widen access unseen.
		if !accept {
			s.alertApplied(group, add, remove)
		}
	}
	// The accepted set moves only when an administrator accepts, or on a
	// first fill small enough to apply without one.
	if accept || len(prev.AcceptedList) == 0 {
		st.AcceptedList = emails
	}
	return finish(store.GroupSyncOK, fmt.Sprintf("%d members; %d added, %d removed.%s", len(emails), len(add), len(remove), skippedNote))
}

func diffMembers(current, want []string) (add, remove []string) {
	inWant := make(map[string]bool, len(want))
	for _, e := range want {
		inWant[e] = true
	}
	inCur := make(map[string]bool, len(current))
	for _, e := range current {
		inCur[e] = true
		if !inWant[e] {
			remove = append(remove, e)
		}
	}
	for _, e := range want {
		if !inCur[e] {
			add = append(add, e)
		}
	}
	sort.Strings(remove)
	return add, remove
}

// feedSetHash identifies a fetched address set (sorted, de-duplicated).
func feedSetHash(emails []string) string {
	h := sha256.Sum256([]byte(strings.Join(emails, "\n")))
	return hex.EncodeToString(h[:])
}

// fetchFeed GETs the feed and returns its valid, de-duplicated, lower-cased
// addresses and the count of entries skipped as not addresses. The body may
// be a JSON array of strings or an object with an "emails" array.
func (s *Server) fetchFeed(ctx context.Context, feed config.GroupFeed) ([]string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feed.URL, nil)
	if err != nil {
		return nil, 0, errors.New("the feed URL is not usable")
	}
	req.Header.Set("Authorization", "Bearer "+feed.Token)
	req.Header.Set("Accept", "application/json")
	resp, err := s.feeds.client.Do(req)
	if err != nil {
		return nil, 0, &feedUnreachable{"the feed could not be reached"}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, &feedUnreachable{fmt.Sprintf("the feed answered %d", resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, feedMaxBody+1))
	if err != nil {
		return nil, 0, &feedUnreachable{"the feed could not be read"}
	}
	if len(body) > feedMaxBody {
		return nil, 0, errors.New("the feed is larger than 1 MiB")
	}
	var list []string
	if err := json.Unmarshal(body, &list); err != nil {
		var obj struct {
			Emails []string `json:"emails"`
		}
		if err2 := json.Unmarshal(body, &obj); err2 != nil || obj.Emails == nil {
			return nil, 0, errors.New("the feed is not a JSON list of addresses")
		}
		list = obj.Emails
	}
	if len(list) > feedMaxAddresses {
		return nil, 0, fmt.Errorf("the feed lists more than %d addresses", feedMaxAddresses)
	}
	seen := map[string]bool{}
	var out []string
	skipped := 0
	for _, raw := range list {
		e := normalizeEmail(raw)
		// Only plain addresses the allow-list admits: a feed never brings in
		// an outside address, which would otherwise reach group-gated apps
		// through a guest session.
		if !plainAddress(e) || !s.policy.Allowed(e) {
			skipped++
			continue
		}
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	sort.Strings(out)
	return out, skipped, nil
}

func (s *Server) groupExistsCtx(ctx context.Context, name string) (bool, error) {
	groups, err := s.store.ListGroups(ctx)
	if err != nil {
		return false, err
	}
	for _, g := range groups {
		if g.Name == name {
			return true, nil
		}
	}
	return false, nil
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
func (s *Server) alertApplied(group string, add, remove []string) {
	var parts []string
	if len(add) > 0 {
		parts = append(parts, "These members have been added: "+alertList(add)+".")
	}
	if len(remove) > 0 {
		parts = append(parts, "These members have been removed: "+alertList(remove)+".")
	}
	s.postFeedAlert("Gateway group feed changed members",
		fmt.Sprintf("The gateway has updated %s from its feed. %s", group, strings.Join(parts, " ")))
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
