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
	// KeptHash survives every write, whatever the feed does in between, so
	// a change an administrator kept cannot be revived by the roster
	// returning something else for a round and then the same change again.
	st := store.GroupSyncState{Group: group, LastAttempt: now, AcceptedList: prev.AcceptedList, KeptHash: prev.KeptHash}
	finish := func(status, detail string) (store.GroupSyncState, error) {
		st.Status, st.Detail = status, detail
		if status == store.GroupSyncOK {
			st.LastSuccess = now
		}
		if err := s.store.SetGroupSyncState(dbCtx, st); err != nil {
			return st, err
		}
		s.feeds.clearRetry(group)
		// Alert on entering a problem state, again when a held change is
		// replaced, and whenever a wait to apply automatically starts or
		// restarts, so every alert that matters gives the time it applies.
		if status != store.GroupSyncOK && (prev.Status != status ||
			(status == store.GroupSyncHeld && (prev.PendingHash != st.PendingHash || !st.HeldSince.Equal(prev.HeldSince)))) {
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
	// autoApplied marks a held change applied once its wait has passed.
	autoApplied := false
	skippedNote := ""
	if skipped > 0 {
		skippedNote = fmt.Sprintf(" %d entries were skipped because they were not plain email addresses or not on the allow-list.", skipped)
	}

	if accept && hash != prev.PendingHash {
		st.PendingHash, st.PendingAddList, st.PendingRemoveList = hash, add, remove
		tooLarge := !feed.Rotating && feedTooLarge(len(current), len(emails), len(prev.AcceptedList))
		if s.cfg.FeedAutoApplyAfter > 0 && !tooLarge {
			st.HeldSince = now
		}
		return finish(store.GroupSyncHeld, "The feed has changed since the change was held, so the new change is held for checking instead."+
			s.autoNote(now, hash, st.KeptHash, tooLarge))
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
			// The wait runs from when this exact change was first held. A
			// different change starts it again, so an administrator always
			// has the full wait to see the change that will be applied.
			// The hold time is kept only while a wait is set, so switching
			// the wait on starts every existing hold's wait afresh, with an
			// alert giving its time, rather than applying old holds at once.
			wait := s.cfg.FeedAutoApplyAfter
			heldSince := time.Time{}
			if wait > 0 {
				heldSince = now
				if prev.Status == store.GroupSyncHeld && prev.PendingHash == hash && !prev.HeldSince.IsZero() {
					heldSince = prev.HeldSince
				}
			}
			tooLarge := !feed.Rotating && feedTooLarge(len(current), len(emails), len(prev.AcceptedList))
			if tooLarge {
				// Never applied on its own, so no wait runs and the page
				// offers no Keep button: only Accept applies it.
				heldSince = time.Time{}
			}
			if wait > 0 && !tooLarge && st.KeptHash != hash && !heldSince.Equal(now) && !now.Before(heldSince.Add(wait)) {
				autoApplied = true
			} else {
				st.PendingHash, st.PendingAddList, st.PendingRemoveList = hash, add, remove
				st.HeldSince = heldSince
				detail := "The change is held for checking because " + strings.Join(reasons, ", and ") + "." + skippedNote
				return finish(store.GroupSyncHeld, detail+s.autoNote(heldSince, hash, st.KeptHash, tooLarge))
			}
		}
	}
	if autoApplied {
		// The wait applied it, not whoever pressed Sync now after it ran out.
		actor = "group feed"
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
		if autoApplied {
			summary += fmt.Sprintf(" (applied automatically after being held for %s)", feedWait(s.cfg.FeedAutoApplyAfter))
		}
		events = append(events, store.AdminEvent{Actor: actor, Action: store.AdminActionGroupSync, Target: group, Detail: summary, CreatedAt: now})
		if err := s.store.ApplyGroupSync(dbCtx, group, add, remove, events); err != nil {
			return finish(store.GroupSyncFailed, "The gateway could not update members.")
		}
		s.groupRecheck.forgetAll()
		// A change applied without an administrator is announced, so the
		// roster cannot widen access unseen.
		if !accept {
			note := ""
			if autoApplied {
				note = fmt.Sprintf("The change had been held for %s and no administrator kept the current members. ", feedWait(s.cfg.FeedAutoApplyAfter))
			}
			s.alertApplied(group, note, add, remove)
		}
	}
	// The accepted set moves when an administrator accepts, when a held
	// change has waited out its time, or on a first fill small enough to
	// apply without one.
	if accept || autoApplied || len(prev.AcceptedList) == 0 {
		st.AcceptedList = emails
	}
	if accept || autoApplied {
		st.KeptHash = ""
	}
	detail := fmt.Sprintf("%d members; %d added, %d removed.%s", len(emails), len(add), len(remove), skippedNote)
	if autoApplied {
		detail = fmt.Sprintf("%d members; %d added, %d removed, applied automatically after the change had been held for %s.%s", len(emails), len(add), len(remove), feedWait(s.cfg.FeedAutoApplyAfter), skippedNote)
	}
	return finish(store.GroupSyncOK, detail)
}

// feedTooLarge reports a change no wait should apply on its own: one that
// would leave the group less than half its current size or less than half
// the list last accepted, or more than double its current size (beyond a
// small allowance for a group just starting). A changeover swaps people and
// keeps the size; a roster returning one address, or the whole allow-list,
// does not, and such a change waits for an administrator however long. A
// rotating group (GROUP_FEED_ROTATING), whose whole membership is replaced at
// a changeover, has no ceiling: the wait and Keep current members are its
// safeguards, with the refusal of an empty list.
func feedTooLarge(current, next, accepted int) bool {
	return next*2 < current || next*2 < accepted || next > 2*current+10
}

// autoNote is what a held change's detail says about applying on its own.
func (s *Server) autoNote(heldSince time.Time, hash, kept string, tooLarge bool) string {
	switch {
	case s.cfg.FeedAutoApplyAfter == 0:
		return ""
	case kept == hash:
		return feedKeptNote
	case tooLarge:
		return " The change would more than halve or more than double the group, so it will be applied only if an administrator accepts it."
	}
	return " It will be applied automatically at the first sync after " + s.stampMin(heldSince.Add(s.cfg.FeedAutoApplyAfter)) + " unless an administrator keeps the current members."
}

// feedWait says a wait in words, for details and the audit.
func feedWait(d time.Duration) string {
	if d%time.Hour == 0 {
		if h := int(d / time.Hour); h == 1 {
			return "1 hour"
		} else {
			return fmt.Sprintf("%d hours", h)
		}
	}
	return d.String()
}

// keepHeldChange records that an administrator wants the current members
// kept: the held change shown (hash) is not applied automatically. It can
// still be accepted, and a different change starts its own wait.
func (s *Server) keepHeldChange(ctx context.Context, group, hash string) error {
	s.feeds.mu.Lock()
	defer s.feeds.mu.Unlock()
	states, err := s.store.ListGroupSyncStates(ctx)
	if err != nil {
		return errStateUnreadable
	}
	st := states[group]
	if st.Status != store.GroupSyncHeld {
		if hash != "" && hash == feedSetHash(st.AcceptedList) {
			return errAlreadyApplied
		}
		return errNothingHeld
	}
	if hash == "" || hash != st.PendingHash {
		return errChangeReplaced
	}
	st.KeptHash = hash
	st.Detail = strings.SplitN(st.Detail, " It will be applied automatically at the first sync after ", 2)[0]
	if !strings.HasSuffix(st.Detail, feedKeptNote) {
		st.Detail += feedKeptNote
	}
	return s.store.SetGroupSyncState(ctx, st)
}

const feedKeptNote = " An administrator has kept the current members, so the change will be applied only if it is accepted."

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
		msg := fmt.Sprintf("the feed answered %d", resp.StatusCode)
		// Only an answer that says "try later" is retried: a server error,
		// a timeout or a rate limit. A refused token (401, 403), a moved feed
		// (404, or a redirect, which is never followed) and the like will not
		// change by waiting, and are reported at once.
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests {
			return nil, 0, &feedUnreachable{msg}
		}
		return nil, 0, errors.New(msg)
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
