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
// is applied only when an administrator accepts it. Members of a feed-filled
// group cannot be edited on the admin pages, since the next sync would undo
// the edit; such a group can still be included in other groups.

const (
	feedFetchTimeout = 20 * time.Second
	feedMaxBody      = 1 << 20 // 1 MiB: tens of thousands of addresses
	feedMaxAddresses = 20000
	feedFirstDelay   = time.Minute
)

type feedSyncer struct {
	feeds  map[string]config.GroupFeed
	client *http.Client
	mu     sync.Mutex // one sync at a time; syncs are rare and small
}

func newFeedSyncer(feeds []config.GroupFeed) *feedSyncer {
	m := make(map[string]config.GroupFeed, len(feeds))
	for _, f := range feeds {
		m[f.Group] = f
	}
	return &feedSyncer{
		feeds: m,
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
				if _, err := s.syncFeed(ctx, g, "group feed", ""); err != nil {
					log.Printf("group feed %s: %v", g, err)
					if errors.Is(err, errStateUnreadable) {
						s.alertFeed(g, "The gateway could not read the group's last sync, so the feed has not been fetched.")
					}
				}
			}
			t.Reset(s.cfg.FeedInterval)
		}
	}()
}

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
		// Alert on entering a problem state, and again when a held change
		// is replaced by a different one.
		if status != store.GroupSyncOK && (prev.Status != status || (status == store.GroupSyncHeld && prev.PendingHash != st.PendingHash)) {
			s.alertFeed(group, detail)
		}
		return st, nil
	}

	emails, skipped, err := s.fetchFeed(ctx, feed)
	if err != nil {
		return finish(store.GroupSyncFailed, "The feed could not be used: "+err.Error()+".")
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
		return nil, 0, errors.New("the feed could not be reached")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("the feed answered %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, feedMaxBody+1))
	if err != nil {
		return nil, 0, errors.New("the feed could not be read")
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
	if s.cfg.FeedAlertURL == "" {
		return
	}
	u, err := url.Parse(s.cfg.FeedAlertURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return
	}
	msg := fmt.Sprintf("Group feed %s needs attention. %s The members have been kept as they were.", group, detail)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(msg))
		if err != nil {
			return
		}
		req.Header.Set("Title", "Gateway group feed needs attention")
		resp, err := s.feeds.client.Do(req)
		if err != nil {
			log.Printf("group feed alert: %v", err)
			return
		}
		resp.Body.Close()
	}()
}
