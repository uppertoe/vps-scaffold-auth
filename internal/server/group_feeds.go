package server

import (
	"context"
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
	// A sync that would remove more than this share of the current members
	// (of a group with at least feedShrinkFloor members) is held.
	feedShrinkFloor = 4
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
				if _, err := s.syncFeed(ctx, g, false); err != nil {
					log.Printf("group feed %s: %v", g, err)
				}
			}
			t.Reset(s.cfg.FeedInterval)
		}
	}()
}

var errNoFeed = errors.New("group has no feed")

// syncFeed fetches group's feed and applies it. accept applies a change that
// would otherwise be held for being too large a shrink.
func (s *Server) syncFeed(ctx context.Context, group string, accept bool) (store.GroupSyncState, error) {
	feed, ok := s.feedFor(group)
	if !ok {
		return store.GroupSyncState{}, errNoFeed
	}
	s.feeds.mu.Lock()
	defer s.feeds.mu.Unlock()

	now := s.now()
	prev, _ := s.store.ListGroupSyncStates(ctx)
	st := store.GroupSyncState{Group: group, LastAttempt: now}
	finish := func(status, detail string) (store.GroupSyncState, error) {
		st.Status, st.Detail = status, detail
		if status == store.GroupSyncOK {
			st.LastSuccess = now
		}
		if err := s.store.SetGroupSyncState(ctx, st); err != nil {
			return st, err
		}
		if status != store.GroupSyncOK && prev[group].Status != status {
			s.alertFeed(group, status, detail)
		}
		return st, nil
	}

	emails, skipped, err := s.fetchFeed(ctx, feed)
	if err != nil {
		return finish(store.GroupSyncFailed, "The feed could not be used: "+err.Error()+".")
	}
	if len(emails) == 0 {
		return finish(store.GroupSyncEmpty, "The feed returned no addresses.")
	}

	exists, err := s.groupExistsCtx(ctx, group)
	if err != nil {
		return finish(store.GroupSyncFailed, "The gateway could not read groups.")
	}
	if !exists {
		if err := s.store.CreateGroup(ctx, group, ""); err != nil {
			return finish(store.GroupSyncFailed, "The gateway could not create the group.")
		}
	}
	current, err := s.store.ListGroupMembers(ctx, group)
	if err != nil {
		return finish(store.GroupSyncFailed, "The gateway could not read members.")
	}
	want := make(map[string]bool, len(emails))
	for _, e := range emails {
		want[e] = true
	}
	have := make(map[string]bool, len(current))
	var remove []string
	for _, e := range current {
		have[e] = true
		if !want[e] {
			remove = append(remove, e)
		}
	}
	var add []string
	for _, e := range emails {
		if !have[e] {
			add = append(add, e)
		}
	}
	if !accept && len(current) >= feedShrinkFloor && 2*len(remove) > len(current) {
		st.PendingAdd, st.PendingRemove = len(add), len(remove)
		return finish(store.GroupSyncHeld, fmt.Sprintf("The feed would remove %d of %d members.", len(remove), len(current)))
	}
	if len(add)+len(remove) > 0 {
		if err := s.store.ApplyGroupSync(ctx, group, add, remove); err != nil {
			return finish(store.GroupSyncFailed, "The gateway could not update members.")
		}
		s.groupRecheck.forgetAll()
		_ = s.store.RecordAdminEvent(ctx, store.AdminEvent{
			Actor: "group feed", Action: store.AdminActionGroupSync, Target: group,
			Detail:    feedChangeDetail(add, remove),
			CreatedAt: now,
		})
	}
	detail := fmt.Sprintf("%d members; %d added, %d removed.", len(emails), len(add), len(remove))
	if skipped > 0 {
		detail += fmt.Sprintf(" %d entries were not email addresses and were skipped.", skipped)
	}
	return finish(store.GroupSyncOK, detail)
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
		if !validEmail(e) {
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

// feedChangeDetail summarises a sync for the audit log, listing up to 20
// addresses each way.
func feedChangeDetail(add, remove []string) string {
	list := func(xs []string) string {
		if len(xs) > 20 {
			return strings.Join(xs[:20], ", ") + fmt.Sprintf(" and %d more", len(xs)-20)
		}
		return strings.Join(xs, ", ")
	}
	parts := []string{}
	if len(add) > 0 {
		parts = append(parts, fmt.Sprintf("added %d: %s", len(add), list(add)))
	}
	if len(remove) > 0 {
		parts = append(parts, fmt.Sprintf("removed %d: %s", len(remove), list(remove)))
	}
	return strings.Join(parts, "; ")
}

// alertFeed posts a short notice to GROUP_FEED_ALERT_URL (an ntfy topic, for
// example) when a feed moves into a failed, empty or held state.
func (s *Server) alertFeed(group, status, detail string) {
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
