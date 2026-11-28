// One feed sync: fetching a feed, holding large changes, and applying the difference to the list.

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
	"sort"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

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
	st := store.GroupSyncState{Group: group, LastAttempt: now, AcceptedList: prev.AcceptedList, KeptHash: prev.KeptHash, AddedFrom: prev.AddedFrom}
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

	emails, addedFrom, skipped, err := s.fetchFeed(ctx, feed)
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
	st.AddedFrom = addedFrom
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
		skippedNote = fmt.Sprintf(" %d entries were skipped because they were not plain email addresses or the gateway does not count them as staff.", skipped)
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
		s.markGroupsChanged(now)
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
// keeps the size; a roster returning one address, or every staff address,
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
// addresses, the feed's "added_from" labels for those addresses, and the
// count of entries skipped as not addresses. The body may be a JSON array of
// strings or an object with an "emails" array and, optionally, an
// "added_from" object mapping a listed address to the address the feed made
// it from (roster-insights lists tom.darling for a roster's tom.darling2).
// The labels only describe members; they never add one.
func (s *Server) fetchFeed(ctx context.Context, feed config.GroupFeed) ([]string, map[string]string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feed.URL, nil)
	if err != nil {
		return nil, nil, 0, errors.New("the feed URL is not usable")
	}
	req.Header.Set("Authorization", "Bearer "+feed.Token)
	req.Header.Set("Accept", "application/json")
	resp, err := s.feeds.client.Do(req)
	if err != nil {
		return nil, nil, 0, &feedUnreachable{"the feed could not be reached"}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("the feed answered %d", resp.StatusCode)
		// Only an answer that says "try later" is retried: a server error,
		// a timeout or a rate limit. A refused token (401, 403), a moved feed
		// (404, or a redirect, which is never followed) and the like will not
		// change by waiting, and are reported at once.
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests {
			return nil, nil, 0, &feedUnreachable{msg}
		}
		return nil, nil, 0, errors.New(msg)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, feedMaxBody+1))
	if err != nil {
		return nil, nil, 0, &feedUnreachable{"the feed could not be read"}
	}
	if len(body) > feedMaxBody {
		return nil, nil, 0, errors.New("the feed is larger than 1 MiB")
	}
	var list []string
	var labels map[string]string
	if err := json.Unmarshal(body, &list); err != nil {
		var obj struct {
			Emails    []string          `json:"emails"`
			AddedFrom map[string]string `json:"added_from"`
		}
		if err2 := json.Unmarshal(body, &obj); err2 != nil || obj.Emails == nil {
			return nil, nil, 0, errors.New("the feed is not a JSON list of addresses")
		}
		list, labels = obj.Emails, obj.AddedFrom
	}
	if len(list) > feedMaxAddresses {
		return nil, nil, 0, fmt.Errorf("the feed lists more than %d addresses", feedMaxAddresses)
	}
	// While the gateway cannot tell who is staff, the fetch fails, so the
	// group keeps its members rather than lose every one.
	if s.rolesUnavailable(ctx) {
		return nil, nil, 0, errors.New("the gateway could not read its domain groups")
	}
	seen := map[string]bool{}
	var out []string
	skipped := 0
	for _, raw := range list {
		e := normalizeEmail(raw)
		// Only plain addresses of known people (knownRole: ADMIN_EMAILS,
		// or a domain group's domains): a feed never brings in
		// an outside address, which would otherwise reach group-gated apps
		// through a guest session.
		if !plainAddress(e) || !s.known(ctx, e) {
			skipped++
			continue
		}
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	sort.Strings(out)
	var addedFrom map[string]string
	for k, v := range labels {
		k, v = normalizeEmail(k), normalizeEmail(v)
		if seen[k] && plainAddress(v) && k != v {
			if addedFrom == nil {
				addedFrom = map[string]string{}
			}
			addedFrom[k] = v
		}
	}
	return out, addedFrom, skipped, nil
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
