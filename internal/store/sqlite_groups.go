// Groups (lists): members, includes, feed sync state and resolved membership.

package store

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"time"
)

// --- DB-managed groups ---

// ListGroups returns all groups ordered by name.
func (s *SQLite) ListGroups(ctx context.Context) ([]Group, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, label, kind, COALESCE(org, ''), created_at FROM groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		var g Group
		var created int64
		if err := rows.Scan(&g.Name, &g.Label, &g.Kind, &g.Org, &created); err != nil {
			return nil, err
		}
		g.CreatedAt = time.Unix(created, 0)
		out = append(out, g)
	}
	return out, rows.Err()
}

// CreateGroup inserts a group, ignoring a duplicate name.
func (s *SQLite) CreateGroup(ctx context.Context, name, label string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO groups (name, label, created_at) VALUES (?, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET label = excluded.label`,
		name, label, time.Now().Unix())
	return err
}

// UpdateGroupLabel changes an existing group's display label.
func (s *SQLite) UpdateGroupLabel(ctx context.Context, name, label string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE groups SET label = ? WHERE name = ?`, label, name)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// SetGroupOrg sets a domain group's organisation name; an empty name is
// stored as NULL. It reports whether the domain group exists.
func (s *SQLite) SetGroupOrg(ctx context.Context, name, org string) (bool, error) {
	var v any
	if org != "" {
		v = org
	}
	res, err := s.db.ExecContext(ctx, `UPDATE groups SET org = ? WHERE name = ? AND kind = ?`, v, name, GroupKindDomain)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ErrIncludeCycle is returned when including a group would make a group
// include itself, directly or through others.
var ErrIncludeCycle = errors.New("group include would create a cycle")

// AddGroupInclude makes every member of included a member of group too.
// Both groups must exist. A self-include, or one that would close a cycle, is
// refused with ErrIncludeCycle.
func (s *SQLite) AddGroupInclude(ctx context.Context, group, included string) error {
	if group == included {
		return ErrIncludeCycle
	}
	// Only a list includes another list: a domain group holds domains, not
	// people, so it neither includes nor is included.
	for _, g := range []string{group, included} {
		kind, ok, err := s.groupKind(ctx, g)
		if err != nil {
			return err
		}
		if ok && kind != GroupKindList {
			return ErrGroupKind
		}
	}
	// Check and insert in one transaction, so two opposite includes posted at
	// once cannot both pass the check.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit
	// A cycle forms if group is already reachable downwards from included.
	var n int
	if err := tx.QueryRowContext(ctx,
		`WITH RECURSIVE d(name) AS (
		   SELECT included FROM group_includes WHERE group_name = ?
		   UNION
		   SELECT gi.included FROM group_includes gi JOIN d ON gi.group_name = d.name
		 )
		 SELECT COUNT(*) FROM d WHERE name = ?`, included, group).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrIncludeCycle
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO group_includes (group_name, included, created_at) VALUES (?, ?, ?)
		 ON CONFLICT(group_name, included) DO NOTHING`,
		group, included, time.Now().Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

// RemoveGroupInclude stops group including included.
func (s *SQLite) RemoveGroupInclude(ctx context.Context, group, included string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM group_includes WHERE group_name = ? AND included = ?`, group, included)
	return err
}

// ListGroupIncludes returns every include as group -> included groups.
func (s *SQLite) ListGroupIncludes(ctx context.Context) (map[string][]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT group_name, included FROM group_includes ORDER BY group_name, included`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var g, inc string
		if err := rows.Scan(&g, &inc); err != nil {
			return nil, err
		}
		out[g] = append(out[g], inc)
	}
	return out, rows.Err()
}

// AddGroupMembers adds several addresses to a group in one transaction and
// returns the ones that were not already members.
func (s *SQLite) AddGroupMembers(ctx context.Context, group string, emails []string) ([]string, error) {
	if err := s.refuseDomainGroup(ctx, group); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit
	now := time.Now().Unix()
	var added []string
	for _, e := range emails {
		res, err := tx.ExecContext(ctx,
			`INSERT INTO group_members (group_name, email, created_at) VALUES (?, ?, ?)
			 ON CONFLICT(group_name, email) DO NOTHING`, group, e, now)
		if err != nil {
			return nil, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			added = append(added, e)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return added, nil
}

// ApplyGroupSync adds and removes members of a feed-filled group, and records
// the audit events, in one transaction: the change and its record succeed or
// fail together.
func (s *SQLite) ApplyGroupSync(ctx context.Context, group string, add, remove []string, events []AdminEvent) error {
	if err := s.refuseDomainGroup(ctx, group); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit
	now := time.Now().Unix()
	for _, e := range add {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO group_members (group_name, email, created_at) VALUES (?, ?, ?)
			 ON CONFLICT(group_name, email) DO NOTHING`, group, e, now); err != nil {
			return err
		}
	}
	for _, e := range remove {
		if _, err := tx.ExecContext(ctx, `DELETE FROM group_members WHERE group_name = ? AND email = ?`, group, e); err != nil {
			return err
		}
	}
	for _, e := range events {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO admin_events (actor, action, target, detail, client_ip, user_agent, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			e.Actor, e.Action, e.Target, e.Detail, e.ClientIP, e.UserAgent, e.CreatedAt.Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SetGroupSyncState records the outcome of a feed sync.
func (s *SQLite) SetGroupSyncState(ctx context.Context, st GroupSyncState) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO group_sync_state (group_name, last_attempt, last_success, status, detail, pending_add, pending_remove,
		   pending_hash, pending_add_list, pending_remove_list, accepted_list, held_since, kept_hash, added_from)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(group_name) DO UPDATE SET
		   last_attempt = excluded.last_attempt,
		   last_success = CASE WHEN excluded.last_success > 0 THEN excluded.last_success ELSE group_sync_state.last_success END,
		   status = excluded.status, detail = excluded.detail,
		   pending_add = excluded.pending_add, pending_remove = excluded.pending_remove,
		   pending_hash = excluded.pending_hash, pending_add_list = excluded.pending_add_list,
		   pending_remove_list = excluded.pending_remove_list, accepted_list = excluded.accepted_list,
		   held_since = excluded.held_since, kept_hash = excluded.kept_hash, added_from = excluded.added_from`,
		st.Group, st.LastAttempt.Unix(), unixOrZero(st.LastSuccess), st.Status, st.Detail, len(st.PendingAddList), len(st.PendingRemoveList),
		st.PendingHash, strings.Join(st.PendingAddList, "\n"), strings.Join(st.PendingRemoveList, "\n"), strings.Join(st.AcceptedList, "\n"),
		unixOrZero(st.HeldSince), st.KeptHash, joinPairs(st.AddedFrom))
	return err
}

// ListGroupSyncStates returns the last sync outcome per group.
func (s *SQLite) ListGroupSyncStates(ctx context.Context) (map[string]GroupSyncState, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT group_name, last_attempt, last_success, status, detail, pending_add, pending_remove,
		        pending_hash, pending_add_list, pending_remove_list, accepted_list, held_since, kept_hash, added_from FROM group_sync_state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]GroupSyncState{}
	for rows.Next() {
		var st GroupSyncState
		var attempt, success, heldSince int64
		var nAdd, nRemove int
		var addList, removeList, acceptedList, addedFrom string
		if err := rows.Scan(&st.Group, &attempt, &success, &st.Status, &st.Detail, &nAdd, &nRemove,
			&st.PendingHash, &addList, &removeList, &acceptedList, &heldSince, &st.KeptHash, &addedFrom); err != nil {
			return nil, err
		}
		st.AddedFrom = splitPairs(addedFrom)
		st.PendingAddList, st.PendingRemoveList = splitLines(addList), splitLines(removeList)
		st.AcceptedList = splitLines(acceptedList)
		st.LastAttempt = time.Unix(attempt, 0)
		if success > 0 {
			st.LastSuccess = time.Unix(success, 0)
		}
		if heldSince > 0 {
			st.HeldSince = time.Unix(heldSince, 0)
		}
		out[st.Group] = st
	}
	return out, rows.Err()
}

// joinPairs stores a map as sorted "key<TAB>value" lines; splitPairs reads it.
func joinPairs(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		lines = append(lines, k+"\t"+m[k])
	}
	return strings.Join(lines, "\n")
}

func splitPairs(s string) map[string]string {
	if s == "" {
		return nil
	}
	out := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(line, "\t"); ok {
			out[k] = v
		}
	}
	return out
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// DeleteGroup removes a group; memberships, includes and domain rules
// cascade. A group that a role assignment names is refused with
// ErrGroupHoldsRoles, checked in the same transaction as the delete.
func (s *SQLite) DeleteGroup(ctx context.Context, name string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit
	n, err := groupRoleCountIn(ctx, tx, name)
	if err != nil {
		return err
	}
	if n > 0 {
		return ErrGroupHoldsRoles
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM groups WHERE name = ?`, name); err != nil {
		return err
	}
	// An approval to read a group's members is for this group, never for a
	// group created later under the same name.
	if _, err := tx.ExecContext(ctx, `DELETE FROM member_reader_approvals WHERE group_name = ?`, name); err != nil {
		return err
	}
	return tx.Commit()
}

// AddGroupMember adds an email to a group (idempotent). A domain group has
// no members, so it is refused with ErrGroupKind.
func (s *SQLite) AddGroupMember(ctx context.Context, group, email string) error {
	if err := s.refuseDomainGroup(ctx, group); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO group_members (group_name, email, created_at) VALUES (?, ?, ?)
		 ON CONFLICT(group_name, email) DO NOTHING`,
		group, email, time.Now().Unix())
	return err
}

// RemoveGroupMember removes an email from a group.
func (s *SQLite) RemoveGroupMember(ctx context.Context, group, email string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM group_members WHERE group_name = ? AND email = ?`, group, email)
	return err
}

// ListGroupMembers returns a group's member emails, ordered.
func (s *SQLite) ListGroupMembers(ctx context.Context, group string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT email FROM group_members WHERE group_name = ? ORDER BY email`, group)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GroupsForEmail returns the group names an email belongs to.
func (s *SQLite) GroupsForEmail(ctx context.Context, email string) ([]string, error) {
	// Direct memberships, then every group that includes one of them, and so
	// on upwards. UNION (not UNION ALL) drops repeats, so the walk ends even
	// if a cycle ever slipped past AddGroupInclude's check.
	rows, err := s.db.QueryContext(ctx,
		`WITH RECURSIVE g(name) AS (
		   SELECT group_name FROM group_members WHERE email = ?
		   UNION
		   SELECT gi.group_name FROM group_includes gi JOIN g ON gi.included = g.name
		 )
		 SELECT name FROM g ORDER BY name`, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// GroupMembersResolved returns the addresses a group admits: its own members
// and, through includes, the members of every group it includes, and so on
// down. It is the inverse of GroupsForEmail: an address is listed here
// exactly when group is among GroupsForEmail(address). exists is false when
// the group does not exist.
func (s *SQLite) GroupMembersResolved(ctx context.Context, group string) (members []string, exists bool, err error) {
	var one int
	switch err := s.db.QueryRowContext(ctx, `SELECT 1 FROM groups WHERE name = ?`, group).Scan(&one); {
	case err == sql.ErrNoRows:
		return nil, false, nil
	case err != nil:
		return nil, false, err
	}
	rows, err := s.db.QueryContext(ctx,
		`WITH RECURSIVE g(name) AS (
		   SELECT ?
		   UNION
		   SELECT gi.included FROM group_includes gi JOIN g ON gi.group_name = g.name
		 )
		 SELECT DISTINCT email FROM group_members WHERE group_name IN (SELECT name FROM g) ORDER BY email`, group)
	if err != nil {
		return nil, true, err
	}
	defer rows.Close()
	members = []string{}
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return nil, true, err
		}
		members = append(members, e)
	}
	return members, true, rows.Err()
}
