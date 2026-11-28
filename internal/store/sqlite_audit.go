// Audit records: admin and sign-in events, app access, member reads and reader approvals.

package store

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"time"
)

// RecordAdminEvent appends an administrative-action audit row.
func (s *SQLite) RecordAdminEvent(ctx context.Context, e AdminEvent) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO admin_events (actor, action, target, detail, client_ip, user_agent, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.Actor, e.Action, e.Target, e.Detail, e.ClientIP, e.UserAgent, e.CreatedAt.Unix())
	return err
}

// ListAdminEvents returns admin-action events, newest first.
func (s *SQLite) ListAdminEvents(ctx context.Context, limit, offset int) ([]AdminEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, actor, action, target, detail, client_ip, user_agent, created_at
		 FROM admin_events ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdminEvent
	for rows.Next() {
		var e AdminEvent
		var ts int64
		if err := rows.Scan(&e.ID, &e.Actor, &e.Action, &e.Target, &e.Detail, &e.ClientIP, &e.UserAgent, &ts); err != nil {
			return nil, err
		}
		e.CreatedAt = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// RecordAuthEvent appends a login-flow audit row.
func (s *SQLite) RecordAuthEvent(ctx context.Context, e AuthEvent) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_events (email, event_type, outcome, client_ip, user_agent, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		e.Email, e.EventType, e.Outcome, e.ClientIP, e.UserAgent, e.CreatedAt.Unix())
	return err
}

// HasRecentLogin reports whether email signed in successfully from clientIP at
// or after since. The partial index idx_auth_events_login answers it alone.
func (s *SQLite) HasRecentLogin(ctx context.Context, email, clientIP string, since time.Time) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx,
		// The event type and outcome are literals so that SQLite can use the
		// partial index idx_auth_events_login, which answers this alone.
		`SELECT 1 FROM auth_events
		 WHERE event_type = 'login' AND outcome = 'ok' AND email = ? AND client_ip = ? AND created_at >= ?
		 LIMIT 1`,
		email, clientIP, since.Unix()).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

// ListAuthEvents returns login-flow events, newest first. Empty email = all.
func (s *SQLite) ListAuthEvents(ctx context.Context, email string, limit, offset int) ([]AuthEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `SELECT id, email, event_type, outcome, client_ip, user_agent, created_at FROM auth_events`
	args := []any{}
	if email != "" {
		query += ` WHERE email = ?`
		args = append(args, email)
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuthEvent
	for rows.Next() {
		var e AuthEvent
		var created int64
		if err := rows.Scan(&e.ID, &e.Email, &e.EventType, &e.Outcome, &e.ClientIP, &e.UserAgent, &created); err != nil {
			return nil, err
		}
		e.CreatedAt = time.Unix(created, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// RecordAppAccess records one app access, ignoring a repeat within the same hour
// bucket (the UNIQUE constraint makes this idempotent).
func (s *SQLite) RecordAppAccess(ctx context.Context, a AppAccess) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO app_access (email, host, kind, bucket, created_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(email, host, kind, bucket) DO NOTHING`,
		a.Email, a.Host, a.Kind, a.Bucket, a.CreatedAt.Unix())
	return err
}

// likeContains is a LIKE pattern matching any text containing sub, with the
// pattern characters in sub escaped (ESCAPE '\').
func likeContains(sub string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(strings.ToLower(sub)) + "%"
}

// accessWhere builds the WHERE clause shared by the access-log queries.
func accessWhere(f AccessFilter, withHost bool) (string, []any) {
	where := ` WHERE created_at >= ?`
	args := []any{f.Since.Unix()}
	switch {
	case f.Email != "" && f.EmailExact:
		where += ` AND email = ?`
		args = append(args, strings.ToLower(f.Email))
	case f.Email != "":
		where += ` AND email LIKE ? ESCAPE '\'`
		args = append(args, likeContains(f.Email))
	}
	if withHost && f.Host != "" {
		where += ` AND host = ?`
		args = append(args, f.Host)
	}
	return where, args
}

func (s *SQLite) SummariseAppAccess(ctx context.Context, f AccessFilter, dayOffset int) ([]AccessSummary, error) {
	where, args := accessWhere(f, true)
	rows, err := s.db.QueryContext(ctx,
		`SELECT email, host, kind, MIN(created_at), MAX(created_at), COUNT(*),
		        COUNT(DISTINCT (bucket * 3600 + ?) / 86400)
		 FROM app_access`+where+`
		 GROUP BY email, host, kind
		 ORDER BY MAX(created_at) DESC, email, host`,
		append([]any{dayOffset}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccessSummary
	for rows.Next() {
		var a AccessSummary
		var first, last int64
		if err := rows.Scan(&a.Email, &a.Host, &a.Kind, &first, &last, &a.Hours, &a.Days); err != nil {
			return nil, err
		}
		a.First, a.Last = time.Unix(first, 0), time.Unix(last, 0)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *SQLite) SummarisePeople(ctx context.Context, f AccessFilter, dayOffset int) ([]AccessSummary, error) {
	where, args := accessWhere(f, true)
	rows, err := s.db.QueryContext(ctx,
		`SELECT email, MIN(created_at), MAX(created_at), COUNT(DISTINCT bucket),
		        COUNT(DISTINCT (bucket * 3600 + ?) / 86400)
		 FROM app_access`+where+`
		 GROUP BY email
		 ORDER BY MAX(created_at) DESC, email`,
		append([]any{dayOffset}, args...)...)
	if err != nil {
		return nil, err
	}
	var out []AccessSummary
	for rows.Next() {
		var a AccessSummary
		var first, last int64
		if err := rows.Scan(&a.Email, &first, &last, &a.Hours, &a.Days); err != nil {
			rows.Close()
			return nil, err
		}
		a.First, a.Last = time.Unix(first, 0), time.Unix(last, 0)
		out = append(out, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Each person's sites and kinds, read separately so each list is sorted
	// and distinct without relying on GROUP_CONCAT ordering.
	sites := map[string][]string{}
	kinds := map[string][]string{}
	pairs, err := s.db.QueryContext(ctx, `SELECT DISTINCT email, host, kind FROM app_access`+where+` ORDER BY email, host, kind`, args...)
	if err != nil {
		return nil, err
	}
	defer pairs.Close()
	for pairs.Next() {
		var e, h, k string
		if err := pairs.Scan(&e, &h, &k); err != nil {
			return nil, err
		}
		if l := sites[e]; len(l) == 0 || l[len(l)-1] != h {
			sites[e] = append(l, h)
		}
		if k != "" && !slices.Contains(kinds[e], k) {
			kinds[e] = append(kinds[e], k)
		}
	}
	if err := pairs.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Sites, out[i].Kinds = sites[out[i].Email], kinds[out[i].Email]
	}
	return out, nil
}

func (s *SQLite) AppAccessHosts(ctx context.Context, since time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT host FROM app_access WHERE created_at >= ? ORDER BY host`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *SQLite) ListAuthEventsFiltered(ctx context.Context, f AccessFilter, limit int) ([]AuthEvent, error) {
	where, args := accessWhere(f, false)
	if f.RefusedOnly {
		where += ` AND outcome <> 'ok'`
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, email, event_type, outcome, client_ip, user_agent, created_at FROM auth_events`+where+
			` ORDER BY created_at DESC, id DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuthEvent
	for rows.Next() {
		var e AuthEvent
		var created int64
		if err := rows.Scan(&e.ID, &e.Email, &e.EventType, &e.Outcome, &e.ClientIP, &e.UserAgent, &created); err != nil {
			return nil, err
		}
		e.CreatedAt = time.Unix(created, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListAppAccess returns app-access rows, newest first. Empty email = all.
func (s *SQLite) ListAppAccess(ctx context.Context, email string, limit, offset int) ([]AppAccess, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `SELECT id, email, host, kind, bucket, created_at FROM app_access`
	args := []any{}
	if email != "" {
		query += ` WHERE email = ?`
		args = append(args, email)
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AppAccess
	for rows.Next() {
		var a AppAccess
		var created int64
		if err := rows.Scan(&a.ID, &a.Email, &a.Host, &a.Kind, &a.Bucket, &created); err != nil {
			return nil, err
		}
		a.CreatedAt = time.Unix(created, 0)
		out = append(out, a)
	}
	return out, rows.Err()
}

// PruneAuditBefore enforces the retention window across both audit tables.
func (s *SQLite) PruneAuditBefore(ctx context.Context, cutoff time.Time) error {
	cut := cutoff.Unix()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM auth_events WHERE created_at < ?`, cut); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM app_access WHERE created_at < ?`, cut); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM member_reads WHERE last_at < ?`, cut); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM admin_events WHERE created_at < ?`, cut)
	return err
}

// RecordMemberRead notes that app read group's members from source (the
// caller's address), folded to one row per app, group, source and hour with a
// count of reads. A token used from a second container shows as a second
// source.
func (s *SQLite) RecordMemberRead(ctx context.Context, app, group, source string, at time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO member_reads (app, group_name, source, bucket, created_at, last_at) VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(app, group_name, source, bucket) DO UPDATE SET reads = reads + 1, last_at = excluded.last_at`,
		app, group, source, at.Unix()/3600, at.Unix(), at.Unix())
	return err
}

// ListMemberReaderApprovals returns every approval, ordered by app and group.
func (s *SQLite) ListMemberReaderApprovals(ctx context.Context) ([]MemberReaderApproval, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT app, group_name, approved_by, approved_at FROM member_reader_approvals ORDER BY app, group_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MemberReaderApproval
	for rows.Next() {
		var a MemberReaderApproval
		var at int64
		if err := rows.Scan(&a.App, &a.Group, &a.ApprovedBy, &at); err != nil {
			return nil, err
		}
		a.ApprovedAt = time.Unix(at, 0)
		out = append(out, a)
	}
	return out, rows.Err()
}

// MemberReaderApproved reports whether app may read group's members.
func (s *SQLite) MemberReaderApproved(ctx context.Context, app, group string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM member_reader_approvals WHERE app = ? AND group_name = ?`, app, group).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// ApproveMemberReader records an approval; an existing one is kept as it was,
// and nothing is recorded for a group that does not exist, so an approval can
// never outlive a group deleted at the same moment.
func (s *SQLite) ApproveMemberReader(ctx context.Context, app, group, by string, at time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO member_reader_approvals (app, group_name, approved_by, approved_at)
		 SELECT ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM groups WHERE name = ?)
		 ON CONFLICT(app, group_name) DO NOTHING`, app, group, by, at.Unix(), group)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// WithdrawMemberReader removes an approval.
func (s *SQLite) WithdrawMemberReader(ctx context.Context, app, group string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM member_reader_approvals WHERE app = ? AND group_name = ?`, app, group)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// SummariseMemberReads returns one row per app and group read since since,
// newest last read first.
func (s *SQLite) SummariseMemberReads(ctx context.Context, since time.Time) ([]MemberReadSummary, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT app, group_name, source, MIN(created_at), MAX(last_at), SUM(reads)
		 FROM member_reads WHERE last_at >= ?
		 GROUP BY app, group_name, source ORDER BY MAX(last_at) DESC, app, group_name, source`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MemberReadSummary
	for rows.Next() {
		var m MemberReadSummary
		var first, last int64
		if err := rows.Scan(&m.App, &m.Group, &m.Source, &first, &last, &m.Reads); err != nil {
			return nil, err
		}
		m.First, m.Last = time.Unix(first, 0), time.Unix(last, 0)
		out = append(out, m)
	}
	return out, rows.Err()
}
