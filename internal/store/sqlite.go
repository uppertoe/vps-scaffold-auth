package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // pure-Go, CGO-free SQLite driver
)

// SQLite is a Store backed by a single SQLite file. It uses WAL mode and a
// busy timeout so the (single-instance) service never trips over its own
// concurrent reads/writes.
type SQLite struct {
	db *sql.DB
}

// OpenSQLite opens (creating if necessary) the database at path and applies the
// schema.
func OpenSQLite(path string) (*SQLite, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite writes are serialized; a single connection avoids "database is
	// locked" churn and is plenty for this low-volume service.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	s := &SQLite{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *SQLite) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS codes (
	email      TEXT PRIMARY KEY,
	code_hash  TEXT NOT NULL,
	expires_at INTEGER NOT NULL,
	attempts   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS totp_secrets (
	email  TEXT PRIMARY KEY,
	secret TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS groups (
	name       TEXT PRIMARY KEY,
	label      TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS group_members (
	group_name TEXT NOT NULL REFERENCES groups(name) ON DELETE CASCADE,
	email      TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	PRIMARY KEY (group_name, email)
);
CREATE INDEX IF NOT EXISTS idx_group_members_email ON group_members(email);
CREATE TABLE IF NOT EXISTS break_glass_codes (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	label        TEXT NOT NULL UNIQUE,
	note         TEXT NOT NULL DEFAULT '',
	target_group TEXT NOT NULL,
	token_enc    TEXT NOT NULL,
	token_hash   TEXT NOT NULL UNIQUE,
	redirect     TEXT NOT NULL DEFAULT '',
	status       TEXT NOT NULL DEFAULT 'active',
	created_at   INTEGER NOT NULL,
	updated_at   INTEGER NOT NULL,
	ov_title        TEXT NOT NULL DEFAULT '',
	ov_body         TEXT NOT NULL DEFAULT '',
	ov_instructions TEXT NOT NULL DEFAULT '',
	ov_header_color TEXT NOT NULL DEFAULT '',
	ov_accent_color TEXT NOT NULL DEFAULT '',
	ov_bar1_color   TEXT NOT NULL DEFAULT '',
	ov_bar2_color   TEXT NOT NULL DEFAULT '',
	ov_bar3_color   TEXT NOT NULL DEFAULT '',
	ov_logo         BLOB,
	ov_logo_type    TEXT NOT NULL DEFAULT '',
	ov_glyph        BLOB,
	ov_glyph_type   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_bg_codes_status ON break_glass_codes(status);
CREATE TABLE IF NOT EXISTS break_glass_events (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	code_id    INTEGER NOT NULL REFERENCES break_glass_codes(id) ON DELETE CASCADE,
	label      TEXT NOT NULL,
	client_ip  TEXT NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL DEFAULT '',
	outcome    TEXT NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bg_events_code ON break_glass_events(code_id, created_at);
CREATE TABLE IF NOT EXISTS pdf_branding (
	id            INTEGER PRIMARY KEY CHECK (id = 1),
	title         TEXT NOT NULL DEFAULT '',
	body          TEXT NOT NULL DEFAULT '',
	instructions  TEXT NOT NULL DEFAULT '',
	logo          BLOB,
	logo_type     TEXT NOT NULL DEFAULT '',
	glyph         BLOB,
	glyph_type    TEXT NOT NULL DEFAULT '',
	pdf_logo      BLOB,
	pdf_logo_type TEXT NOT NULL DEFAULT '',
	header_color  TEXT NOT NULL DEFAULT '',
	accent_color  TEXT NOT NULL DEFAULT '',
	bar1_color    TEXT NOT NULL DEFAULT '',
	bar2_color    TEXT NOT NULL DEFAULT '',
	bar3_color    TEXT NOT NULL DEFAULT '',
	updated_at    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS app_settings (
	id                  INTEGER PRIMARY KEY CHECK (id = 1),
	breakglass_secs     INTEGER NOT NULL DEFAULT 0,
	notify_emails       TEXT NOT NULL DEFAULT '',
	webhook_url         TEXT NOT NULL DEFAULT '',
	updated_at          INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS auth_events (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	email      TEXT NOT NULL,
	event_type TEXT NOT NULL,
	outcome    TEXT NOT NULL,
	client_ip  TEXT NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_events_email ON auth_events(email, created_at);
CREATE INDEX IF NOT EXISTS idx_auth_events_created ON auth_events(created_at);
CREATE TABLE IF NOT EXISTS app_access (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	email      TEXT NOT NULL,
	host       TEXT NOT NULL,
	kind       TEXT NOT NULL DEFAULT '',
	bucket     INTEGER NOT NULL,
	created_at INTEGER NOT NULL,
	UNIQUE (email, host, kind, bucket)
);
CREATE INDEX IF NOT EXISTS idx_app_access_email ON app_access(email, created_at);
CREATE INDEX IF NOT EXISTS idx_app_access_created ON app_access(created_at);
CREATE TABLE IF NOT EXISTS admin_events (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	actor      TEXT NOT NULL,
	action     TEXT NOT NULL,
	target     TEXT NOT NULL DEFAULT '',
	detail     TEXT NOT NULL DEFAULT '',
	client_ip  TEXT NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_admin_events_created ON admin_events(created_at);
CREATE INDEX IF NOT EXISTS idx_admin_events_actor ON admin_events(actor, created_at);`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	// Forward-compatible column adds for databases created by an earlier build.
	if err := s.ensureColumns("pdf_branding", []column{
		{"header_color", "TEXT NOT NULL DEFAULT ''"},
		{"accent_color", "TEXT NOT NULL DEFAULT ''"},
		{"bar1_color", "TEXT NOT NULL DEFAULT ''"},
		{"bar2_color", "TEXT NOT NULL DEFAULT ''"},
		{"bar3_color", "TEXT NOT NULL DEFAULT ''"},
		{"pdf_logo", "BLOB"},
		{"pdf_logo_type", "TEXT NOT NULL DEFAULT ''"},
	}); err != nil {
		return err
	}
	return s.ensureColumns("break_glass_codes", []column{
		{"ov_title", "TEXT NOT NULL DEFAULT ''"},
		{"ov_body", "TEXT NOT NULL DEFAULT ''"},
		{"ov_instructions", "TEXT NOT NULL DEFAULT ''"},
		{"ov_header_color", "TEXT NOT NULL DEFAULT ''"},
		{"ov_accent_color", "TEXT NOT NULL DEFAULT ''"},
		{"ov_bar1_color", "TEXT NOT NULL DEFAULT ''"},
		{"ov_bar2_color", "TEXT NOT NULL DEFAULT ''"},
		{"ov_bar3_color", "TEXT NOT NULL DEFAULT ''"},
		{"ov_logo", "BLOB"},
		{"ov_logo_type", "TEXT NOT NULL DEFAULT ''"},
		{"ov_glyph", "BLOB"},
		{"ov_glyph_type", "TEXT NOT NULL DEFAULT ''"},
	})
}

type column struct{ name, def string }

// ensureColumns adds any missing columns to table (idempotent). Names and
// definitions are code-controlled literals.
func (s *SQLite) ensureColumns(table string, cols []column) error {
	rows, err := s.db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return err
	}
	existing := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		existing[name] = true
	}
	rows.Close()
	for _, c := range cols {
		if existing[c.name] {
			continue
		}
		if _, err := s.db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + c.name + ` ` + c.def); err != nil {
			return err
		}
	}
	return nil
}

// SaveCode upserts the code hash for an email, resetting attempts to zero.
func (s *SQLite) SaveCode(ctx context.Context, email, codeHash string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO codes (email, code_hash, expires_at, attempts)
VALUES (?, ?, ?, 0)
ON CONFLICT(email) DO UPDATE SET
	code_hash = excluded.code_hash,
	expires_at = excluded.expires_at,
	attempts = 0`,
		email, codeHash, expiresAt.Unix())
	return err
}

// EnsureCode inserts a code for an email only if none already exists, never
// clobbering a live code. See the Store interface.
func (s *SQLite) EnsureCode(ctx context.Context, email, codeHash string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO codes (email, code_hash, expires_at, attempts)
VALUES (?, ?, ?, 0)
ON CONFLICT(email) DO NOTHING`,
		email, codeHash, expiresAt.Unix())
	return err
}

// HasRecentCode reports whether a code row exists for email with an expiry later
// than minExpiry. Issue time is derived from expires_at (which equals issue time
// + OTP_TTL), so a row surviving this filter was minted within the cooldown
// window. See the Store interface.
func (s *SQLite) HasRecentCode(ctx context.Context, email string, minExpiry time.Time) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM codes WHERE email = ? AND expires_at > ?`,
		email, minExpiry.Unix()).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// DeleteExpiredCodes prunes code rows past their expiry.
func (s *SQLite) DeleteExpiredCodes(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM codes WHERE expires_at < ?`, now.Unix())
	return err
}

// ConsumeCode performs the verify-and-consume in a single transaction.
func (s *SQLite) ConsumeCode(ctx context.Context, email, candidateHash string, maxAttempts int, now time.Time) (ConsumeResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ConsumeNoCode, err
	}
	defer tx.Rollback()

	var storedHash string
	var expiresAt int64
	var attempts int
	err = tx.QueryRowContext(ctx,
		`SELECT code_hash, expires_at, attempts FROM codes WHERE email = ?`, email).
		Scan(&storedHash, &expiresAt, &attempts)
	if err == sql.ErrNoRows {
		return ConsumeNoCode, nil
	}
	if err != nil {
		return ConsumeNoCode, err
	}

	del := func() error {
		_, e := tx.ExecContext(ctx, `DELETE FROM codes WHERE email = ?`, email)
		return e
	}

	if now.Unix() > expiresAt {
		if err := del(); err != nil {
			return ConsumeExpired, err
		}
		return ConsumeExpired, tx.Commit()
	}
	if attempts >= maxAttempts {
		if err := del(); err != nil {
			return ConsumeTooManyAttempts, err
		}
		return ConsumeTooManyAttempts, tx.Commit()
	}

	if subtle.ConstantTimeCompare([]byte(storedHash), []byte(candidateHash)) == 1 {
		if err := del(); err != nil {
			return ConsumeOK, err
		}
		return ConsumeOK, tx.Commit()
	}

	// Wrong code: count the attempt, and invalidate if the cap is now reached.
	attempts++
	if attempts >= maxAttempts {
		if err := del(); err != nil {
			return ConsumeTooManyAttempts, err
		}
		return ConsumeTooManyAttempts, tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `UPDATE codes SET attempts = ? WHERE email = ?`, attempts, email); err != nil {
		return ConsumeMismatch, err
	}
	return ConsumeMismatch, tx.Commit()
}

// GetTOTPSecret returns the stored secret for an email, if present.
func (s *SQLite) GetTOTPSecret(ctx context.Context, email string) (string, bool, error) {
	var secret string
	err := s.db.QueryRowContext(ctx, `SELECT secret FROM totp_secrets WHERE email = ?`, email).Scan(&secret)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return secret, true, nil
}

// SetTOTPSecret stores or replaces the secret for an email.
func (s *SQLite) SetTOTPSecret(ctx context.Context, email, secret string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO totp_secrets (email, secret) VALUES (?, ?)
ON CONFLICT(email) DO UPDATE SET secret = excluded.secret`, email, secret)
	return err
}

// DeleteTOTPSecret removes the secret for an email (no-op if absent).
func (s *SQLite) DeleteTOTPSecret(ctx context.Context, email string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM totp_secrets WHERE email = ?`, email)
	return err
}

// --- DB-managed groups ---

// ListGroups returns all groups ordered by name.
func (s *SQLite) ListGroups(ctx context.Context) ([]Group, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, label, created_at FROM groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		var g Group
		var created int64
		if err := rows.Scan(&g.Name, &g.Label, &created); err != nil {
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

// DeleteGroup removes a group; memberships cascade.
func (s *SQLite) DeleteGroup(ctx context.Context, name string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM groups WHERE name = ?`, name)
	return err
}

// AddGroupMember adds an email to a group (idempotent).
func (s *SQLite) AddGroupMember(ctx context.Context, group, email string) error {
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
	rows, err := s.db.QueryContext(ctx,
		`SELECT group_name FROM group_members WHERE email = ? ORDER BY group_name`, email)
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

// --- Break-the-glass codes ---

const bgColumns = `id, label, note, target_group, token_enc, token_hash, redirect, status, created_at, updated_at`

func scanBreakGlass(sc interface{ Scan(...any) error }) (BreakGlassCode, error) {
	var c BreakGlassCode
	var created, updated int64
	err := sc.Scan(&c.ID, &c.Label, &c.Note, &c.TargetGroup, &c.TokenEnc, &c.TokenHash,
		&c.Redirect, &c.Status, &created, &updated)
	if err != nil {
		return BreakGlassCode{}, err
	}
	c.CreatedAt = time.Unix(created, 0)
	c.UpdatedAt = time.Unix(updated, 0)
	return c, nil
}

// CreateBreakGlassCode inserts a code and returns its id.
func (s *SQLite) CreateBreakGlassCode(ctx context.Context, c BreakGlassCode) (int64, error) {
	now := time.Now().Unix()
	if c.Status == "" {
		c.Status = BreakGlassActive
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO break_glass_codes
		 (label, note, target_group, token_enc, token_hash, redirect, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Label, c.Note, c.TargetGroup, c.TokenEnc, c.TokenHash, c.Redirect, c.Status, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListBreakGlassCodes returns all codes, newest first.
func (s *SQLite) ListBreakGlassCodes(ctx context.Context) ([]BreakGlassCode, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+bgColumns+` FROM break_glass_codes ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BreakGlassCode
	for rows.Next() {
		c, err := scanBreakGlass(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetBreakGlassCode returns a code by id.
func (s *SQLite) GetBreakGlassCode(ctx context.Context, id int64) (BreakGlassCode, bool, error) {
	c, err := scanBreakGlass(s.db.QueryRowContext(ctx,
		`SELECT `+bgColumns+` FROM break_glass_codes WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return BreakGlassCode{}, false, nil
	}
	if err != nil {
		return BreakGlassCode{}, false, err
	}
	return c, true, nil
}

// LookupBreakGlassByTokenHash finds a code by its token hash, any status.
func (s *SQLite) LookupBreakGlassByTokenHash(ctx context.Context, tokenHash string) (BreakGlassCode, bool, error) {
	c, err := scanBreakGlass(s.db.QueryRowContext(ctx,
		`SELECT `+bgColumns+` FROM break_glass_codes WHERE token_hash = ?`, tokenHash))
	if err == sql.ErrNoRows {
		return BreakGlassCode{}, false, nil
	}
	if err != nil {
		return BreakGlassCode{}, false, err
	}
	return c, true, nil
}

// RevokeBreakGlassCode marks a code revoked.
func (s *SQLite) RevokeBreakGlassCode(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE break_glass_codes SET status = ?, updated_at = ? WHERE id = ?`,
		BreakGlassRevoked, time.Now().Unix(), id)
	return err
}

// RemintBreakGlassCode replaces a code's token and reactivates it.
func (s *SQLite) RemintBreakGlassCode(ctx context.Context, id int64, newTokenEnc, newTokenHash string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE break_glass_codes SET token_enc = ?, token_hash = ?, status = ?, updated_at = ? WHERE id = ?`,
		newTokenEnc, newTokenHash, BreakGlassActive, time.Now().Unix(), id)
	return err
}

// RecordBreakGlassEvent appends an audit event.
func (s *SQLite) RecordBreakGlassEvent(ctx context.Context, e BreakGlassEvent) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO break_glass_events (code_id, label, client_ip, user_agent, outcome, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		e.CodeID, e.Label, e.ClientIP, e.UserAgent, e.Outcome, time.Now().Unix())
	return err
}

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
	_, err := s.db.ExecContext(ctx, `DELETE FROM admin_events WHERE created_at < ?`, cut)
	return err
}

// GetCodeBranding returns a code's branding overrides (empty = inherit global).
func (s *SQLite) GetCodeBranding(ctx context.Context, codeID int64) (Branding, error) {
	var b Branding
	err := s.db.QueryRowContext(ctx,
		`SELECT ov_title, ov_body, ov_instructions, ov_header_color, ov_accent_color,
		        ov_bar1_color, ov_bar2_color, ov_bar3_color, ov_logo, ov_logo_type, ov_glyph, ov_glyph_type
		 FROM break_glass_codes WHERE id = ?`, codeID).
		Scan(&b.Title, &b.Body, &b.Instructions, &b.HeaderColor, &b.AccentColor,
			&b.Bar1Color, &b.Bar2Color, &b.Bar3Color, &b.Logo, &b.LogoType, &b.Glyph, &b.GlyphType)
	if err == sql.ErrNoRows {
		return Branding{}, nil
	}
	if err != nil {
		return Branding{}, err
	}
	return b, nil
}

// SaveCodeBrandingMeta upserts a code's text + colour overrides.
func (s *SQLite) SaveCodeBrandingMeta(ctx context.Context, codeID int64, title, body, instructions, header, accent, bar1, bar2, bar3 string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE break_glass_codes SET
			ov_title = ?, ov_body = ?, ov_instructions = ?,
			ov_header_color = ?, ov_accent_color = ?, ov_bar1_color = ?, ov_bar2_color = ?, ov_bar3_color = ?,
			updated_at = ?
		 WHERE id = ?`,
		title, body, instructions, header, accent, bar1, bar2, bar3, time.Now().Unix(), codeID)
	return err
}

// SetCodeBrandingImage stores a code's override logo or glyph.
func (s *SQLite) SetCodeBrandingImage(ctx context.Context, codeID int64, which BrandingImage, data []byte, mime string) error {
	blobCol, typeCol := codeBrandingImageColumns(which)
	if blobCol == "" {
		return fmt.Errorf("store: unknown branding image %q", which)
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE break_glass_codes SET `+blobCol+` = ?, `+typeCol+` = ?, updated_at = ? WHERE id = ?`,
		data, mime, time.Now().Unix(), codeID)
	return err
}

// ClearCodeBrandingImage removes a code's override logo or glyph.
func (s *SQLite) ClearCodeBrandingImage(ctx context.Context, codeID int64, which BrandingImage) error {
	blobCol, typeCol := codeBrandingImageColumns(which)
	if blobCol == "" {
		return fmt.Errorf("store: unknown branding image %q", which)
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE break_glass_codes SET `+blobCol+` = NULL, `+typeCol+` = '', updated_at = ? WHERE id = ?`,
		time.Now().Unix(), codeID)
	return err
}

func codeBrandingImageColumns(which BrandingImage) (blobCol, typeCol string) {
	switch which {
	case BrandingLogo:
		return "ov_logo", "ov_logo_type"
	case BrandingGlyph:
		return "ov_glyph", "ov_glyph_type"
	default:
		return "", ""
	}
}

// ListBreakGlassEvents returns events, newest first. codeID 0 lists all codes.
func (s *SQLite) ListBreakGlassEvents(ctx context.Context, codeID int64, limit, offset int) ([]BreakGlassEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `SELECT id, code_id, label, client_ip, user_agent, outcome, created_at FROM break_glass_events`
	args := []any{}
	if codeID > 0 {
		query += ` WHERE code_id = ?`
		args = append(args, codeID)
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BreakGlassEvent
	for rows.Next() {
		var e BreakGlassEvent
		var created int64
		if err := rows.Scan(&e.ID, &e.CodeID, &e.Label, &e.ClientIP, &e.UserAgent, &e.Outcome, &created); err != nil {
			return nil, err
		}
		e.CreatedAt = time.Unix(created, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- PDF branding (singleton row id=1) ---

// GetBranding returns the stored branding row, if any.
func (s *SQLite) GetBranding(ctx context.Context) (Branding, bool, error) {
	var b Branding
	var updated int64
	err := s.db.QueryRowContext(ctx,
		`SELECT title, body, instructions, logo, logo_type, glyph, glyph_type,
		        pdf_logo, pdf_logo_type,
		        header_color, accent_color, bar1_color, bar2_color, bar3_color, updated_at
		 FROM pdf_branding WHERE id = 1`).
		Scan(&b.Title, &b.Body, &b.Instructions, &b.Logo, &b.LogoType, &b.Glyph, &b.GlyphType,
			&b.PDFLogo, &b.PDFLogoType,
			&b.HeaderColor, &b.AccentColor, &b.Bar1Color, &b.Bar2Color, &b.Bar3Color, &updated)
	if err == sql.ErrNoRows {
		return Branding{}, false, nil
	}
	if err != nil {
		return Branding{}, false, err
	}
	b.UpdatedAt = time.Unix(updated, 0)
	return b, true, nil
}

// SaveBrandingColors upserts the palette colours, leaving text/images intact.
func (s *SQLite) SaveBrandingColors(ctx context.Context, header, accent, bar1, bar2, bar3 string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO pdf_branding (id, header_color, accent_color, bar1_color, bar2_color, bar3_color, updated_at)
		 VALUES (1, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
			header_color = excluded.header_color, accent_color = excluded.accent_color,
			bar1_color = excluded.bar1_color, bar2_color = excluded.bar2_color,
			bar3_color = excluded.bar3_color, updated_at = excluded.updated_at`,
		header, accent, bar1, bar2, bar3, time.Now().Unix())
	return err
}

// GetAppSettings returns the runtime settings row, if saved.
func (s *SQLite) GetAppSettings(ctx context.Context) (AppSettings, error) {
	var a AppSettings
	var updated int64
	err := s.db.QueryRowContext(ctx,
		`SELECT breakglass_secs, notify_emails, webhook_url, updated_at FROM app_settings WHERE id = 1`).
		Scan(&a.BreakGlassSecs, &a.NotifyEmails, &a.WebhookURL, &updated)
	if err == sql.ErrNoRows {
		return AppSettings{}, nil
	}
	if err != nil {
		return AppSettings{}, err
	}
	a.Exists = true
	a.UpdatedAt = time.Unix(updated, 0)
	return a, nil
}

// SaveAppSettings upserts the runtime settings.
func (s *SQLite) SaveAppSettings(ctx context.Context, breakglassSecs int, notifyEmails, webhookURL string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO app_settings (id, breakglass_secs, notify_emails, webhook_url, updated_at)
		 VALUES (1, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
			breakglass_secs = excluded.breakglass_secs, notify_emails = excluded.notify_emails,
			webhook_url = excluded.webhook_url, updated_at = excluded.updated_at`,
		breakglassSecs, notifyEmails, webhookURL, time.Now().Unix())
	return err
}

// SaveBrandingText upserts the text fields, leaving any stored images intact.
func (s *SQLite) SaveBrandingText(ctx context.Context, title, body, instructions string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO pdf_branding (id, title, body, instructions, updated_at)
		 VALUES (1, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
			title = excluded.title, body = excluded.body,
			instructions = excluded.instructions, updated_at = excluded.updated_at`,
		title, body, instructions, time.Now().Unix())
	return err
}

// SetBrandingImage stores or replaces the logo or glyph image.
func (s *SQLite) SetBrandingImage(ctx context.Context, which BrandingImage, data []byte, mime string) error {
	col, typeCol := brandingImageColumns(which)
	if col == "" {
		return fmt.Errorf("store: unknown branding image %q", which)
	}
	// Ensure the singleton row exists, then update the targeted columns.
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO pdf_branding (id, updated_at) VALUES (1, ?) ON CONFLICT(id) DO NOTHING`,
		time.Now().Unix()); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE pdf_branding SET `+col+` = ?, `+typeCol+` = ?, updated_at = ? WHERE id = 1`,
		data, mime, time.Now().Unix())
	return err
}

// ClearBrandingImage removes the logo or glyph image.
func (s *SQLite) ClearBrandingImage(ctx context.Context, which BrandingImage) error {
	col, typeCol := brandingImageColumns(which)
	if col == "" {
		return fmt.Errorf("store: unknown branding image %q", which)
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE pdf_branding SET `+col+` = NULL, `+typeCol+` = '', updated_at = ? WHERE id = 1`,
		time.Now().Unix())
	return err
}

// brandingImageColumns maps an image slot to its (blob, mime) column names.
// Returning fixed literals keeps these out of user-influenced SQL.
func brandingImageColumns(which BrandingImage) (blobCol, typeCol string) {
	switch which {
	case BrandingLogo:
		return "logo", "logo_type"
	case BrandingGlyph:
		return "glyph", "glyph_type"
	case BrandingPDFLogo:
		return "pdf_logo", "pdf_logo_type"
	default:
		return "", ""
	}
}

// Close closes the database.
func (s *SQLite) Close() error { return s.db.Close() }
