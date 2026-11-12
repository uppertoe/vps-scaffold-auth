package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
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
	if err := s.migrateInvitations(); err != nil {
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
-- Wrong-guess counter scoped to (email, client_ip). Keyed per source IP rather
-- than per code so a stranger who knows a registered address cannot burn the
-- victim's live code with wrong guesses: exhausting the cap blocks only that IP,
-- never the code itself. Reset when a fresh code is minted. Client IP is
-- non-spoofable here (rightmost XFF + Caddy overwrites it), so this cannot be
-- rotated cheaply.
CREATE TABLE IF NOT EXISTS code_attempts (
	email      TEXT NOT NULL,
	client_ip  TEXT NOT NULL,
	attempts   INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (email, client_ip)
);
CREATE TABLE IF NOT EXISTS totp_secrets (
	email  TEXT PRIMARY KEY,
	secret TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS totp_failures (
	email        TEXT PRIMARY KEY,
	fail_count   INTEGER NOT NULL DEFAULT 0,
	window_start INTEGER NOT NULL
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
-- A group can include other groups: every member of an included group is a
-- member of the including group too (resolved in GroupsForEmail).
CREATE TABLE IF NOT EXISTS group_includes (
	group_name TEXT NOT NULL REFERENCES groups(name) ON DELETE CASCADE,
	included   TEXT NOT NULL REFERENCES groups(name) ON DELETE CASCADE,
	created_at INTEGER NOT NULL,
	PRIMARY KEY (group_name, included)
);
CREATE INDEX IF NOT EXISTS idx_group_includes_included ON group_includes(included);
-- A domain group admits everyone whose address is at one of its domains. It
-- has no members; a list group (the default) has no domains.
CREATE TABLE IF NOT EXISTS group_domains (
	group_name TEXT NOT NULL REFERENCES groups(name) ON DELETE CASCADE,
	domain     TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	PRIMARY KEY (group_name, domain)
);
-- Who holds each app role. kind is domain_group, list, person, network or
-- guests; ref names the group, the address or the network, and is empty for
-- guests. until (Unix seconds, 0 for none) ends a person's assignment; how
-- records whether an administrator added the person or an invitation did.
-- No foreign key on ref: a group's deletion is refused while it is assigned.
CREATE TABLE IF NOT EXISTS role_assignments (
	app        TEXT NOT NULL,
	role       TEXT NOT NULL,
	kind       TEXT NOT NULL,
	ref        TEXT NOT NULL DEFAULT '',
	until      INTEGER NOT NULL DEFAULT 0,
	how        TEXT NOT NULL DEFAULT '',
	created_by TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	PRIMARY KEY (app, role, kind, ref)
);
CREATE INDEX IF NOT EXISTS idx_role_assignments_ref ON role_assignments(kind, ref);
-- The last sync of each feed-filled group, for the admin pages. Not tied to
-- groups by a foreign key: a feed's state outlives a deleted group row.
CREATE TABLE IF NOT EXISTS group_sync_state (
	group_name   TEXT PRIMARY KEY,
	last_attempt INTEGER NOT NULL,
	last_success INTEGER NOT NULL DEFAULT 0,
	status       TEXT NOT NULL,
	detail       TEXT NOT NULL DEFAULT '',
	pending_add    INTEGER NOT NULL DEFAULT 0,
	pending_remove INTEGER NOT NULL DEFAULT 0,
	-- A held change: the hash of the fetched address set and the addresses
	-- it would add and remove (newline-separated), so an admin reviews and
	-- accepts exactly that change.
	pending_hash        TEXT NOT NULL DEFAULT '',
	pending_add_list    TEXT NOT NULL DEFAULT '',
	pending_remove_list TEXT NOT NULL DEFAULT '',
	-- The member set an administrator last accepted (or the first small
	-- fill), newline-separated: drift from it, however gradual, is held.
	accepted_list TEXT NOT NULL DEFAULT ''
);
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
CREATE INDEX IF NOT EXISTS idx_auth_events_login ON auth_events(email, client_ip, created_at)
	WHERE event_type = 'login' AND outcome = 'ok';
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
CREATE TABLE IF NOT EXISTS used_challenges (
	hash  BLOB PRIMARY KEY,
	until INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS session_cutoffs (
	key        TEXT PRIMARY KEY,
	ended_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS member_reads (
	app        TEXT NOT NULL,
	group_name TEXT NOT NULL,
	source     TEXT NOT NULL,
	bucket     INTEGER NOT NULL,
	created_at INTEGER NOT NULL,
	last_at    INTEGER NOT NULL,
	reads      INTEGER NOT NULL DEFAULT 1,
	UNIQUE (app, group_name, source, bucket)
);
CREATE INDEX IF NOT EXISTS idx_member_reads_last ON member_reads(last_at);
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
CREATE INDEX IF NOT EXISTS idx_admin_events_actor ON admin_events(actor, created_at);
CREATE TABLE IF NOT EXISTS passkeys (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	email         TEXT NOT NULL,
	credential_id BLOB NOT NULL UNIQUE,
	public_key    BLOB NOT NULL,
	user_handle   BLOB NOT NULL,
	sign_count    INTEGER NOT NULL DEFAULT 0,
	label         TEXT NOT NULL DEFAULT '',
	admin_grade   INTEGER NOT NULL DEFAULT 0,
	created_at    INTEGER NOT NULL,
	last_used_at  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_passkeys_email ON passkeys(email);`
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
	if err := s.ensureColumns("groups", []column{
		{"kind", "TEXT NOT NULL DEFAULT 'list'"},
	}); err != nil {
		return err
	}
	if err := s.ensureColumns("group_sync_state", []column{
		{"held_since", "INTEGER NOT NULL DEFAULT 0"},
		{"kept_hash", "TEXT NOT NULL DEFAULT ''"},
		{"added_from", "TEXT NOT NULL DEFAULT ''"},
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
		{"app", "TEXT"},
		{"role", "TEXT"},
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

// SaveCode upserts the code hash for an email and clears the per-IP wrong-guess
// counters, giving the freshly minted code a clean attempt budget.
func (s *SQLite) SaveCode(ctx context.Context, email, codeHash string, expiresAt time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO codes (email, code_hash, expires_at, attempts)
VALUES (?, ?, ?, 0)
ON CONFLICT(email) DO UPDATE SET
	code_hash = excluded.code_hash,
	expires_at = excluded.expires_at,
	attempts = 0`,
		email, codeHash, expiresAt.Unix()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM code_attempts WHERE email = ?`, email); err != nil {
		return err
	}
	return tx.Commit()
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
	if _, err := s.db.ExecContext(ctx, `DELETE FROM codes WHERE expires_at < ?`, now.Unix()); err != nil {
		return err
	}
	// Drop attempt rows whose code no longer exists (expired-without-consume).
	_, err := s.db.ExecContext(ctx, `DELETE FROM code_attempts WHERE email NOT IN (SELECT email FROM codes)`)
	return err
}

// ConsumeCode performs the verify-and-consume in a single transaction. The
// wrong-guess cap is scoped to clientIP: hitting it returns ConsumeTooManyAttempts
// for that IP only and leaves the code intact, so an attacker who set the target
// email cannot delete a code the legitimate user still holds. The code is removed
// only on a correct guess or expiry. clientIP is non-spoofable at this layer
// (rightmost XFF + Caddy overwrites it), so the per-IP scoping cannot be rotated.
func (s *SQLite) ConsumeCode(ctx context.Context, email, clientIP, candidateHash string, maxAttempts, maxTotalAttempts int, now time.Time) (ConsumeResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ConsumeNoCode, err
	}
	defer tx.Rollback()

	var storedHash string
	var expiresAt int64
	var total int
	err = tx.QueryRowContext(ctx,
		`SELECT code_hash, expires_at, attempts FROM codes WHERE email = ?`, email).
		Scan(&storedHash, &expiresAt, &total)
	if err == sql.ErrNoRows {
		return ConsumeNoCode, nil
	}
	if err != nil {
		return ConsumeNoCode, err
	}

	// Remove the code and every IP's attempt budget for it.
	clear := func() error {
		if _, e := tx.ExecContext(ctx, `DELETE FROM codes WHERE email = ?`, email); e != nil {
			return e
		}
		_, e := tx.ExecContext(ctx, `DELETE FROM code_attempts WHERE email = ?`, email)
		return e
	}

	if now.Unix() > expiresAt {
		if err := clear(); err != nil {
			return ConsumeExpired, err
		}
		return ConsumeExpired, tx.Commit()
	}

	// Aggregate budget across every source: the per-IP cap below cannot stop a
	// guesser who rotates addresses, so the code itself carries a total, and
	// reaching it burns the code. The total is set well above the per-IP cap so
	// a single stranger still cannot burn a victim's code on their own.
	if maxTotalAttempts > 0 && total >= maxTotalAttempts {
		if err := clear(); err != nil {
			return ConsumeBurned, err
		}
		return ConsumeBurned, tx.Commit()
	}

	var attempts int
	err = tx.QueryRowContext(ctx,
		`SELECT attempts FROM code_attempts WHERE email = ? AND client_ip = ?`, email, clientIP).
		Scan(&attempts)
	if err != nil && err != sql.ErrNoRows {
		return ConsumeMismatch, err
	}
	if attempts >= maxAttempts {
		// This source has spent its budget. Leave the code for other clients.
		return ConsumeTooManyAttempts, tx.Commit()
	}

	if subtle.ConstantTimeCompare([]byte(storedHash), []byte(candidateHash)) == 1 {
		if err := clear(); err != nil {
			return ConsumeOK, err
		}
		return ConsumeOK, tx.Commit()
	}

	// Wrong code: count this IP's attempt and the code's total. The code stays
	// valid for everyone else unless the total is now spent, in which case it
	// is burned so no further source can keep guessing at it.
	attempts++
	total++
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO code_attempts (email, client_ip, attempts) VALUES (?, ?, ?)
		 ON CONFLICT(email, client_ip) DO UPDATE SET attempts = excluded.attempts`,
		email, clientIP, attempts); err != nil {
		return ConsumeMismatch, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE codes SET attempts = ? WHERE email = ?`, total, email); err != nil {
		return ConsumeMismatch, err
	}
	if maxTotalAttempts > 0 && total >= maxTotalAttempts {
		if err := clear(); err != nil {
			return ConsumeBurned, err
		}
		return ConsumeBurned, tx.Commit()
	}
	if attempts >= maxAttempts {
		return ConsumeTooManyAttempts, tx.Commit()
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

// --- Passkeys ---
//
// AUTOINCREMENT, not a plain rowid: a session records the ID of the passkey
// that started it, and renewal ends the session once that ID is gone. A
// reused ID would let a new passkey keep an old, removed one's sessions alive.

const passkeyCols = `id, email, credential_id, public_key, user_handle, sign_count, label, admin_grade, created_at, last_used_at`

func scanPasskey(sc interface{ Scan(...any) error }) (Passkey, error) {
	var p Passkey
	var grade int
	var created, used int64
	if err := sc.Scan(&p.ID, &p.Email, &p.CredentialID, &p.PublicKey, &p.UserHandle, &p.SignCount, &p.Label, &grade, &created, &used); err != nil {
		return Passkey{}, err
	}
	p.AdminGrade = grade != 0
	p.CreatedAt = time.Unix(created, 0)
	if used != 0 {
		p.LastUsedAt = time.Unix(used, 0)
	}
	return p, nil
}

// CreatePasskey stores a verified passkey.
func (s *SQLite) CreatePasskey(ctx context.Context, p Passkey) (int64, error) {
	grade := 0
	if p.AdminGrade {
		grade = 1
	}
	res, err := s.db.ExecContext(ctx, `
INSERT INTO passkeys (email, credential_id, public_key, user_handle, sign_count, label, admin_grade, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, p.Email, p.CredentialID, p.PublicKey, p.UserHandle, p.SignCount, p.Label, grade, p.CreatedAt.Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *SQLite) onePasskey(ctx context.Context, where string, arg any) (Passkey, bool, error) {
	p, err := scanPasskey(s.db.QueryRowContext(ctx, `SELECT `+passkeyCols+` FROM passkeys WHERE `+where, arg))
	if err == sql.ErrNoRows {
		return Passkey{}, false, nil
	}
	if err != nil {
		return Passkey{}, false, err
	}
	return p, true, nil
}

// PasskeyByCredentialID finds the passkey a sign-in names.
func (s *SQLite) PasskeyByCredentialID(ctx context.Context, credentialID []byte) (Passkey, bool, error) {
	return s.onePasskey(ctx, `credential_id = ?`, credentialID)
}

// GetPasskey returns one passkey by ID.
func (s *SQLite) GetPasskey(ctx context.Context, id int64) (Passkey, bool, error) {
	return s.onePasskey(ctx, `id = ?`, id)
}

// ListPasskeys returns a person's passkeys, newest first.
func (s *SQLite) ListPasskeys(ctx context.Context, email string) ([]Passkey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+passkeyCols+` FROM passkeys WHERE email = ? ORDER BY id DESC`, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Passkey
	for rows.Next() {
		p, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// TouchPasskey records a sign-in.
func (s *SQLite) TouchPasskey(ctx context.Context, id int64, signCount uint32, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ?`, signCount, now.Unix(), id)
	return err
}

// DeletePasskey removes one of email's passkeys.
func (s *SQLite) DeletePasskey(ctx context.Context, email string, id int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM passkeys WHERE id = ? AND email = ?`, id, email)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// DeletePasskeys removes all of email's passkeys.
func (s *SQLite) DeletePasskeys(ctx context.Context, email string) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM passkeys WHERE email = ?`, email)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// TOTPFailureCount returns the number of failed TOTP verifications recorded for
// email within the rolling window ending at now. A stale window (last failure
// older than window) reports 0. This backs the per-account lockout that the
// shared per-IP limiter alone cannot provide.
func (s *SQLite) TOTPFailureCount(ctx context.Context, email string, window time.Duration, now time.Time) (int, error) {
	var count int
	var start int64
	err := s.db.QueryRowContext(ctx,
		`SELECT fail_count, window_start FROM totp_failures WHERE email = ?`, email).Scan(&count, &start)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if now.Sub(time.Unix(start, 0)) >= window {
		return 0, nil
	}
	return count, nil
}

// RecordTOTPFailure registers one failed TOTP verification for email and returns
// the resulting count within the rolling window. When the previous window has
// elapsed the counter restarts at 1.
func (s *SQLite) RecordTOTPFailure(ctx context.Context, email string, window time.Duration, now time.Time) (int, error) {
	var count int
	var start int64
	err := s.db.QueryRowContext(ctx,
		`SELECT fail_count, window_start FROM totp_failures WHERE email = ?`, email).Scan(&count, &start)
	switch {
	case err == sql.ErrNoRows || now.Sub(time.Unix(start, 0)) >= window:
		count, start = 1, now.Unix()
	case err != nil:
		return 0, err
	default:
		count++
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO totp_failures (email, fail_count, window_start) VALUES (?, ?, ?)
		 ON CONFLICT(email) DO UPDATE SET fail_count = excluded.fail_count, window_start = excluded.window_start`,
		email, count, start); err != nil {
		return 0, err
	}
	return count, nil
}

// ReserveTOTPAttempt increments the per-account attempt counter inside one
// transaction and returns the new count. See the Store interface for why the
// reservation precedes the check. The connection pool holds a single
// connection, so concurrent reservations serialise.
func (s *SQLite) ReserveTOTPAttempt(ctx context.Context, email string, window time.Duration, now time.Time) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var count int
	var start int64
	err = tx.QueryRowContext(ctx,
		`SELECT fail_count, window_start FROM totp_failures WHERE email = ?`, email).Scan(&count, &start)
	switch {
	case err == sql.ErrNoRows || now.Sub(time.Unix(start, 0)) >= window:
		count, start = 1, now.Unix()
	case err != nil:
		return 0, err
	default:
		count++
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO totp_failures (email, fail_count, window_start) VALUES (?, ?, ?)
		 ON CONFLICT(email) DO UPDATE SET fail_count = excluded.fail_count, window_start = excluded.window_start`,
		email, count, start); err != nil {
		return 0, err
	}
	return count, tx.Commit()
}

// ClearTOTPFailures resets the failure counter after a successful verification.
func (s *SQLite) ClearTOTPFailures(ctx context.Context, email string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM totp_failures WHERE email = ?`, email)
	return err
}

// --- DB-managed groups ---

// ListGroups returns all groups ordered by name.
func (s *SQLite) ListGroups(ctx context.Context) ([]Group, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, label, kind, created_at FROM groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		var g Group
		var created int64
		if err := rows.Scan(&g.Name, &g.Label, &g.Kind, &created); err != nil {
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

// --- Break-the-glass codes ---

const bgColumns = `id, label, note, target_group, COALESCE(app, ''), COALESCE(role, ''), token_enc, token_hash, redirect, status, created_at, updated_at`

func scanBreakGlass(sc interface{ Scan(...any) error }) (BreakGlassCode, error) {
	var c BreakGlassCode
	var created, updated int64
	err := sc.Scan(&c.ID, &c.Label, &c.Note, &c.TargetGroup, &c.App, &c.Role, &c.TokenEnc, &c.TokenHash,
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
		 (label, note, target_group, app, role, token_enc, token_hash, redirect, status, created_at, updated_at)
		 VALUES (?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), ?, ?, ?, ?, ?, ?)`,
		c.Label, c.Note, c.TargetGroup, c.App, c.Role, c.TokenEnc, c.TokenHash, c.Redirect, c.Status, now, now)
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

// UseChallenge records a passkey challenge, by its hash, as used until until.
// It reports false if the challenge is already recorded and its entry has not
// yet expired. One statement does both, so two posts of the same challenge
// cannot both succeed.
func (s *SQLite) UseChallenge(ctx context.Context, hash []byte, until, now time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO used_challenges (hash, until) VALUES (?, ?)
		 ON CONFLICT(hash) DO UPDATE SET until = excluded.until WHERE used_challenges.until < ?`,
		hash, until.Unix(), now.Unix())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// PruneChallenges deletes expired challenge entries and returns how many
// remain.
func (s *SQLite) PruneChallenges(ctx context.Context, now time.Time) (int, error) {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM used_challenges WHERE until < ?`, now.Unix()); err != nil {
		return 0, err
	}
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM used_challenges`).Scan(&n)
	return n, err
}

// EndSessionsBefore records that every session for key that began at or
// before at has ended. key is a person's address, or "card:<id>" for the
// sessions a break-glass card granted. A later time replaces an earlier one;
// an earlier one never replaces a later one.
func (s *SQLite) EndSessionsBefore(ctx context.Context, key string, at time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO session_cutoffs (key, ended_at) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET ended_at = MAX(ended_at, excluded.ended_at)`, key, at.Unix())
	return err
}

// ListSessionCutoffs returns every recorded cutoff, as Unix seconds by key.
func (s *SQLite) ListSessionCutoffs(ctx context.Context) (map[string]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, ended_at FROM session_cutoffs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var k string
		var at int64
		if err := rows.Scan(&k, &at); err != nil {
			return nil, err
		}
		out[k] = at
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
