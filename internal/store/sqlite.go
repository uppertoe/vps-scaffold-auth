package store

import (
	"context"
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
	if err := s.migrateInvitations(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.migrateSessions(); err != nil {
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
CREATE TABLE IF NOT EXISTS releases (
	name       TEXT PRIMARY KEY,
	first_run  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS declared_apps (
	name       TEXT PRIMARY KEY
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
CREATE TABLE IF NOT EXISTS member_reader_approvals (
	app         TEXT NOT NULL,
	group_name  TEXT NOT NULL,
	approved_by TEXT NOT NULL,
	approved_at INTEGER NOT NULL,
	PRIMARY KEY (app, group_name)
);
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
		// A domain group's organisation name, such as RCH, which a
		// withdrawn card's page names. NULL for none.
		{"org", "TEXT"},
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
	if err := s.ensureColumns("break_glass_codes", []column{
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
	}); err != nil {
		return err
	}
	// Every passkey added before computers could hold one was added on a
	// phone, so existing rows take "phone".
	if err := s.ensureColumns("passkeys", []column{
		{"device", "TEXT NOT NULL DEFAULT 'phone'"},
		{"attachment", "TEXT NOT NULL DEFAULT ''"},
		{"transports", "TEXT NOT NULL DEFAULT ''"},
	}); err != nil {
		return err
	}
	return s.migrateCardDesigns()
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

// ReplaceDeclaredApps records the apps the manifest declares at this start
// and returns those the previous start recorded, in one transaction.
func (s *SQLite) ReplaceDeclaredApps(ctx context.Context, apps []string) (previous []string, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT name FROM declared_apps ORDER BY name`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return nil, err
		}
		previous = append(previous, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM declared_apps`); err != nil {
		return nil, err
	}
	for _, a := range apps {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO declared_apps (name) VALUES (?)`, a); err != nil {
			return nil, err
		}
	}
	return previous, tx.Commit()
}

// FirstRun returns when a release named name first ran on this database,
// recording now if it never has. A later call, by this release or a later one,
// returns the first time and changes nothing.
func (s *SQLite) FirstRun(ctx context.Context, name string, now time.Time) (time.Time, error) {
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO releases (name, first_run) VALUES (?, ?) ON CONFLICT(name) DO NOTHING`, name, now.Unix()); err != nil {
		return time.Time{}, err
	}
	var at int64
	if err := s.db.QueryRowContext(ctx, `SELECT first_run FROM releases WHERE name = ?`, name).Scan(&at); err != nil {
		return time.Time{}, err
	}
	return time.Unix(at, 0), nil
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

// Close closes the database.
func (s *SQLite) Close() error { return s.db.Close() }
