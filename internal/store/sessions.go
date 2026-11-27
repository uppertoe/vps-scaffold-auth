package store

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

// Session is one signed-in session. The cookie carries a random token; only
// its SHA-256 hash is stored, so a copy of the database holds no usable
// session.
type Session struct {
	ID     int64
	Hash   []byte
	Email  string
	Kind   string
	Groups string
	// TOTP and Step record the admin second step: whether it was passed in
	// this session, and when it was last passed (Unix seconds).
	TOTP bool
	Step int64
	// Passkey is the passkey the person signed in with, and Card the
	// break-glass card whose scan granted the session; zero otherwise.
	Passkey int64
	Card    int64
	// SignedIn is when the person signed in; Renewed is when the session's
	// groups were last worked out. TTL is the lifetime each renewal grants.
	SignedIn time.Time
	Renewed  time.Time
	TTL      time.Duration
	Expires  time.Time
	LastSeen time.Time
	// Device is a short summary of the browser, such as "Safari on iPhone".
	Device string
}

// SessionStore holds the signed-in sessions.
type SessionStore interface {
	// CreateSession stores a new session and returns its ID.
	CreateSession(ctx context.Context, s Session) (int64, error)
	// CreateMigratedSession stores the session an old-format cookie
	// converts to, and records the conversion until until, in one
	// transaction. It reports false, and stores nothing, if that cookie was
	// converted before.
	CreateMigratedSession(ctx context.Context, s Session, until time.Time) (int64, bool, error)
	// UpdateSession saves a renewal: the kind, groups, admin step, renewal
	// time, lifetime and expiry of session s.ID.
	UpdateSession(ctx context.Context, s Session) error
	// TouchSession records when a session was last seen.
	TouchSession(ctx context.Context, id int64, at time.Time) error
	// DeleteSessions deletes the sessions with these IDs.
	DeleteSessions(ctx context.Context, ids []int64) error
	// ListSessions returns every session that has not expired at now.
	ListSessions(ctx context.Context, now time.Time) ([]Session, error)
	// DeleteExpiredSessions deletes the sessions, and the records of
	// converted cookies, that have expired at now.
	DeleteExpiredSessions(ctx context.Context, now time.Time) error
}

func (s *SQLite) migrateSessions() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS sessions (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	hash         BLOB NOT NULL UNIQUE,
	email        TEXT NOT NULL,
	kind         TEXT NOT NULL DEFAULT '',
	groups       TEXT NOT NULL DEFAULT '',
	totp         INTEGER NOT NULL DEFAULT 0,
	step         INTEGER NOT NULL DEFAULT 0,
	passkey_id   INTEGER NOT NULL DEFAULT 0,
	card_id      INTEGER NOT NULL DEFAULT 0,
	signed_in_at INTEGER NOT NULL,
	renewed_at   INTEGER NOT NULL,
	ttl          INTEGER NOT NULL,
	expires_at   INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL,
	device       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS migrated_sessions (
	hash  BLOB PRIMARY KEY,
	until INTEGER NOT NULL
);`)
	return err
}

// ctxExecer is a database or a transaction.
type ctxExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func insertSession(ctx context.Context, db ctxExecer, x Session) (int64, error) {
	res, err := db.ExecContext(ctx, `INSERT INTO sessions
		(hash, email, kind, groups, totp, step, passkey_id, card_id, signed_in_at, renewed_at, ttl, expires_at, last_seen_at, device)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		x.Hash, x.Email, x.Kind, x.Groups, boolInt(x.TOTP), x.Step, x.Passkey, x.Card,
		x.SignedIn.Unix(), x.Renewed.Unix(), int64(x.TTL.Seconds()), x.Expires.Unix(), x.LastSeen.Unix(), x.Device)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// CreateSession stores a new session and returns its ID.
func (s *SQLite) CreateSession(ctx context.Context, x Session) (int64, error) {
	return insertSession(ctx, s.db, x)
}

// CreateMigratedSession stores a converted old-format cookie's session, once.
func (s *SQLite) CreateMigratedSession(ctx context.Context, x Session, until time.Time) (int64, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `INSERT INTO migrated_sessions (hash, until) VALUES (?, ?) ON CONFLICT(hash) DO NOTHING`, x.Hash, until.Unix())
	if err != nil {
		return 0, false, err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return 0, false, err
	}
	id, err := insertSession(ctx, tx, x)
	if err != nil {
		return 0, false, err
	}
	return id, true, tx.Commit()
}

// UpdateSession saves a renewal of session x.ID.
func (s *SQLite) UpdateSession(ctx context.Context, x Session) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET kind = ?, groups = ?, totp = ?, step = ?, renewed_at = ?, ttl = ?, expires_at = ? WHERE id = ?`,
		x.Kind, x.Groups, boolInt(x.TOTP), x.Step, x.Renewed.Unix(), int64(x.TTL.Seconds()), x.Expires.Unix(), x.ID)
	return err
}

// TouchSession records when a session was last seen.
func (s *SQLite) TouchSession(ctx context.Context, id int64, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ? WHERE id = ?`, at.Unix(), id)
	return err
}

// DeleteSessions deletes the sessions with these IDs, in one statement.
func (s *SQLite) DeleteSessions(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id IN (?`+strings.Repeat(",?", len(ids)-1)+`)`, args...)
	return err
}

// ListSessions returns every session that has not expired at now.
func (s *SQLite) ListSessions(ctx context.Context, now time.Time) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, hash, email, kind, groups, totp, step, passkey_id, card_id,
		signed_in_at, renewed_at, ttl, expires_at, last_seen_at, device
		FROM sessions WHERE expires_at > ? ORDER BY id`, now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var x Session
		var totp int
		var signedIn, renewed, ttl, expires, seen int64
		if err := rows.Scan(&x.ID, &x.Hash, &x.Email, &x.Kind, &x.Groups, &totp, &x.Step, &x.Passkey, &x.Card,
			&signedIn, &renewed, &ttl, &expires, &seen, &x.Device); err != nil {
			return nil, err
		}
		x.TOTP = totp != 0
		x.SignedIn, x.Renewed, x.Expires, x.LastSeen = time.Unix(signedIn, 0), time.Unix(renewed, 0), time.Unix(expires, 0), time.Unix(seen, 0)
		x.TTL = time.Duration(ttl) * time.Second
		out = append(out, x)
	}
	return out, rows.Err()
}

// DeleteExpiredSessions deletes expired sessions and conversion records.
func (s *SQLite) DeleteExpiredSessions(ctx context.Context, now time.Time) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, now.Unix()); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM migrated_sessions WHERE until <= ?`, now.Unix())
	return err
}
