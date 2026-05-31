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
);`
	_, err := s.db.Exec(schema)
	return err
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

// Close closes the database.
func (s *SQLite) Close() error { return s.db.Close() }
