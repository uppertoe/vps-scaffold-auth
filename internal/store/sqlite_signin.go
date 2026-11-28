// Sign-in codes, TOTP secrets and failures, passkeys and WebAuthn challenges.

package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"time"
)

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

const passkeyCols = `id, email, credential_id, public_key, user_handle, sign_count, label, admin_grade, device, attachment, transports, created_at, last_used_at`

func scanPasskey(sc interface{ Scan(...any) error }) (Passkey, error) {
	var p Passkey
	var grade int
	var created, used int64
	if err := sc.Scan(&p.ID, &p.Email, &p.CredentialID, &p.PublicKey, &p.UserHandle, &p.SignCount, &p.Label, &grade, &p.Device, &p.Attachment, &p.Transports, &created, &used); err != nil {
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
	device := p.Device
	if device == "" {
		device = DevicePhone
	}
	res, err := s.db.ExecContext(ctx, `
INSERT INTO passkeys (email, credential_id, public_key, user_handle, sign_count, label, admin_grade, device, attachment, transports, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, p.Email, p.CredentialID, p.PublicKey, p.UserHandle, p.SignCount, p.Label, grade, device, p.Attachment, p.Transports, p.CreatedAt.Unix())
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
