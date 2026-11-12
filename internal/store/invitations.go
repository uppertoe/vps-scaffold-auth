package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Invitations. An invitation names one address and gives one role in one
// app, until a date or permanently, once the person accepts it. Only a hash
// of the link's token is stored: the token itself is in the email alone, and
// a resend replaces the hash, so the old link stops working.

// Administrative actions for invitations (target "app:role", detail the
// address).
const (
	AdminActionInviteCreate   = "invite_create"
	AdminActionInviteResend   = "invite_resend"
	AdminActionInviteWithdraw = "invite_withdraw"
	AdminActionInviteAccept   = "invite_accept"
)

// ErrInvitationClosed refuses accepting an invitation that has been
// withdrawn, accepted or has expired, or that names another address.
var ErrInvitationClosed = errors.New("the invitation is no longer open")

// Invitation is one invitation. Until is the moment the role would end (zero
// for permanently), as in RoleAssignment. SentAt and ExpiresAt change at each
// resend.
type Invitation struct {
	ID          int64
	Email       string
	App         string
	Role        string
	Until       time.Time
	Message     string
	TokenHash   string
	CreatedBy   string
	CreatedAt   time.Time
	SentAt      time.Time
	ExpiresAt   time.Time
	AcceptedAt  time.Time
	WithdrawnAt time.Time
	// Undelivered records that the mailer refused the last email sent for it.
	Undelivered bool
}

// Open reports whether the invitation can still be accepted at now.
func (v Invitation) Open(now time.Time) bool {
	return v.AcceptedAt.IsZero() && v.WithdrawnAt.IsZero() && now.Before(v.ExpiresAt)
}

const invitationSchema = `
CREATE TABLE IF NOT EXISTS invitations (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	email        TEXT NOT NULL,
	app          TEXT NOT NULL,
	role         TEXT NOT NULL,
	until        INTEGER NOT NULL DEFAULT 0,
	message      TEXT NOT NULL DEFAULT '',
	token_hash   TEXT NOT NULL UNIQUE,
	created_by   TEXT NOT NULL DEFAULT '',
	created_at   INTEGER NOT NULL,
	sent_at      INTEGER NOT NULL,
	expires_at   INTEGER NOT NULL,
	accepted_at  INTEGER NOT NULL DEFAULT 0,
	withdrawn_at INTEGER NOT NULL DEFAULT 0,
	undelivered  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_invitations_email ON invitations(email);
-- The reminders sent before a person's role ends: one row for each
-- assignment and end date, so each is sent once, and an extended role is
-- reminded again before its new end.
CREATE TABLE IF NOT EXISTS role_reminders (
	app     TEXT NOT NULL,
	role    TEXT NOT NULL,
	ref     TEXT NOT NULL,
	until   INTEGER NOT NULL,
	sent_at INTEGER NOT NULL,
	PRIMARY KEY (app, role, ref, until)
);`

// migrateInvitations creates the invitation tables.
func (s *SQLite) migrateInvitations() error {
	_, err := s.db.Exec(invitationSchema)
	return err
}

const invitationColumns = `id, email, app, role, until, message, token_hash, created_by, created_at, sent_at, expires_at, accepted_at, withdrawn_at, undelivered`

func scanInvitation(sc interface{ Scan(...any) error }) (Invitation, error) {
	var v Invitation
	var until, created, sent, expires, accepted, withdrawn int64
	var undelivered int
	if err := sc.Scan(&v.ID, &v.Email, &v.App, &v.Role, &until, &v.Message, &v.TokenHash, &v.CreatedBy,
		&created, &sent, &expires, &accepted, &withdrawn, &undelivered); err != nil {
		return Invitation{}, err
	}
	v.Until = timeOrZero(until)
	v.CreatedAt = time.Unix(created, 0)
	v.SentAt = time.Unix(sent, 0)
	v.ExpiresAt = time.Unix(expires, 0)
	v.AcceptedAt = timeOrZero(accepted)
	v.WithdrawnAt = timeOrZero(withdrawn)
	v.Undelivered = undelivered != 0
	return v, nil
}

func timeOrZero(n int64) time.Time {
	if n <= 0 {
		return time.Time{}
	}
	return time.Unix(n, 0)
}

// CreateInvitations inserts invitations with their admin-log records in one
// transaction and returns their IDs in order.
func (s *SQLite) CreateInvitations(ctx context.Context, invs []Invitation, events []AdminEvent) ([]int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit
	ids := make([]int64, 0, len(invs))
	for _, v := range invs {
		v.Email = strings.ToLower(strings.TrimSpace(v.Email))
		if !strings.Contains(v.Email, "@") || v.App == "" || v.Role == "" || v.TokenHash == "" {
			return nil, ErrInvalidAssignment
		}
		res, err := tx.ExecContext(ctx,
			`INSERT INTO invitations (email, app, role, until, message, token_hash, created_by, created_at, sent_at, expires_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			v.Email, v.App, v.Role, unixOrZero(v.Until), v.Message, v.TokenHash, v.CreatedBy,
			v.CreatedAt.Unix(), v.SentAt.Unix(), v.ExpiresAt.Unix())
		if err != nil {
			return nil, err
		}
		id, err := res.LastInsertId()
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	for _, e := range events {
		if err := insertAdminEvent(ctx, tx, e); err != nil {
			return nil, err
		}
	}
	return ids, tx.Commit()
}

// ListInvitations returns every invitation, newest sent first.
func (s *SQLite) ListInvitations(ctx context.Context) ([]Invitation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+invitationColumns+` FROM invitations ORDER BY sent_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Invitation
	for rows.Next() {
		v, err := scanInvitation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLite) oneInvitation(ctx context.Context, where string, arg any) (Invitation, bool, error) {
	v, err := scanInvitation(s.db.QueryRowContext(ctx, `SELECT `+invitationColumns+` FROM invitations WHERE `+where, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return Invitation{}, false, nil
	}
	if err != nil {
		return Invitation{}, false, err
	}
	return v, true, nil
}

// GetInvitation returns one invitation by ID.
func (s *SQLite) GetInvitation(ctx context.Context, id int64) (Invitation, bool, error) {
	return s.oneInvitation(ctx, `id = ?`, id)
}

// InvitationByTokenHash finds the invitation a link names, whatever its state.
func (s *SQLite) InvitationByTokenHash(ctx context.Context, tokenHash string) (Invitation, bool, error) {
	if tokenHash == "" {
		return Invitation{}, false, nil
	}
	return s.oneInvitation(ctx, `token_hash = ?`, tokenHash)
}

// ResendInvitation gives an invitation a new token and a new expiry, and
// clears a failed delivery. The old link stops working. An accepted or
// withdrawn invitation is refused with ErrInvitationClosed.
func (s *SQLite) ResendInvitation(ctx context.Context, id int64, tokenHash string, sentAt, expiresAt time.Time, e AdminEvent) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit
	res, err := tx.ExecContext(ctx,
		`UPDATE invitations SET token_hash = ?, sent_at = ?, expires_at = ?, undelivered = 0
		 WHERE id = ? AND accepted_at = 0 AND withdrawn_at = 0`,
		tokenHash, sentAt.Unix(), expiresAt.Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrInvitationClosed
	}
	if err := insertAdminEvent(ctx, tx, e); err != nil {
		return err
	}
	return tx.Commit()
}

// WithdrawInvitation withdraws an invitation that has not been accepted. It
// returns ErrInvitationClosed for one that has been accepted or withdrawn.
func (s *SQLite) WithdrawInvitation(ctx context.Context, id int64, at time.Time, e AdminEvent) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit
	res, err := tx.ExecContext(ctx,
		`UPDATE invitations SET withdrawn_at = ? WHERE id = ? AND accepted_at = 0 AND withdrawn_at = 0`, at.Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrInvitationClosed
	}
	if err := insertAdminEvent(ctx, tx, e); err != nil {
		return err
	}
	return tx.Commit()
}

// MarkInvitationUndelivered records that the email carrying tokenHash was
// refused by the mailer. A resend since then has a new hash and is left
// alone.
func (s *SQLite) MarkInvitationUndelivered(ctx context.Context, id int64, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE invitations SET undelivered = 1 WHERE id = ? AND token_hash = ?`, id, tokenHash)
	return err
}

// AcceptInvitation accepts an open invitation for email in one transaction:
// it marks the invitation accepted and gives the person the role, recording
// e. A person who already holds the role directly keeps the later of the two
// end dates. The assignment names the inviter as its creator, so a reminder
// before its end can name them. It returns ErrInvitationClosed when the
// invitation is not open at now or names another address.
func (s *SQLite) AcceptInvitation(ctx context.Context, id int64, email string, now time.Time, e AdminEvent) (Invitation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Invitation{}, err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit
	v, err := scanInvitation(tx.QueryRowContext(ctx, `SELECT `+invitationColumns+` FROM invitations WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Invitation{}, ErrInvitationClosed
	}
	if err != nil {
		return Invitation{}, err
	}
	if !v.Open(now) || v.Email != strings.ToLower(strings.TrimSpace(email)) {
		return Invitation{}, ErrInvitationClosed
	}
	until := v.Until
	var had int64
	err = tx.QueryRowContext(ctx,
		`SELECT until FROM role_assignments WHERE app = ? AND role = ? AND kind = ? AND ref = ?`,
		v.App, v.Role, AssignPerson, v.Email).Scan(&had)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return Invitation{}, err
	case had == 0:
		until = time.Time{}
	case !until.IsZero() && had > until.Unix():
		until = time.Unix(had, 0)
	}
	a := RoleAssignment{App: v.App, Role: v.Role, Kind: AssignPerson, Ref: v.Email, Until: until, How: AssignedByInvite, CreatedBy: v.CreatedBy}
	if err := checkAssignment(ctx, tx, &a); err != nil {
		return Invitation{}, err
	}
	if err := insertAssignment(ctx, tx, a); err != nil {
		return Invitation{}, err
	}
	// The How column dates the acceptance, so the date is the acceptance's
	// even when the person held the role before.
	if _, err := tx.ExecContext(ctx,
		`UPDATE role_assignments SET created_at = ? WHERE app = ? AND role = ? AND kind = ? AND ref = ?`,
		now.Unix(), a.App, a.Role, a.Kind, a.Ref); err != nil {
		return Invitation{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE invitations SET accepted_at = ? WHERE id = ?`, now.Unix(), id); err != nil {
		return Invitation{}, err
	}
	if err := insertAdminEvent(ctx, tx, e); err != nil {
		return Invitation{}, err
	}
	if err := tx.Commit(); err != nil {
		return Invitation{}, err
	}
	v.AcceptedAt = time.Unix(now.Unix(), 0)
	return v, nil
}

// MarkReminderSent records that the reminder before an assignment's end has
// been sent, and reports false when it had been already, so each is sent
// once.
func (s *SQLite) MarkReminderSent(ctx context.Context, app, role, ref string, until, at time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO role_reminders (app, role, ref, until, sent_at) VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(app, role, ref, until) DO NOTHING`, app, role, ref, until.Unix(), at.Unix())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
