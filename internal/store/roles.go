package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Group kinds. A list group holds addresses (added by hand, by bulk paste or
// from a feed); a domain group holds email domains and admits everyone at
// them. Existing groups are lists.
const (
	GroupKindList   = "list"
	GroupKindDomain = "domain"
)

// Role assignment kinds: what holds an app role.
const (
	AssignDomainGroup = "domain_group" // Ref is a domain group
	AssignList        = "list"         // Ref is a list group
	AssignPerson      = "person"       // Ref is an email address
	AssignNetwork     = "network"      // Ref is a network named in NETWORK_RANGES
	AssignGuests      = "guests"       // Ref is empty
)

// How a person came to hold a role.
const (
	AssignedByAdmin  = "admin"
	AssignedByInvite = "invite"
)

// RoleUser is the role every app has. A break-glass card may hold it and no
// other.
const RoleUser = "user"

var (
	// ErrGroupKind refuses a domain rule on a list group, a member on a
	// domain group, an assignment naming a group of the wrong kind, or a
	// change of an existing group's kind.
	ErrGroupKind = errors.New("the group is of the wrong kind for this change")
	// ErrInvalidDomain refuses a domain that is not a plain host name.
	ErrInvalidDomain = errors.New("not a valid email domain")
	// ErrWebmailDomain refuses a domain rule for a public webmail provider,
	// which would admit anyone who opens a free account there.
	ErrWebmailDomain = errors.New("a public webmail domain cannot be a domain rule")
	// ErrInvalidAssignment refuses a role assignment whose fields do not fit
	// its kind.
	ErrInvalidAssignment = errors.New("invalid role assignment")
	// ErrNoSuchGroup refuses an assignment or domain rule for a missing group.
	ErrNoSuchGroup = errors.New("no such group")
	// ErrGroupHoldsRoles refuses deleting a group that a role assignment
	// names; the assignments are removed first, on each app's page.
	ErrGroupHoldsRoles = errors.New("the group holds app roles")
	// ErrCardRole refuses giving a card any role but RoleUser.
	ErrCardRole = errors.New("a break-glass card can hold the user role only")
)

// RoleAssignment is one holder of an app role. Until is zero for none and is
// used only by person assignments.
type RoleAssignment struct {
	App       string
	Role      string
	Kind      string
	Ref       string
	Until     time.Time
	How       string
	CreatedBy string
	CreatedAt time.Time
}

// webmailDomains are free email providers. A domain rule for one would open
// a role to anyone who signs up with that provider, so it is refused.
var webmailDomains = map[string]struct{}{
	"gmail.com": {}, "googlemail.com": {}, "outlook.com": {}, "outlook.com.au": {},
	"hotmail.com": {}, "hotmail.com.au": {}, "live.com": {}, "live.com.au": {},
	"msn.com": {}, "yahoo.com": {}, "yahoo.com.au": {}, "ymail.com": {},
	"icloud.com": {}, "me.com": {}, "mac.com": {}, "bigpond.com": {}, "bigpond.net.au": {},
	"proton.me": {}, "protonmail.com": {}, "pm.me": {}, "aol.com": {}, "gmx.com": {},
	"gmx.net": {}, "mail.com": {}, "zoho.com": {}, "yandex.com": {}, "fastmail.com": {},
	"optusnet.com.au": {}, "iinet.net.au": {}, "tpg.com.au": {},
}

// IsWebmailDomain reports whether domain is a public webmail provider.
func IsWebmailDomain(domain string) bool {
	_, ok := webmailDomains[strings.ToLower(strings.TrimSpace(domain))]
	return ok
}

// NormalizeDomain lowercases a domain rule and drops a leading "@". It
// returns ErrInvalidDomain unless the result is a plain dotted host name.
func NormalizeDomain(domain string) (string, error) {
	d := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(domain)), "@")
	if d == "" || len(d) > 253 || !strings.Contains(d, ".") {
		return "", ErrInvalidDomain
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" {
			return "", ErrInvalidDomain
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return "", ErrInvalidDomain
			}
		}
	}
	return d, nil
}

// querier is what both *sql.DB and *sql.Tx offer, so a check can run inside
// or outside a transaction.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// groupKind returns a group's kind; ok is false when the group is missing.
func (s *SQLite) groupKind(ctx context.Context, name string) (string, bool, error) {
	return groupKindIn(ctx, s.db, name)
}

func groupKindIn(ctx context.Context, q querier, name string) (string, bool, error) {
	var kind string
	err := q.QueryRowContext(ctx, `SELECT kind FROM groups WHERE name = ?`, name).Scan(&kind)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return kind, true, nil
}

// refuseDomainGroup returns ErrGroupKind when group is a domain group. A
// missing group is left to the caller's own insert to report.
func (s *SQLite) refuseDomainGroup(ctx context.Context, group string) error {
	kind, ok, err := s.groupKind(ctx, group)
	if err != nil {
		return err
	}
	if ok && kind == GroupKindDomain {
		return ErrGroupKind
	}
	return nil
}

// CreateGroupOfKind inserts a group of the given kind.
func (s *SQLite) CreateGroupOfKind(ctx context.Context, name, label, kind string) error {
	if kind != GroupKindList && kind != GroupKindDomain {
		return ErrGroupKind
	}
	existing, ok, err := s.groupKind(ctx, name)
	if err != nil {
		return err
	}
	if ok && existing != kind {
		return ErrGroupKind
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO groups (name, label, kind, created_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET label = excluded.label`,
		name, label, kind, time.Now().Unix())
	return err
}

// AddGroupDomain adds a domain rule to a domain group (idempotent).
func (s *SQLite) AddGroupDomain(ctx context.Context, group, domain string) error {
	d, err := NormalizeDomain(domain)
	if err != nil {
		return err
	}
	if IsWebmailDomain(d) {
		return ErrWebmailDomain
	}
	kind, ok, err := s.groupKind(ctx, group)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNoSuchGroup
	}
	if kind != GroupKindDomain {
		return ErrGroupKind
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO group_domains (group_name, domain, created_at) VALUES (?, ?, ?)
		 ON CONFLICT(group_name, domain) DO NOTHING`, group, d, time.Now().Unix())
	return err
}

// RemoveGroupDomain removes a domain rule.
func (s *SQLite) RemoveGroupDomain(ctx context.Context, group, domain string) error {
	d := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(domain)), "@")
	_, err := s.db.ExecContext(ctx, `DELETE FROM group_domains WHERE group_name = ? AND domain = ?`, group, d)
	return err
}

// ListGroupDomains returns domain group -> sorted domains.
func (s *SQLite) ListGroupDomains(ctx context.Context) (map[string][]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT group_name, domain FROM group_domains ORDER BY group_name, domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var g, d string
		if err := rows.Scan(&g, &d); err != nil {
			return nil, err
		}
		out[g] = append(out[g], d)
	}
	return out, rows.Err()
}

// AddRoleAssignment inserts or replaces an assignment after checking that
// its fields fit its kind.
func (s *SQLite) AddRoleAssignment(ctx context.Context, a RoleAssignment) error {
	if err := checkAssignment(ctx, s.db, &a); err != nil {
		return err
	}
	return insertAssignment(ctx, s.db, a)
}

// checkAssignment normalises a and checks that its fields fit its kind and
// that a group it names exists and is of the right kind.
func checkAssignment(ctx context.Context, q querier, a *RoleAssignment) error {
	a.App = strings.TrimSpace(a.App)
	a.Role = strings.TrimSpace(a.Role)
	a.Ref = strings.TrimSpace(a.Ref)
	if a.App == "" || a.Role == "" {
		return ErrInvalidAssignment
	}
	switch a.Kind {
	case AssignDomainGroup, AssignList:
		want := GroupKindDomain
		if a.Kind == AssignList {
			want = GroupKindList
		}
		kind, ok, err := groupKindIn(ctx, q, a.Ref)
		if err != nil {
			return err
		}
		if !ok {
			return ErrNoSuchGroup
		}
		if kind != want {
			return ErrGroupKind
		}
		if !a.Until.IsZero() || a.How != "" {
			return ErrInvalidAssignment
		}
	case AssignPerson:
		a.Ref = strings.ToLower(a.Ref)
		if !strings.Contains(a.Ref, "@") {
			return ErrInvalidAssignment
		}
		if a.How != AssignedByAdmin && a.How != AssignedByInvite {
			return ErrInvalidAssignment
		}
	case AssignNetwork:
		if a.Ref == "" || !a.Until.IsZero() || a.How != "" {
			return ErrInvalidAssignment
		}
	case AssignGuests:
		if a.Ref != "" || !a.Until.IsZero() || a.How != "" {
			return ErrInvalidAssignment
		}
	default:
		return ErrInvalidAssignment
	}
	return nil
}

func insertAssignment(ctx context.Context, q querier, a RoleAssignment) error {
	var until int64
	if !a.Until.IsZero() {
		until = a.Until.Unix()
	}
	_, err := q.ExecContext(ctx,
		`INSERT INTO role_assignments (app, role, kind, ref, until, how, created_by, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(app, role, kind, ref) DO UPDATE SET
		   until = excluded.until, how = excluded.how, created_by = excluded.created_by`,
		a.App, a.Role, a.Kind, a.Ref, until, a.How, a.CreatedBy, time.Now().Unix())
	return err
}

// ApplyRoleChanges removes the take assignments and adds the give ones in
// one transaction, recording events with them: every change and its record
// is saved, or none is. Each give is checked as AddRoleAssignment checks it.
func (s *SQLite) ApplyRoleChanges(ctx context.Context, give, take []RoleAssignment, events []AdminEvent) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit
	for _, a := range take {
		if err := removeAssignment(ctx, tx, a.App, a.Role, a.Kind, a.Ref); err != nil {
			return err
		}
	}
	for _, a := range give {
		if err := checkAssignment(ctx, tx, &a); err != nil {
			return err
		}
		if err := insertAssignment(ctx, tx, a); err != nil {
			return err
		}
	}
	for _, e := range events {
		if err := insertAdminEvent(ctx, tx, e); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func insertAdminEvent(ctx context.Context, q querier, e AdminEvent) error {
	_, err := q.ExecContext(ctx,
		`INSERT INTO admin_events (actor, action, target, detail, client_ip, user_agent, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.Actor, e.Action, e.Target, e.Detail, e.ClientIP, e.UserAgent, e.CreatedAt.Unix())
	return err
}

// GroupRoleCount returns how many role assignments name group, as a domain
// group or as a list.
func (s *SQLite) GroupRoleCount(ctx context.Context, group string) (int, error) {
	return groupRoleCountIn(ctx, s.db, group)
}

func groupRoleCountIn(ctx context.Context, q querier, group string) (int, error) {
	var n int
	err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM role_assignments WHERE kind IN (?, ?) AND ref = ?`,
		AssignDomainGroup, AssignList, group).Scan(&n)
	return n, err
}

// RemoveRoleAssignment deletes one assignment.
func (s *SQLite) RemoveRoleAssignment(ctx context.Context, app, role, kind, ref string) error {
	return removeAssignment(ctx, s.db, app, role, kind, ref)
}

func removeAssignment(ctx context.Context, q querier, app, role, kind, ref string) error {
	if kind == AssignPerson {
		ref = strings.ToLower(strings.TrimSpace(ref))
	}
	_, err := q.ExecContext(ctx,
		`DELETE FROM role_assignments WHERE app = ? AND role = ? AND kind = ? AND ref = ?`,
		app, role, kind, ref)
	return err
}

// ListRoleAssignments returns one app's assignments, or all when app is "".
func (s *SQLite) ListRoleAssignments(ctx context.Context, app string) ([]RoleAssignment, error) {
	q := `SELECT app, role, kind, ref, until, how, created_by, created_at FROM role_assignments`
	var args []any
	if app != "" {
		q += ` WHERE app = ?`
		args = append(args, app)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY app, role, kind, ref`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RoleAssignment
	for rows.Next() {
		var a RoleAssignment
		var until, created int64
		if err := rows.Scan(&a.App, &a.Role, &a.Kind, &a.Ref, &until, &a.How, &a.CreatedBy, &created); err != nil {
			return nil, err
		}
		if until > 0 {
			a.Until = time.Unix(until, 0)
		}
		a.CreatedAt = time.Unix(created, 0)
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetBreakGlassRole points a card at an app's user role.
func (s *SQLite) SetBreakGlassRole(ctx context.Context, id int64, app, role string) error {
	if role != RoleUser || strings.TrimSpace(app) == "" {
		return ErrCardRole
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE break_glass_codes SET app = ?, role = ?, updated_at = ? WHERE id = ?`,
		app, role, time.Now().Unix(), id)
	return err
}
