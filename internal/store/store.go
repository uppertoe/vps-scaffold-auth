// Package store persists the service's state in SQLite: sign-in codes, the
// signed-in sessions, passkeys, admin authenticator secrets, groups and their
// members, app role assignments, invitations, break-glass cards, card designs
// and the audit trail. The browser's session cookie carries only a random
// token; the session itself is a row here, found by the token's hash.
package store

import (
	"context"
	"time"
)

// Store is the persistence interface. Implementations must be safe for
// concurrent use.
type Store interface {
	// SaveCode stores (replacing any existing code for the email) the hash of a
	// freshly issued OTP code with its expiry, resetting the attempt counter.
	SaveCode(ctx context.Context, email, codeHash string, expiresAt time.Time) error

	// EnsureCode stores codeHash for email only if no code currently exists for
	// it (insert-if-absent), so a live code is never clobbered. Used to persist
	// an unguessable, never-emailed decoy for addresses that are not sent a code,
	// so the /verify-code step is indistinguishable for permitted vs
	// non-permitted addresses (closing an oracle for who may sign in).
	EnsureCode(ctx context.Context, email, codeHash string, expiresAt time.Time) error

	// HasRecentCode reports whether an unconsumed code exists for email whose
	// expiry is later than minExpiry. Callers pass minExpiry = now + OTPTTL -
	// cooldown, i.e. "issued within the cooldown window", to suppress re-minting a
	// still-fresh code. ConsumeCode deletes the code only on a correct guess or
	// expiry (never on wrong guesses), so any surviving row is still usable.
	HasRecentCode(ctx context.Context, email string, minExpiry time.Time) (bool, error)

	// ConsumeCode atomically checks candidateHash against the stored code for
	// email, enforcing expiry and a per-clientIP wrong-guess cap, and consumes the
	// code on a successful match. Exhausting the cap returns ConsumeTooManyAttempts
	// for that clientIP only and leaves the code intact for other clients, so a
	// third party cannot burn a code the legitimate holder still has.
	//
	// maxAttempts caps wrong guesses per (email, client IP); maxTotalAttempts caps
	// wrong guesses for the code as a whole, across every IP. Reaching the total
	// deletes the code: a guesser who rotates source addresses gets at most
	// maxTotalAttempts tries at any one code, and the real owner simply requests
	// another. The per-IP cap is what stops one stranger burning a victim's code
	// cheaply; the total is what stops a distributed guess.
	ConsumeCode(ctx context.Context, email, clientIP, candidateHash string, maxAttempts, maxTotalAttempts int, now time.Time) (ConsumeResult, error)

	// DeleteExpiredCodes removes code rows whose expiry has passed. Called
	// opportunistically so decoys for never-verified addresses cannot accumulate
	// without bound.
	DeleteExpiredCodes(ctx context.Context, now time.Time) error

	// GetTOTPSecret returns the stored TOTP secret for an admin email. The value
	// is opaque to the store (encrypted by the caller).
	GetTOTPSecret(ctx context.Context, email string) (secret string, ok bool, err error)

	// SetTOTPSecret stores (or replaces) the TOTP secret for an admin email.
	SetTOTPSecret(ctx context.Context, email, secret string) error

	// TOTPFailureCount returns failed TOTP verifications for email within the
	// rolling window ending at now (a stale window reports 0).
	TOTPFailureCount(ctx context.Context, email string, window time.Duration, now time.Time) (int, error)
	// RecordTOTPFailure registers one failed TOTP verification and returns the
	// resulting count within the rolling window.
	RecordTOTPFailure(ctx context.Context, email string, window time.Duration, now time.Time) (int, error)
	// ReserveTOTPAttempt counts one TOTP verification attempt BEFORE the code is
	// checked and returns the attempt's ordinal within the rolling window, in a
	// single transaction. Reserving first means the cap bounds how many codes
	// are ever checked, however many submissions arrive at once; a check-then-
	// record sequence would let every concurrent submission pass the check
	// before any failure was recorded. A successful login clears the counter.
	ReserveTOTPAttempt(ctx context.Context, email string, window time.Duration, now time.Time) (int, error)
	// ClearTOTPFailures resets the counter after a success.
	ClearTOTPFailures(ctx context.Context, email string) error
	// DeleteTOTPSecret removes the TOTP secret for an admin email (no-op if
	// absent). Used for admin-mediated 2FA reset/removal.
	DeleteTOTPSecret(ctx context.Context, email string) error

	// --- DB-managed groups ---

	// ListGroups returns all groups, ordered by name.
	ListGroups(ctx context.Context) ([]Group, error)
	// CreateGroup inserts a group (no-op if it already exists).
	CreateGroup(ctx context.Context, name, label string) error
	// AddGroupInclude makes every member of included a member of group too;
	// ErrIncludeCycle refuses a self-include or a cycle, and ErrGroupKind
	// an include where either group is not a list.
	AddGroupInclude(ctx context.Context, group, included string) error
	RemoveGroupInclude(ctx context.Context, group, included string) error
	// ListGroupIncludes returns group -> included groups.
	ListGroupIncludes(ctx context.Context) (map[string][]string, error)
	// AddGroupMembers adds several addresses at once and returns those that
	// were not already members.
	AddGroupMembers(ctx context.Context, group string, emails []string) ([]string, error)
	// ApplyGroupSync adds and removes a feed-filled group's members in one
	// transaction; Set/ListGroupSyncState record each feed's last outcome.
	ApplyGroupSync(ctx context.Context, group string, add, remove []string, events []AdminEvent) error
	SetGroupSyncState(ctx context.Context, st GroupSyncState) error
	ListGroupSyncStates(ctx context.Context) (map[string]GroupSyncState, error)
	// UpdateGroupLabel changes an existing group's display label. It reports
	// whether the group exists.
	UpdateGroupLabel(ctx context.Context, name, label string) (bool, error)
	// SetGroupOrg sets a domain group's organisation name (empty for none).
	// It reports whether the domain group exists.
	SetGroupOrg(ctx context.Context, name, org string) (bool, error)
	// DeleteGroup removes a group and (via cascade) its memberships. A group
	// a role assignment names is refused with ErrGroupHoldsRoles.
	// DeleteGroup also deletes, in the same transaction, every approval for
	// an app to read the group's members (see MemberReaderApproval).
	DeleteGroup(ctx context.Context, name string) error
	// AddGroupMember adds an email to a group (idempotent).
	AddGroupMember(ctx context.Context, group, email string) error
	// RemoveGroupMember removes an email from a group.
	RemoveGroupMember(ctx context.Context, group, email string) error
	// ListGroupMembers returns the member emails of a group, ordered.
	ListGroupMembers(ctx context.Context, group string) ([]string, error)
	// GroupsForEmail returns the group names an email belongs to.
	GroupsForEmail(ctx context.Context, email string) ([]string, error)

	// --- App roles (see roles.go) ---

	// CreateGroupOfKind inserts a group of the given kind (GroupKindList or
	// GroupKindDomain), ignoring a duplicate name as CreateGroup does. It
	// refuses to change the kind of an existing group.
	CreateGroupOfKind(ctx context.Context, name, label, kind string) error
	// AddGroupDomain adds an email domain rule to a domain group. It refuses
	// a list group (ErrGroupKind), a malformed domain (ErrInvalidDomain) and a
	// public webmail domain (ErrWebmailDomain).
	AddGroupDomain(ctx context.Context, group, domain string) error
	RemoveGroupDomain(ctx context.Context, group, domain string) error
	// ListGroupDomains returns domain group -> its domains, sorted.
	ListGroupDomains(ctx context.Context) (map[string][]string, error)
	// AddRoleAssignment gives an app role to a domain group, a list, a person,
	// a network or guests (see RoleAssignment). Adding the same assignment
	// again replaces its until, how and created_by.
	AddRoleAssignment(ctx context.Context, a RoleAssignment) error
	RemoveRoleAssignment(ctx context.Context, app, role, kind, ref string) error
	// ApplyRoleChanges removes take and adds give (each checked as
	// AddRoleAssignment checks it) and records events, in one transaction.
	ApplyRoleChanges(ctx context.Context, give, take []RoleAssignment, events []AdminEvent) error
	// GroupRoleCount returns how many role assignments name a group.
	GroupRoleCount(ctx context.Context, group string) (int, error)
	// ListRoleAssignments returns the assignments of one app, or of every app
	// when app is empty, ordered by app, role, kind and ref.
	ListRoleAssignments(ctx context.Context, app string) ([]RoleAssignment, error)
	// SetBreakGlassRole points a card at an app role. Only the user role may
	// be given to a card (ErrCardRole), because its holder is not identified.
	SetBreakGlassRole(ctx context.Context, id int64, app, role string) error

	// --- Invitations (see invitations.go) ---

	// CreateInvitations inserts invitations and their admin-log records in
	// one transaction, returning their IDs.
	CreateInvitations(ctx context.Context, invs []Invitation, events []AdminEvent) ([]int64, error)
	// ListInvitations returns every invitation, newest sent first.
	ListInvitations(ctx context.Context) ([]Invitation, error)
	GetInvitation(ctx context.Context, id int64) (Invitation, bool, error)
	// InvitationByTokenHash finds the invitation a link names, in any state.
	InvitationByTokenHash(ctx context.Context, tokenHash string) (Invitation, bool, error)
	// ResendInvitation replaces the token and the expiry, so the old link
	// stops working; WithdrawInvitation withdraws. Both refuse an accepted or
	// withdrawn invitation with ErrInvitationClosed, and record e.
	ResendInvitation(ctx context.Context, id int64, tokenHash string, sentAt, expiresAt time.Time, e AdminEvent) error
	WithdrawInvitation(ctx context.Context, id int64, at time.Time, e AdminEvent) error
	// MarkInvitationUndelivered records a refused email, unless the
	// invitation has been resent since.
	MarkInvitationUndelivered(ctx context.Context, id int64, tokenHash string) error
	// MarkInvitationDelivered reopens an invitation whose email carrying
	// tokenHash the mailer has accepted.
	MarkInvitationDelivered(ctx context.Context, id int64, tokenHash string) error
	// AcceptInvitation marks an open invitation for email accepted and gives
	// the person its role, in one transaction with e.
	AcceptInvitation(ctx context.Context, id int64, email string, now time.Time, e AdminEvent) (Invitation, error)
	// MarkReminderSent records the reminder before an assignment's end, and
	// reports false when it had been recorded already.
	MarkReminderSent(ctx context.Context, app, role, ref string, until, at time.Time) (bool, error)

	// --- Break-the-glass codes ---

	// CreateBreakGlassCode inserts a code and returns its id. CreatedAt/UpdatedAt
	// are set by the store.
	CreateBreakGlassCode(ctx context.Context, c BreakGlassCode) (int64, error)
	// ListBreakGlassCodes returns all codes, newest first.
	ListBreakGlassCodes(ctx context.Context) ([]BreakGlassCode, error)
	// GetBreakGlassCode returns a code by id (including its ciphertext).
	GetBreakGlassCode(ctx context.Context, id int64) (BreakGlassCode, bool, error)
	// LookupBreakGlassByTokenHash finds a code by its token hash regardless of
	// status, so the caller can distinguish active / revoked / unknown.
	LookupBreakGlassByTokenHash(ctx context.Context, tokenHash string) (BreakGlassCode, bool, error)
	// RevokeBreakGlassCode marks a code revoked.
	RevokeBreakGlassCode(ctx context.Context, id int64) error
	// RemintBreakGlassCode replaces an active code's token (ciphertext +
	// hash). A withdrawn or unknown code is refused (ErrCardNotActive), so a
	// replacement never brings a withdrawn card back.
	RemintBreakGlassCode(ctx context.Context, id int64, newTokenEnc, newTokenHash string) error
	// RecordBreakGlassEvent appends an audit event. CreatedAt is set by the store.
	RecordBreakGlassEvent(ctx context.Context, e BreakGlassEvent) error

	// --- Per-code PDF branding overrides ---
	// These reuse the Branding struct; an empty field means "inherit the global
	// branding". Images are nil when not overridden.

	// GetCodeBranding returns a code's per-code branding overrides.
	GetCodeBranding(ctx context.Context, codeID int64) (Branding, error)
	// SaveCodeBrandingMeta upserts a code's text + colour overrides (empty =
	// inherit), leaving its override images untouched.
	SaveCodeBrandingMeta(ctx context.Context, codeID int64, title, body, instructions, header, accent, bar1, bar2, bar3 string) error
	// SetCodeBrandingImage stores a code's override logo or glyph.
	SetCodeBrandingImage(ctx context.Context, codeID int64, which BrandingImage, data []byte, mime string) error
	// ClearCodeBrandingImage removes a code's override logo or glyph.
	ClearCodeBrandingImage(ctx context.Context, codeID int64, which BrandingImage) error
	// ListBreakGlassEvents returns events for a code (0 = all codes), newest
	// first, paginated.
	ListBreakGlassEvents(ctx context.Context, codeID int64, limit, offset int) ([]BreakGlassEvent, error)

	// --- PDF branding (singleton) ---

	// GetBranding returns the stored branding row. ok=false means none saved yet
	// (caller falls back to defaults).
	GetBranding(ctx context.Context) (b Branding, ok bool, err error)
	// SaveBrandingText upserts the text fields, leaving images and colours
	// untouched.
	SaveBrandingText(ctx context.Context, title, body, instructions string) error
	// SaveBrandingColors upserts the five palette colours (hex strings), leaving
	// text and images untouched.
	SaveBrandingColors(ctx context.Context, header, accent, bar1, bar2, bar3 string) error
	// SetBrandingImage stores (or replaces) the logo or glyph image.
	SetBrandingImage(ctx context.Context, which BrandingImage, data []byte, mime string) error
	// ClearBrandingImage removes the logo or glyph image.
	ClearBrandingImage(ctx context.Context, which BrandingImage) error

	// --- App settings (singleton) ---

	// GetAppSettings returns the runtime settings row (Exists=false if unsaved).
	GetAppSettings(ctx context.Context) (AppSettings, error)
	// SaveAppSettings upserts the runtime settings.
	SaveAppSettings(ctx context.Context, breakglassSecs int, notifyEmails, webhookURL string) error

	// --- Login & access audit ---

	// RecordAdminEvent appends an administrative-action audit row. CreatedAt is
	// taken from the event.
	RecordAdminEvent(ctx context.Context, e AdminEvent) error
	// ListAdminEvents returns admin-action events, newest first, paginated.
	ListAdminEvents(ctx context.Context, limit, offset int) ([]AdminEvent, error)
	// RecordAuthEvent appends a login-flow audit row. CreatedAt is taken from the
	// supplied value (callers pass the server clock).
	RecordAuthEvent(ctx context.Context, e AuthEvent) error
	// ListAuthEvents returns login-flow events, newest first, paginated. An empty
	// email lists across all addresses.
	ListAuthEvents(ctx context.Context, email string, limit, offset int) ([]AuthEvent, error)
	// HasRecentLogin reports whether email signed in successfully from
	// clientIP at or after since (an AuthEventLogin with AuthOutcomeOK).
	HasRecentLogin(ctx context.Context, email, clientIP string, since time.Time) (bool, error)
	// RecordAppAccess records one app access, deduplicated on
	// (email, host, kind, bucket): a repeat within the same hour is a no-op.
	RecordAppAccess(ctx context.Context, a AppAccess) error
	// ListAppAccess returns app-access rows, newest first, paginated. An empty
	// email lists across all addresses.
	ListAppAccess(ctx context.Context, email string, limit, offset int) ([]AppAccess, error)
	// SummariseAppAccess folds the hourly app-access rows matching f into one
	// row per person, site and kind, newest last visit first. dayOffset (in
	// seconds east of UTC) sets where a day starts when counting days.
	SummariseAppAccess(ctx context.Context, f AccessFilter, dayOffset int) ([]AccessSummary, error)
	// SummarisePeople folds the rows matching f into one row per person,
	// with their sites and kinds of session, newest last visit first.
	SummarisePeople(ctx context.Context, f AccessFilter, dayOffset int) ([]AccessSummary, error)
	// UseChallenge records a passkey challenge as used until until, and
	// reports false if it was already used and has not expired.
	UseChallenge(ctx context.Context, hash []byte, until, now time.Time) (bool, error)
	// PruneChallenges deletes expired challenge entries and returns how many
	// remain.
	PruneChallenges(ctx context.Context, now time.Time) (int, error)
	// EndSessionsBefore ends every session for key (an address, or
	// "card:<id>") that began at or before at.
	EndSessionsBefore(ctx context.Context, key string, at time.Time) error
	// ListSessionCutoffs returns every cutoff, Unix seconds by key.
	ListSessionCutoffs(ctx context.Context) (map[string]int64, error)
	// FirstRun returns when the release name first ran on this database,
	// recording now if it never has.
	FirstRun(ctx context.Context, name string, now time.Time) (time.Time, error)
	// ReplaceDeclaredApps records the apps the manifest declares at this
	// start and returns those the previous start recorded.
	ReplaceDeclaredApps(ctx context.Context, apps []string) (previous []string, err error)
	// GroupKind returns a group's kind (GroupKindList or GroupKindDomain);
	// exists is false for a group that does not exist.
	GroupKind(ctx context.Context, group string) (kind string, exists bool, err error)
	// GroupMembersResolved returns the addresses group admits, through its
	// includes too; exists is false for a group that does not exist.
	GroupMembersResolved(ctx context.Context, group string) (members []string, exists bool, err error)
	// RecordMemberRead notes that an app read a group's members.
	RecordMemberRead(ctx context.Context, app, group, source string, at time.Time) error
	// ListMemberReaderApprovals returns every approved (app, group) pair from
	// the member-readers file, ordered by app and group.
	ListMemberReaderApprovals(ctx context.Context) ([]MemberReaderApproval, error)
	// MemberReaderApproved reports whether an administrator has approved app
	// reading group's members.
	MemberReaderApproved(ctx context.Context, app, group string) (bool, error)
	// ApproveMemberReader records an administrator's approval of app reading
	// group's members. It reports false, and changes nothing, when the pair
	// is already approved or the group does not exist.
	ApproveMemberReader(ctx context.Context, app, group, by string, at time.Time) (bool, error)
	// WithdrawMemberReader removes an approval; it reports false when there
	// was none.
	WithdrawMemberReader(ctx context.Context, app, group string) (bool, error)
	// SummariseMemberReads returns which apps read which groups since since.
	SummariseMemberReads(ctx context.Context, since time.Time) ([]MemberReadSummary, error)
	// AppAccessHosts lists the sites with an app-access row since since.
	AppAccessHosts(ctx context.Context, since time.Time) ([]string, error)
	// ListAuthEventsFiltered returns login-flow events matching f (Host is
	// ignored), newest first, at most limit.
	ListAuthEventsFiltered(ctx context.Context, f AccessFilter, limit int) ([]AuthEvent, error)
	// PruneAuditBefore deletes auth_events and app_access rows older than cutoff,
	// enforcing the retention window.
	PruneAuditBefore(ctx context.Context, cutoff time.Time) error

	// CreatePasskey stores a verified passkey and returns its ID. A credential
	// ID already stored (for anyone) is refused.
	CreatePasskey(ctx context.Context, p Passkey) (int64, error)
	// PasskeyByCredentialID finds the passkey a sign-in names.
	PasskeyByCredentialID(ctx context.Context, credentialID []byte) (Passkey, bool, error)
	// GetPasskey returns one passkey by ID (the renewal check).
	GetPasskey(ctx context.Context, id int64) (Passkey, bool, error)
	// ListPasskeys returns a person's passkeys, newest first.
	ListPasskeys(ctx context.Context, email string) ([]Passkey, error)
	// TouchPasskey records a sign-in: the new counter and the time.
	TouchPasskey(ctx context.Context, id int64, signCount uint32, now time.Time) error
	// DeletePasskey removes one of email's passkeys; false if it was not
	// theirs or did not exist.
	DeletePasskey(ctx context.Context, email string, id int64) (bool, error)
	// DeletePasskeys removes all of email's passkeys and returns how many.
	DeletePasskeys(ctx context.Context, email string) (int, error)

	// Card designs, and each card's design, download and test.
	CardDesignStore

	// The signed-in sessions (sessions.go).
	SessionStore

	// Close releases underlying resources.
	Close() error
}
