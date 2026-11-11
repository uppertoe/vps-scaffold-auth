// Package store persists the only mutable state the service needs: the
// single-use OTP codes (for replay protection) and, optionally, admin TOTP
// secrets. Sessions are stateless signed cookies and never touch the store.
package store

import (
	"context"
	"time"
)

// ConsumeResult is the outcome of attempting to verify an OTP code.
type ConsumeResult int

const (
	// ConsumeOK means the code matched and has been consumed (single-use).
	ConsumeOK ConsumeResult = iota
	// ConsumeNoCode means no outstanding code exists for the email.
	ConsumeNoCode
	// ConsumeExpired means a code existed but has passed its expiry.
	ConsumeExpired
	// ConsumeMismatch means the code did not match (an attempt was counted).
	ConsumeMismatch
	// ConsumeTooManyAttempts means the calling clientIP reached the wrong-guess
	// cap. The code is left intact for other clients (it is not invalidated).
	ConsumeTooManyAttempts
	// ConsumeBurned means the code's total of wrong guesses from all sources
	// is spent, and the code has been destroyed.
	ConsumeBurned
)

// Break-glass code status values.
const (
	BreakGlassActive  = "active"
	BreakGlassRevoked = "revoked"
)

// Break-glass event outcomes.
const (
	OutcomeGranted = "granted"
	OutcomeRevoked = "revoked"
	OutcomeUnknown = "unknown"
	// OutcomeRedirected records a scan by someone who already had a normal
	// session: no emergency session was minted; they were sent to the resource on
	// their own identity (which may still be offered emergency access if denied).
	OutcomeRedirected = "redirected"
	// OutcomeViewed records that a card's address was opened: the page asks
	// for a button press before granting, so a link preview or mail scanner
	// that fetches the address grants nothing.
	OutcomeViewed = "viewed"
	// OutcomeRefusedTarget records a scan of a card whose group has since
	// become an application role or a feed group: nothing was granted.
	OutcomeRefusedTarget = "refused_target"
)

// Human-login audit event types, recorded in auth_events.
const (
	AuthEventVerify = "verify" // email OTP code verification attempt
	AuthEventTOTP   = "totp"   // admin second-factor verification attempt
	AuthEventLogin  = "login"  // a session was issued (login succeeded)
	// Passkeys: a sign-in attempt, a passkey added, a passkey removed by its
	// owner. An administrator's removal is an admin event instead.
	AuthEventPasskey       = "passkey"
	AuthEventPasskeyAdd    = "passkey_add"
	AuthEventPasskeyRemove = "passkey_remove"
	AuthEventSessionsEnd   = "sessions_end" // signed out on every device
)

// Human-login audit event outcomes.
const (
	AuthOutcomeOK        = "ok"
	AuthOutcomeWrongCode = "wrong_code"
	AuthOutcomeExpired   = "expired"
	AuthOutcomeLockedOut = "locked_out"
	AuthOutcomeDenied    = "denied"
	AuthOutcomeReplayed  = "replayed"
	AuthOutcomeNoSecret  = "totp_not_provisioned"
	// Passkey outcomes: no stored passkey has this credential ID; the
	// ceremony or signature did not verify; the signature counter went
	// backwards (a copied key).
	AuthOutcomeUnknownPasskey = "unknown_passkey"
	AuthOutcomeBadPasskey     = "bad_passkey"
	AuthOutcomePasskeyCounter = "passkey_counter"
)

// Administrative action types, recorded in admin_events. Every privileged
// mutation is attributed to the acting admin so emergency-access minting,
// group changes, another admin's 2FA removal, and settings edits leave a
// reviewable trail (previously only break-glass *scans* were audited).
const (
	AdminActionBreakCreate        = "break_glass_create"
	AdminActionBreakRevoke        = "break_glass_revoke"
	AdminActionBreakRemint        = "break_glass_remint"
	AdminActionGroupCreate        = "group_create"
	AdminActionGroupDelete        = "group_delete"
	AdminActionGroupAddMember     = "group_add_member"
	AdminActionGroupRemoveMember  = "group_remove_member"
	AdminActionGroupLabel         = "group_label"
	AdminActionGroupIncludeAdd    = "group_include_add"
	AdminActionGroupIncludeRemove = "group_include_remove"
	AdminActionGroupSync          = "group_sync"
	AdminActionGroupKeep          = "group_keep_members"
	AdminActionTOTPGenerate       = "totp_generate"
	AdminActionTOTPRemove         = "totp_remove"
	AdminActionSessionsEnd        = "sessions_end"
	AdminActionSettingsUpdate     = "settings_update"
	AdminActionBrandingUpdate     = "branding_update"
	AdminActionCodeBranding       = "break_glass_branding"
	AdminActionPasskeysRemove     = "passkeys_remove"
)

// GroupSyncState is the outcome of the last sync of a feed-filled group.
// Status is one of the GroupSync* values; PendingAdd/PendingRemove describe a
// change that was held back for an administrator to accept.
type GroupSyncState struct {
	Group       string
	LastAttempt time.Time
	LastSuccess time.Time
	Status      string
	Detail      string
	// A held change, exactly as it would be applied: the hash of the fetched
	// set, and the addresses it would add and remove.
	PendingHash       string
	PendingAddList    []string
	PendingRemoveList []string
	// AcceptedList is the member set an administrator last accepted (or the
	// first small fill); drift from it beyond a threshold is held.
	AcceptedList []string
	// HeldSince is when the held change (PendingHash) was first held; a
	// different change restarts it. KeptHash is a held change an
	// administrator chose not to have applied automatically.
	HeldSince time.Time
	KeptHash  string
	// AddedFrom maps an address the feed made from another (tom.darling
	// listed for a roster's tom.darling2) to that address, from the last
	// feed answer, so the Groups page can label it.
	AddedFrom map[string]string
}

// Feed sync outcomes.
const (
	GroupSyncOK     = "ok"
	GroupSyncFailed = "failed" // fetch or parse failed; members kept
	GroupSyncEmpty  = "empty"  // the feed returned no addresses; members kept
	GroupSyncHeld   = "held"   // too large a shrink; members kept until accepted
)

// Passkey is one person's registered passkey. PublicKey is the P-256 key as
// SubjectPublicKeyInfo DER: public by nature, so it is stored as it is rather
// than encrypted. UserHandle is the opaque account ID the phone was given at
// registration and returns at every sign-in. AdminGrade records that the
// passkey was added by an administrator who had passed the second factor, so
// a sign-in with it satisfies the admin second factor too; a passkey added
// before its owner became an administrator does not.
type Passkey struct {
	ID           int64
	Email        string
	CredentialID []byte
	PublicKey    []byte
	UserHandle   []byte
	SignCount    uint32
	Label        string
	AdminGrade   bool
	CreatedAt    time.Time
	LastUsedAt   time.Time // zero until first used to sign in
}

// AdminEvent records one administrative mutation for attribution: which admin
// (Actor) did what (Action) to which subject (Target), with optional Detail,
// from which client IP. Actor is the acting admin's validated session email.
type AdminEvent struct {
	ID        int64
	Actor     string
	Action    string // AdminAction* constant
	Target    string // subject of the action (group, code label, email, setting scope)
	Detail    string // optional extra context
	ClientIP  string
	UserAgent string
	CreatedAt time.Time
}

// Group is a named, DB-managed group surfaced via Remote-Groups.
type Group struct {
	Name      string
	Label     string
	Kind      string // GroupKindList or GroupKindDomain
	CreatedAt time.Time
}

// BreakGlassCode is a physical, scannable emergency-access credential. The raw
// token is never stored; TokenEnc holds its AES-GCM ciphertext (for reprint)
// and TokenHash is the one-way lookup key used at scan time.
//
// Deliberately multi-use and NEVER expiring: these are printed QR cards posted
// at clinical locations for emergency access to critical information, so an
// expiring or single-use card could deny care during an emergency. Containment
// of a lost card is by admin *revoke* (Status), not by timeout — do not add
// per-code expiry. (A 2026-07 audit suggested it; rejected on safety grounds.)
type BreakGlassCode struct {
	ID          int64
	Label       string
	Note        string
	TargetGroup string
	// App and Role name the app role the card opens, under the app-roles
	// model. Both are empty for a card that still targets a group.
	App       string
	Role      string
	TokenEnc  string
	TokenHash string
	Redirect  string
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// BreakGlassEvent records one use (or attempted use) of a break-glass code.
// Label is denormalized so the audit trail survives relabel/re-mint.
type BreakGlassEvent struct {
	ID        int64
	CodeID    int64
	Label     string
	ClientIP  string
	UserAgent string
	Outcome   string
	CreatedAt time.Time
}

// AuthEvent records one step of a human login flow — a code verification, a TOTP
// check, or a completed login — for the admin access log. It is the human-login
// analogue of BreakGlassEvent. The email is whatever the user submitted, so a
// failed attempt may carry an arbitrary address.
type AuthEvent struct {
	ID        int64
	Email     string
	EventType string // AuthEvent* constant
	Outcome   string // AuthOutcome* constant
	ClientIP  string
	UserAgent string
	CreatedAt time.Time
}

// AppAccess records that a principal reached a protected app, deduplicated to one
// row per (email, host, kind, hour bucket). It answers "who reached which app,
// when" without persisting every request/path. Bucket is the Unix hour
// (created_at / 3600) and backs the dedup uniqueness constraint; CreatedAt is the
// first sighting within that hour. Kind mirrors the session kind ("" for a normal
// login, KindBreakGlass for emergency access).
type AppAccess struct {
	ID        int64
	Email     string
	Host      string
	Kind      string
	Bucket    int64
	CreatedAt time.Time
}

// AccessFilter narrows the access log. Email matches any address containing
// it (case-insensitive), or only that address when EmailExact is set; Host
// matches one site exactly; empty fields match all. RefusedOnly keeps only
// auth events whose outcome was not "ok".
type AccessFilter struct {
	Email       string
	EmailExact  bool
	Host        string
	Since       time.Time
	RefusedOnly bool
}

// MemberReadSummary is one app's reads of one group's members.
type MemberReadSummary struct {
	App, Group  string
	Source      string // the address the reads came from
	First, Last time.Time
	Reads       int
}

// AccessSummary is one person's use of one site over a period.
type AccessSummary struct {
	Email, Host, Kind string
	First, Last       time.Time
	Hours             int // distinct hours with at least one visit
	Days              int // distinct days with at least one visit
	// Sites and Kinds are set by SummarisePeople: every site the person
	// used, and every kind of session other than an ordinary one.
	Sites, Kinds []string
}

// Branding holds the admin-configurable content rendered on break-glass PDF
// cards. Logo and Glyph are raw image bytes (PNG/JPEG/SVG) with their MIME type;
// either may be empty.
type Branding struct {
	Title        string
	Body         string
	Instructions string
	Logo         []byte
	LogoType     string
	Glyph        []byte
	GlyphType    string
	// PDFLogo is the default logo for break-glass PDF cards (typically a white
	// variant for the dark card header). Falls back to Logo when empty. The plain
	// Logo is the site logo shown on the sign-in pages.
	PDFLogo     []byte
	PDFLogoType string
	// Colours are hex strings like "#003a5c"; empty means use the RCH default.
	HeaderColor string
	AccentColor string
	Bar1Color   string
	Bar2Color   string
	Bar3Color   string
	UpdatedAt   time.Time
}

// AppSettings holds runtime-editable operational settings. Exists is false when
// no admin has saved them yet (callers fall back to env defaults). A zero
// BreakGlassSecs likewise means "use the env default".
type AppSettings struct {
	BreakGlassSecs int
	NotifyEmails   string // CSV
	WebhookURL     string
	Exists         bool
	UpdatedAt      time.Time
}

// BrandingImage names which image slot a branding update targets.
type BrandingImage string

const (
	BrandingLogo    BrandingImage = "logo"
	BrandingGlyph   BrandingImage = "glyph"
	BrandingPDFLogo BrandingImage = "pdflogo"
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
	// non-permitted addresses (closing an allow-list enumeration oracle).
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
	// ErrIncludeCycle refuses a self-include or a cycle.
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
	// DeleteGroup removes a group and (via cascade) its memberships.
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
	// ListRoleAssignments returns the assignments of one app, or of every app
	// when app is empty, ordered by app, role, kind and ref.
	ListRoleAssignments(ctx context.Context, app string) ([]RoleAssignment, error)
	// SetBreakGlassRole points a card at an app role. Only the user role may
	// be given to a card (ErrCardRole), because its holder is not identified.
	SetBreakGlassRole(ctx context.Context, id int64, app, role string) error

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
	// RemintBreakGlassCode replaces a code's token (ciphertext + hash) and marks
	// it active again.
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
	// GroupMembersResolved returns the addresses group admits, through its
	// includes too; exists is false for a group that does not exist.
	GroupMembersResolved(ctx context.Context, group string) (members []string, exists bool, err error)
	// RecordMemberRead notes that an app read a group's members.
	RecordMemberRead(ctx context.Context, app, group, source string, at time.Time) error
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

	// Close releases underlying resources.
	Close() error
}
