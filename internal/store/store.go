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
)

// Human-login audit event types, recorded in auth_events.
const (
	AuthEventVerify = "verify" // email OTP code verification attempt
	AuthEventTOTP   = "totp"   // admin second-factor verification attempt
	AuthEventLogin  = "login"  // a session was issued (login succeeded)
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
)

// Administrative action types, recorded in admin_events. Every privileged
// mutation is attributed to the acting admin so emergency-access minting,
// group changes, another admin's 2FA removal, and settings edits leave a
// reviewable trail (previously only break-glass *scans* were audited).
const (
	AdminActionBreakCreate       = "break_glass_create"
	AdminActionBreakRevoke       = "break_glass_revoke"
	AdminActionBreakRemint       = "break_glass_remint"
	AdminActionGroupCreate       = "group_create"
	AdminActionGroupDelete       = "group_delete"
	AdminActionGroupAddMember    = "group_add_member"
	AdminActionGroupRemoveMember = "group_remove_member"
	AdminActionTOTPGenerate      = "totp_generate"
	AdminActionTOTPRemove        = "totp_remove"
	AdminActionSettingsUpdate    = "settings_update"
	AdminActionBrandingUpdate    = "branding_update"
	AdminActionCodeBranding      = "break_glass_branding"
)

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
	CreatedAt time.Time
}

// BreakGlassCode is a physical, scannable emergency-access credential. The raw
// token is never stored; TokenEnc holds its AES-GCM ciphertext (for reprint)
// and TokenHash is the one-way lookup key used at scan time.
type BreakGlassCode struct {
	ID          int64
	Label       string
	Note        string
	TargetGroup string
	TokenEnc    string
	TokenHash   string
	Redirect    string
	Status      string
	CreatedAt   time.Time
	UpdatedAt   time.Time
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
	ConsumeCode(ctx context.Context, email, clientIP, candidateHash string, maxAttempts int, now time.Time) (ConsumeResult, error)

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
	// RecordAppAccess records one app access, deduplicated on
	// (email, host, kind, bucket): a repeat within the same hour is a no-op.
	RecordAppAccess(ctx context.Context, a AppAccess) error
	// ListAppAccess returns app-access rows, newest first, paginated. An empty
	// email lists across all addresses.
	ListAppAccess(ctx context.Context, email string, limit, offset int) ([]AppAccess, error)
	// PruneAuditBefore deletes auth_events and app_access rows older than cutoff,
	// enforcing the retention window.
	PruneAuditBefore(ctx context.Context, cutoff time.Time) error

	// Close releases underlying resources.
	Close() error
}
