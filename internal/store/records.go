// The records and outcome constants that the Store interface reads and writes.

package store

import (
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
	// OutcomeRefusedTarget records a scan of a card made for a group before
	// app roles, which opens nothing: nothing was granted. Earlier releases
	// recorded it for a card whose group had become staff only.
	OutcomeRefusedTarget = "refused_target"
	// OutcomeTested records a scan by a signed-in gateway administrator,
	// which grants nothing and marks the card tested.
	OutcomeTested = "tested"
	// OutcomeReplaced records a scan of a card's code from before it was
	// replaced: nothing was granted.
	OutcomeReplaced = "replaced"
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
	// On Your sessions: one other session signed out, and every session but
	// the person's own.
	AuthEventSessionEnd        = "session_end"
	AuthEventSessionsEndOthers = "sessions_end_others"
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
	AdminActionBreakCreate = "break_glass_create"
	AdminActionBreakRevoke = "break_glass_revoke"
	AdminActionBreakRemint = "break_glass_remint"
	// A card that opened a group moved onto an app's user role (target the
	// card's label, detail its former group, the app and the page). The
	// move is no longer offered; the constant names the rows it recorded.
	AdminActionBreakMove          = "break_glass_move"
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
	AdminActionSessionEnd         = "session_end"
	AdminActionSessionsEndAll     = "sessions_end_all"
	AdminActionSettingsUpdate     = "settings_update"
	AdminActionBrandingUpdate     = "branding_update"
	AdminActionCodeBranding       = "break_glass_branding"
	AdminActionPasskeysRemove     = "passkeys_remove"
	// App roles: an app role given to or taken from a holder (target
	// "app:role", detail "kind ref"), and a domain rule added to or removed
	// from a domain group (target the group, detail the domain), and a
	// domain group's organisation name set (target the group, detail the
	// name).
	AdminActionRoleGive          = "role_give"
	AdminActionRoleTake          = "role_take"
	AdminActionGroupDomainAdd    = "group_domain_add"
	AdminActionGroupDomainRemove = "group_domain_remove"
	AdminActionGroupOrg          = "group_org"
	// Card designs: a design created, saved or deleted (target the design's
	// name), and a card given another design.
	AdminActionDesignCreate = "card_design_create"
	AdminActionDesignSave   = "card_design_save"
	AdminActionDesignDelete = "card_design_delete"
	AdminActionCardDesign   = "card_design_change"
	// Member readers: an app from the member-readers file approved to read a
	// group's members, or that approval withdrawn (target the app, detail
	// the group).
	AdminActionMemberReaderApprove  = "member_reader_approve"
	AdminActionMemberReaderWithdraw = "member_reader_withdraw"
	// The gateway cleared an approval at start-up, because the readers file
	// no longer lists the pair.
	AdminActionMemberReaderClear = "member_reader_clear"
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
	// Device is the kind of device the passkey was added on: DevicePhone or
	// DeviceComputer. Passkeys from before computers could hold one read as
	// phones, which every one of them was.
	Device string
	// Attachment and Transports are what the browser reported at
	// registration (authenticatorAttachment; getTransports(), comma-separated).
	Attachment string
	Transports string
	CreatedAt  time.Time
	LastUsedAt time.Time // zero until first used to sign in
}

// The kinds of device a passkey is added on.
const (
	DevicePhone    = "phone"
	DeviceComputer = "computer"
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

// Group is a named, DB-managed group: a domain group or a list, given app
// roles on the Apps pages.
type Group struct {
	Name  string
	Label string
	Kind  string // GroupKindList or GroupKindDomain
	// Org is a domain group's organisation name, such as RCH; empty for
	// none.
	Org       string
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
	ID    int64
	Label string
	Note  string
	// App and Role name the app role the card opens. Both are empty for a
	// card made for a group before app roles: such a card opens nothing,
	// and its scan is refused.
	App       string
	Role      string
	TokenEnc  string
	TokenHash string
	Redirect  string
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
	// DesignID is the card's design (0 for none, which draws the first
	// design). PDFAt is when its PDF was last downloaded and TestedAt when an
	// administrator last scanned it as a test; zero for never. A replaced
	// card starts again with neither.
	DesignID int64
	PDFAt    time.Time
	TestedAt time.Time
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

// MemberReaderApproval is an administrator's approval of one app reading one
// group's members, for a pair listed in the member-readers file.
type MemberReaderApproval struct {
	App, Group string
	ApprovedBy string
	ApprovedAt time.Time
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
