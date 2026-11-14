// Package config loads and validates the auth service configuration from the
// environment. It fails fast on missing or nonsensical values so a
// misconfigured container never boots into a half-working state.
package config

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// RateLimit is a parsed "count/window" rule (e.g. "5/15m").
type RateLimit struct {
	Count  int
	Window time.Duration
}

// Config holds every runtime setting. All fields are derived from environment
// variables documented in .env.example.
type Config struct {
	PublicURL       string
	Domain          string // bare server domain, e.g. example.com (from DOMAIN)
	BrandName       string // product/site name shown in the OTP email (defaults to Domain)
	LoginNotice     string // optional operator-set instruction line on the sign-in page (plain text, auto-escaped)
	OTPEmailSubject string // OTP email subject template; {code}/{brand} are substituted
	AllowedDomains  []string
	AdminEmails     []string
	DefaultRedirect string

	// OpenRegistrationHosts lists the hosts (DOMAIN or a subdomain of it) whose
	// login admits strangers as guests: an OTP-verified address the allow-list
	// does not permit is signed in with kind "guest" when the post-login
	// destination is on one of these hosts. Guests reach only routes whose
	// policy says guests=allow (the protected_open guard), so openness is a
	// property of the one app that needs it rather than of the whole server.
	OpenRegistrationHosts []string

	// AllowApexRedirect permits the bare server domain as a post-login
	// destination. Default off: on a subdomain-only deployment the apex
	// commonly has no TLS certificate, and sending a freshly signed-in user
	// there strands them on a browser security error. Enable when the apex is
	// a real site behind this gateway (e.g. a gated path on a landing page).
	AllowApexRedirect bool

	SessionSecret  []byte
	CookieDomain   string
	CookieInsecure bool // dev only: drop the Secure attribute (no TLS)

	// DisplayTimezone is an IANA name (e.g. "Australia/Melbourne") used to render
	// timestamps in the admin UI; empty means UTC. DisplayLocation is the parsed
	// form, resolved once at load (always non-nil).
	DisplayTimezone string

	// RouteGroupsFile is the path of the scaffold-rendered manifest of the
	// gateway groups each route requires ("group<TAB>host" lines,
	// .generated/caddy/route-groups.tsv). When set, the Groups page lists the
	// groups the routes use, offers to create missing ones, and marks groups no
	// route uses. Empty turns the feature off.
	RouteGroupsFile string

	// RouteAccessFile is the scaffold-rendered manifest of each site's access
	// rules ("host<TAB>kind<TAB>value", .generated/caddy/route-access.tsv).
	// When set, the admin overview shows a "who can reach what" table.
	RouteAccessFile string

	// AppRolesFile is the scaffold-rendered manifest of each app's roles
	// ("app<TAB>role<TAB>label<TAB>hosts" lines). A guard that names an app
	// (X-Auth-App) is decided by role assignments, and only against the apps
	// and roles listed here. Empty turns the app-roles model off.
	AppRolesFile string

	// NetworkRanges are named networks a role can be given to, so a request
	// from inside one is admitted without signing in (NETWORK_RANGES, e.g.
	// "rch=10.0.0.0/8,172.16.0.0/12;mch=10.64.0.0/10"). The client address
	// is the one the gateway already trusts for rate limits, never a header
	// the client controls.
	NetworkRanges map[string][]netip.Prefix
	// NetworkNames are the networks' names as NETWORK_RANGES writes them,
	// by their lower-case names, for the admin pages ("RCH network").
	NetworkNames map[string]string

	// GroupFeeds are groups filled from endpoints (GROUP_FEEDS, with tokens in
	// GROUP_FEED_TOKEN_<GROUP>), fetched every FeedInterval. A failed fetch, an
	// empty list or a held change keeps the current members and alerts
	// FeedAlertURL (optional; an ntfy topic URL suits), as does every change
	// the gateway applies without an administrator. FeedAlertToken, if set, is
	// sent as a bearer token (an ntfy publish token for a write-only user).
	GroupFeeds []GroupFeed
	// MemberReaders are the apps that may ask who is in a group
	// (MEMBER_READERS, tokens in MEMBER_READER_TOKEN_<APP>), served on
	// MembersListenAddr, a port Caddy never proxies. Empty: no endpoint.
	MemberReaders     []MemberReader
	MembersListenAddr string
	FeedInterval      time.Duration
	// FeedAutoApplyAfter, when set (GROUP_FEED_AUTO_APPLY_AFTER), applies a
	// held change on its own once the same change has been held this long,
	// unless an administrator chose to keep the current members. Zero keeps
	// every held change until an administrator accepts it.
	FeedAutoApplyAfter time.Duration
	FeedAlertURL       string
	FeedAlertToken     string
	DisplayLocation    *time.Location

	SessionTTL         time.Duration
	SessionRenew       time.Duration
	SessionRememberTTL time.Duration // "remember me" lifetime (>= SessionTTL)
	// SessionMaxAge is the longest a session lasts from sign-in, however
	// often it renews (SESSION_MAX_AGE). Default: the longer of
	// SESSION_REMEMBER_TTL and seven days.
	SessionMaxAge time.Duration

	// DataEncryptionKey, if set (32 bytes), encrypts at-rest secrets; otherwise
	// the key is derived from SessionSecret. Decoded from a hex env value.
	DataEncryptionKey []byte

	OTPTTL         time.Duration
	OTPLength      int
	OTPMaxAttempts int
	// OTPMaxTotalAttempts caps wrong guesses at one code across every source IP;
	// reaching it burns the code. Defaults to ten times OTPMaxAttempts.
	OTPMaxTotalAttempts int
	// OTPResendCooldown suppresses re-minting a code while a live one is still
	// fresh: a /request within this window of the last send is a no-op (keeps the
	// existing code, sends no email). Must be 0 < cooldown < OTPTTL.
	OTPResendCooldown time.Duration

	EmailBackend string // smtp | resend | log
	EmailFrom    string
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	ResendAPIKey string

	TOTPEnabled bool
	TOTPIssuer  string

	// PasskeysEnabled offers passkey sign-in on phones (PASSKEYS_ENABLED, off
	// by default). It is the only setting that puts a script on the sign-in
	// pages, so a deployment turns it on deliberately.
	PasskeysEnabled bool

	// Break-the-glass QR codes.
	BreakGlassSessionTTL     time.Duration
	BreakGlassRedirect       string // default redirect after a break-glass grant
	BreakGlassWebhookURL     string // optional notification webhook
	BreakGlassWebhookTimeout time.Duration
	BreakGlassNotifyEmails   []string // recipients of use-notifications
	// BreakGlassRefusedGroups (BREAKGLASS_REFUSED_GROUPS, space or comma
	// separated) are groups an application reads as one of its own roles, so
	// a break-glass card may not target them and an address outside the
	// allow-list may not be made a member. The gateway also learns such
	// groups from the route manifests; this list is for deployments without
	// them, or for a role the manifests cannot see.
	BreakGlassRefusedGroups []string
	BreakGlassPDFHeader     string
	BreakGlassPDFBody       string

	// RateLimitPerEmail caps the codes sent to one address from one client IP,
	// so a stranger elsewhere cannot spend the owner's own allowance.
	RateLimitPerEmail RateLimit
	// RateLimitPerEmailCeiling caps the codes sent to one address from all IPs
	// together, bounding how hard a distributed party can flood an inbox.
	RateLimitPerEmailCeiling RateLimit
	// RateLimitPerEmailDaily caps the same over a day, so that the hourly
	// ceiling cannot be spent again every hour by a guesser who is in no
	// hurry. An address signing in from its usual network passes both.
	RateLimitPerEmailDaily RateLimit
	// RateLimitPerIP caps code requests (/request) per client IP.
	RateLimitPerIP RateLimit
	// RateLimitSendsPerIP caps the code emails one client IP can cause, across
	// all addresses, bounding bounce-driven damage to the mail account.
	RateLimitSendsPerIP RateLimit
	// RateLimitWrongCodesPerIP caps WRONG email or authenticator codes per
	// client IP. A correct code costs nothing, so many people signing in
	// behind one hospital NAT do not use it up.
	RateLimitWrongCodesPerIP RateLimit
	// RateLimitBreakGlassPerIP throttles break-glass QR scans per client IP. It is
	// deliberately separate from (and more generous than) RateLimitPerIP: the
	// 128-bit token — not this limit — is the brute-force boundary at /break, so
	// this is only an anti-abuse guard, and emergency access must not be throttled
	// when many staff scan from behind one shared egress IP (e.g. a hospital NAT).
	RateLimitBreakGlassPerIP RateLimit

	// AuditRetention bounds how long login-attempt and app-access audit rows are
	// kept before opportunistic pruning. Zero disables pruning (keep forever).
	AuditRetention time.Duration

	SQLitePath string
	ListenAddr string
}

// Load reads configuration from the environment and validates it.
func Load() (*Config, error) {
	c := &Config{
		PublicURL:       strings.TrimRight(getenv("AUTH_PUBLIC_URL", ""), "/"),
		Domain:          strings.ToLower(getenv("DOMAIN", "")),
		BrandName:       strings.TrimSpace(getenv("BRAND_NAME", "")),
		LoginNotice:     strings.TrimSpace(getenv("LOGIN_NOTICE", "")),
		OTPEmailSubject: strings.TrimSpace(getenv("OTP_EMAIL_SUBJECT", "")),
		AllowedDomains:  splitLowerCSV(getenv("ALLOWED_EMAIL_DOMAINS", "")),
		AdminEmails:     splitLowerCSV(getenv("ADMIN_EMAILS", "")),
		DefaultRedirect: getenv("DEFAULT_REDIRECT", ""),
		SessionSecret:   []byte(getenv("SESSION_SECRET", "")),
		CookieDomain:    getenv("COOKIE_DOMAIN", ""),
		EmailBackend:    strings.ToLower(getenv("EMAIL_BACKEND", "log")),
		EmailFrom:       getenv("EMAIL_FROM", ""),
		SMTPHost:        getenv("SMTP_HOST", ""),
		SMTPUsername:    getenv("SMTP_USERNAME", ""),
		SMTPPassword:    getenv("SMTP_PASSWORD", ""),
		ResendAPIKey:    getenv("RESEND_API_KEY", ""),
		TOTPIssuer:      getenv("TOTP_ISSUER", ""),
		SQLitePath:      getenv("SQLITE_PATH", "/data/auth.db"),
		ListenAddr:      getenv("LISTEN_ADDR", ":8080"),

		BreakGlassRedirect:     getenv("BREAKGLASS_REDIRECT", ""),
		BreakGlassWebhookURL:   getenv("BREAKGLASS_WEBHOOK_URL", ""),
		BreakGlassNotifyEmails: splitLowerCSV(getenv("BREAKGLASS_NOTIFY_EMAILS", "")),
		BreakGlassPDFHeader:    getenv("BREAKGLASS_PDF_HEADER", "Emergency access"),
		BreakGlassPDFBody:      getenv("BREAKGLASS_PDF_BODY", "Scan this code to gain temporary emergency access. Every use is logged and an administrator is notified."),
	}

	c.OpenRegistrationHosts = splitLowerCSV(getenv("OPEN_REGISTRATION_HOSTS", ""))

	var err error
	if c.AllowApexRedirect, err = getbool("ALLOW_APEX_REDIRECT", false); err != nil {
		return nil, err
	}
	if c.CookieInsecure, err = getbool("COOKIE_INSECURE", false); err != nil {
		return nil, err
	}
	if c.TOTPEnabled, err = getbool("TOTP_ENABLED", false); err != nil {
		return nil, err
	}
	if c.PasskeysEnabled, err = getbool("PASSKEYS_ENABLED", false); err != nil {
		return nil, err
	}
	if c.SessionTTL, err = getdur("SESSION_TTL", 2*time.Hour); err != nil {
		return nil, err
	}
	// Must stay below SESSION_TTL, or a session expires before it is ever
	// eligible for sliding renewal (which is also where policy revocation and
	// group recomputation happen).
	if c.SessionRenew, err = getdur("SESSION_RENEW_AFTER", time.Hour); err != nil {
		return nil, err
	}
	if c.SessionRememberTTL, err = getdur("SESSION_REMEMBER_TTL", 24*time.Hour); err != nil {
		return nil, err
	}
	defaultMaxAge := 7 * 24 * time.Hour
	if c.SessionRememberTTL > defaultMaxAge {
		defaultMaxAge = c.SessionRememberTTL
	}
	if c.SessionMaxAge, err = getdur("SESSION_MAX_AGE", defaultMaxAge); err != nil {
		return nil, err
	}
	if c.BreakGlassSessionTTL, err = getdur("BREAKGLASS_SESSION_TTL", 8*time.Hour); err != nil {
		return nil, err
	}
	if c.BreakGlassWebhookTimeout, err = getdur("BREAKGLASS_WEBHOOK_TIMEOUT", 5*time.Second); err != nil {
		return nil, err
	}
	c.DisplayTimezone = strings.TrimSpace(getenv("DISPLAY_TIMEZONE", ""))
	c.RouteGroupsFile = strings.TrimSpace(getenv("ROUTE_GROUPS_FILE", ""))
	c.BreakGlassRefusedGroups = splitLowerList(getenv("BREAKGLASS_REFUSED_GROUPS", ""))
	c.RouteAccessFile = strings.TrimSpace(getenv("ROUTE_ACCESS_FILE", ""))
	c.AppRolesFile = strings.TrimSpace(getenv("APP_ROLES_FILE", ""))
	if c.NetworkRanges, err = ParseNetworkRanges(getenv("NETWORK_RANGES", "")); err != nil {
		return nil, err
	}
	c.NetworkNames = NetworkNamesAsWritten(getenv("NETWORK_RANGES", ""))
	c.DisplayLocation = time.UTC
	if c.DisplayTimezone != "" {
		loc, lerr := time.LoadLocation(c.DisplayTimezone)
		if lerr != nil {
			return nil, fmt.Errorf("DISPLAY_TIMEZONE %q is not a valid IANA timezone (e.g. Australia/Melbourne): %w", c.DisplayTimezone, lerr)
		}
		c.DisplayLocation = loc
	}
	if c.DataEncryptionKey, err = gethexkey("DATA_ENCRYPTION_KEY"); err != nil {
		return nil, err
	}
	if c.OTPTTL, err = getdur("OTP_TTL", 10*time.Minute); err != nil {
		return nil, err
	}
	if c.OTPLength, err = getint("OTP_LENGTH", 6); err != nil {
		return nil, err
	}
	if c.OTPMaxAttempts, err = getint("OTP_MAX_ATTEMPTS", 5); err != nil {
		return nil, err
	}
	if c.OTPMaxTotalAttempts, err = getint("OTP_MAX_TOTAL_ATTEMPTS", 10*c.OTPMaxAttempts); err != nil {
		return nil, err
	}
	if c.OTPResendCooldown, err = getdur("OTP_RESEND_COOLDOWN", 60*time.Second); err != nil {
		return nil, err
	}
	if c.SMTPPort, err = getint("SMTP_PORT", 587); err != nil {
		return nil, err
	}
	if c.RateLimitPerEmail, err = getrate("RATELIMIT_PER_EMAIL", RateLimit{5, 15 * time.Minute}); err != nil {
		return nil, err
	}
	// Per-IP limit on code requests. It is set generously enough not to throttle
	// many distinct users behind one shared egress IP (a hospital or office
	// NAT); wrong codes have their own per-IP limit, RateLimitWrongCodesPerIP.
	if c.RateLimitPerIP, err = getrate("RATELIMIT_PER_IP", RateLimit{60, 15 * time.Minute}); err != nil {
		return nil, err
	}
	if c.RateLimitSendsPerIP, err = getrate("RATELIMIT_SENDS_PER_IP", RateLimit{60, time.Hour}); err != nil {
		return nil, err
	}
	if c.RateLimitPerEmailCeiling, err = getrate("RATELIMIT_PER_EMAIL_CEILING", RateLimit{12, time.Hour}); err != nil {
		return nil, err
	}
	if c.RateLimitPerEmailDaily, err = getrate("RATELIMIT_PER_EMAIL_DAILY", RateLimit{20, 24 * time.Hour}); err != nil {
		return nil, err
	}
	if c.RateLimitWrongCodesPerIP, err = getrate("RATELIMIT_WRONG_CODES_PER_IP", RateLimit{60, 15 * time.Minute}); err != nil {
		return nil, err
	}
	if c.RateLimitBreakGlassPerIP, err = getrate("RATELIMIT_BREAKGLASS_PER_IP", RateLimit{60, 5 * time.Minute}); err != nil {
		return nil, err
	}
	// Default audit retention: one year. Set AUDIT_RETENTION=0 to keep forever.
	if c.AuditRetention, err = getdur("AUDIT_RETENTION", 365*24*time.Hour); err != nil {
		return nil, err
	}

	// Default the cookie domain to the server domain (host-shared across
	// subdomains). Operators should override COOKIE_DOMAIN when DOMAIN is
	// itself a subdomain to avoid over-scoping the session cookie.
	if c.CookieDomain == "" && c.Domain != "" {
		c.CookieDomain = "." + c.Domain
	}

	// The OTP email's wordmark defaults to the server domain when no explicit
	// BRAND_NAME is set.
	if c.BrandName == "" {
		c.BrandName = c.Domain
	}

	// OTP subject defaults to the code-led form ("<code> is your sign-in code"),
	// which keeps the code visible in the inbox/notification preview and offered
	// to one-time-code autofill. A deployment can override it (e.g.
	// OTP_EMAIL_SUBJECT="Login - {brand}") — {code} and {brand} are substituted
	// at send time; a template with no {code} trades that inbox-preview
	// affordance for a branded subject.
	if c.OTPEmailSubject == "" {
		c.OTPEmailSubject = "{code} is your sign-in code"
	}

	// Break-glass notifications and redirect fall back to the existing global
	// settings when not explicitly configured.
	if c.BreakGlassRedirect == "" {
		c.BreakGlassRedirect = c.DefaultRedirect
	}
	if len(c.BreakGlassNotifyEmails) == 0 {
		c.BreakGlassNotifyEmails = c.AdminEmails
	}

	if c.GroupFeeds, err = parseGroupFeeds(getenv("GROUP_FEEDS", ""), c.CookieInsecure); err != nil {
		return nil, err
	}
	if c.MemberReaders, err = parseMemberReaders(getenv("MEMBER_READERS", "")); err != nil {
		return nil, err
	}
	if len(c.MemberReaders) > 0 {
		c.MembersListenAddr = strings.TrimSpace(getenv("MEMBERS_LISTEN_ADDR", DefaultMembersListenAddr))
		if listenPort(c.MembersListenAddr) == 0 {
			return nil, fmt.Errorf("MEMBERS_LISTEN_ADDR %q needs a port, such as auth-members:8081", c.MembersListenAddr)
		}
		if sameListener(c.MembersListenAddr, c.ListenAddr) {
			return nil, fmt.Errorf("MEMBERS_LISTEN_ADDR must use a different port from LISTEN_ADDR, which Caddy proxies")
		}
		// The host names the gateway's members networks (see
		// internal/netsplit): without one the members listener would answer
		// on every network, and the public listener on the members networks.
		if h, _, err := net.SplitHostPort(c.MembersListenAddr); err != nil || strings.TrimSpace(h) == "" {
			return nil, fmt.Errorf("MEMBERS_LISTEN_ADDR %q needs the name the gateway has on its members networks, such as auth-members:8081", c.MembersListenAddr)
		}
	}
	for _, g := range strings.FieldsFunc(getenv("GROUP_FEED_ROTATING", ""), func(r rune) bool { return r == ',' || r == ' ' }) {
		found := false
		for i := range c.GroupFeeds {
			if c.GroupFeeds[i].Group == g {
				c.GroupFeeds[i].Rotating, found = true, true
			}
		}
		if !found {
			return nil, fmt.Errorf("GROUP_FEED_ROTATING names %q, which is not a group in GROUP_FEEDS", g)
		}
	}
	c.FeedInterval = DefaultFeedInterval
	if v := strings.TrimSpace(getenv("GROUP_FEED_INTERVAL", "")); v != "" {
		if c.FeedInterval, err = time.ParseDuration(v); err != nil || c.FeedInterval < 5*time.Minute {
			return nil, fmt.Errorf("GROUP_FEED_INTERVAL must be a duration of at least 5m")
		}
	}
	if v := strings.TrimSpace(getenv("GROUP_FEED_AUTO_APPLY_AFTER", "")); v != "" {
		// At least an hour, so an administrator always has time to see the
		// alert and keep the current members.
		if c.FeedAutoApplyAfter, err = time.ParseDuration(v); err != nil || c.FeedAutoApplyAfter < time.Hour {
			return nil, fmt.Errorf("GROUP_FEED_AUTO_APPLY_AFTER must be a duration of at least 1h")
		}
	}
	c.FeedAlertURL = strings.TrimSpace(getenv("GROUP_FEED_ALERT_URL", ""))
	if c.FeedAlertURL != "" {
		u, perr := url.Parse(c.FeedAlertURL)
		if perr != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && !(c.CookieInsecure && u.Scheme == "http")) {
			return nil, fmt.Errorf("GROUP_FEED_ALERT_URL must be an https URL")
		}
	}
	c.FeedAlertToken = strings.TrimSpace(getenv("GROUP_FEED_ALERT_TOKEN", ""))
	if c.FeedAlertToken != "" && c.FeedAlertURL == "" {
		return nil, fmt.Errorf("GROUP_FEED_ALERT_TOKEN is set but GROUP_FEED_ALERT_URL is not")
	}
	if strings.ContainsAny(c.FeedAlertToken, " \t\r\n") {
		return nil, fmt.Errorf("GROUP_FEED_ALERT_TOKEN must not contain whitespace")
	}

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) validate() error {
	if len(c.SessionSecret) < 32 {
		return fmt.Errorf("SESSION_SECRET must be at least 32 bytes (got %d); generate one with: openssl rand -hex 32", len(c.SessionSecret))
	}
	// Length alone doesn't imply entropy: a 32-char run like "aaaa…a" passes the
	// check above but is trivially guessable. Require a spread of distinct bytes.
	// This catches a repeated or typed string; it is not a test of randomness,
	// and a secret must come from a generator (openssl rand -hex 32).
	// A real secret (openssl rand -hex 32 → 16 distinct hex symbols; base64/raw →
	// far more) clears this easily; only degenerate/repeated strings fail.
	if n := distinctBytes(c.SessionSecret); n < 10 {
		return fmt.Errorf("SESSION_SECRET looks low-entropy (%d distinct bytes); generate one with: openssl rand -hex 32", n)
	}
	if len(c.AllowedDomains) == 0 && len(c.AdminEmails) == 0 {
		return fmt.Errorf("at least one of ALLOWED_EMAIL_DOMAINS or ADMIN_EMAILS must be set")
	}
	if c.Domain == "" {
		return fmt.Errorf("DOMAIN must be set")
	}
	if c.PublicURL == "" {
		return fmt.Errorf("AUTH_PUBLIC_URL must be set")
	}
	// Each open host must be a bare hostname within DOMAIN. The host is compared
	// against the post-login destination, which ValidateRedirect already confines
	// to DOMAIN, so an out-of-domain entry could never match; refusing it at boot
	// catches the typo (a URL, a port, a sibling domain) instead of leaving the
	// operator wondering why registration is still closed.
	for _, h := range c.OpenRegistrationHosts {
		if !validHostname(h) {
			return fmt.Errorf("OPEN_REGISTRATION_HOSTS: %q is not a bare hostname (no scheme, port, path, or wildcard)", h)
		}
		if h != c.Domain && !strings.HasSuffix(h, "."+c.Domain) {
			return fmt.Errorf("OPEN_REGISTRATION_HOSTS: %q is not %s or a subdomain of it", h, c.Domain)
		}
	}
	switch c.EmailBackend {
	case "log":
		// The log backend writes every OTP code to the process log (see
		// email/log.go) -- anyone with log-read access could mint a session.
		// It is dev/CI only, so refuse it unless the operator has also opted
		// into the insecure-cookie dev mode. This keeps the config fail-closed:
		// a production box (Secure cookies) that never set EMAIL_BACKEND, or set
		// it to log by mistake, will not boot leaking codes.
		if !c.CookieInsecure {
			return fmt.Errorf("EMAIL_BACKEND=log writes OTP codes to the process log and is dev-only; set EMAIL_BACKEND=smtp or resend for production (or COOKIE_INSECURE=true for local dev)")
		}
	case "smtp":
		if c.SMTPHost == "" || c.EmailFrom == "" {
			return fmt.Errorf("EMAIL_BACKEND=smtp requires SMTP_HOST and EMAIL_FROM")
		}
	case "resend":
		if c.ResendAPIKey == "" || c.EmailFrom == "" {
			return fmt.Errorf("EMAIL_BACKEND=resend requires RESEND_API_KEY and EMAIL_FROM")
		}
	default:
		return fmt.Errorf("EMAIL_BACKEND must be one of: log, smtp, resend (got %q)", c.EmailBackend)
	}
	// Floor of 6: a 4-digit code (10^4 keyspace) is brute-forceable within the
	// attempt cap + resends over a code's lifetime. 6 digits (10^6) is the default.
	if c.OTPLength < 6 || c.OTPLength > 10 {
		return fmt.Errorf("OTP_LENGTH must be between 6 and 10 (got %d)", c.OTPLength)
	}
	if c.OTPMaxAttempts < 1 {
		return fmt.Errorf("OTP_MAX_ATTEMPTS must be >= 1 (got %d)", c.OTPMaxAttempts)
	}
	if c.OTPMaxTotalAttempts < c.OTPMaxAttempts {
		return fmt.Errorf("OTP_MAX_TOTAL_ATTEMPTS must be >= OTP_MAX_ATTEMPTS (got %d < %d)", c.OTPMaxTotalAttempts, c.OTPMaxAttempts)
	}
	// A cooldown >= TTL means a code always expires before its resend unlocks, so
	// the user could never legitimately resend; a non-positive one disables the
	// no-op guard entirely.
	if c.OTPResendCooldown <= 0 || c.OTPResendCooldown >= c.OTPTTL {
		return fmt.Errorf("OTP_RESEND_COOLDOWN (%s) must be > 0 and < OTP_TTL (%s)", c.OTPResendCooldown, c.OTPTTL)
	}
	if c.TOTPEnabled && c.TOTPIssuer == "" {
		c.TOTPIssuer = c.Domain
	}
	if c.SessionRememberTTL < c.SessionTTL {
		return fmt.Errorf("SESSION_REMEMBER_TTL (%s) must be >= SESSION_TTL (%s)", c.SessionRememberTTL, c.SessionTTL)
	}
	if c.SessionMaxAge < c.SessionRememberTTL {
		return fmt.Errorf("SESSION_MAX_AGE (%s) must be >= SESSION_REMEMBER_TTL (%s), or a remembered session ends before the time it promised", c.SessionMaxAge, c.SessionRememberTTL)
	}
	if c.SessionRenew >= c.SessionTTL {
		return fmt.Errorf("SESSION_RENEW_AFTER (%s) must be less than SESSION_TTL (%s), or a session expires before it can slide-renew", c.SessionRenew, c.SessionTTL)
	}
	if c.BreakGlassWebhookURL != "" {
		u, err := url.Parse(c.BreakGlassWebhookURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("BREAKGLASS_WEBHOOK_URL must be an absolute http(s) URL")
		}
	}
	return nil
}

// validHostname reports whether h is a plain lowercase DNS hostname: dot-
// separated labels of a-z, 0-9 and hyphen, none empty, none starting or ending
// with a hyphen. It rejects anything with a scheme, port, path, or "*".
func validHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// gethexkey decodes an optional hex-encoded key. Empty yields a nil key; a
// non-empty value must decode to exactly 32 bytes (AES-256).
func gethexkey(key string) ([]byte, error) {
	v := getenv(key, "")
	if v == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(strings.TrimSpace(v))
	if err != nil {
		return nil, fmt.Errorf("%s: invalid hex: %w", key, err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("%s: must decode to 32 bytes (got %d)", key, len(b))
	}
	return b, nil
}

func getenv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

// distinctBytes counts the distinct byte values in b — a cheap entropy floor
// that rejects degenerate secrets (a single repeated character, short cycles)
// while comfortably passing any real random secret.
func distinctBytes(b []byte) int {
	var seen [256]bool
	n := 0
	for _, c := range b {
		if !seen[c] {
			seen[c] = true
			n++
		}
	}
	return n
}

// getbool reads a boolean setting. An unset or empty value yields def; a value
// that is not one strconv.ParseBool accepts (true/false, 1/0, t/f, in any
// case) is an error, never the default. TOTP_ENABLED=yes starting the service
// with TOTP silently off is exactly the failure this prevents.
func getbool(key string, def bool) (bool, error) {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return def, fmt.Errorf("%s: %q is not a boolean (use true or false)", key, v)
	}
	return b, nil
}

func getint(key string, def int) (int, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func getdur(key string, def time.Duration) (time.Duration, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}

// getrate parses a "count/window" rule such as "5/15m".
func getrate(key string, def RateLimit) (RateLimit, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	parts := strings.SplitN(strings.TrimSpace(v), "/", 2)
	if len(parts) != 2 {
		return RateLimit{}, fmt.Errorf("%s: want COUNT/WINDOW (e.g. 5/15m), got %q", key, v)
	}
	count, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || count < 1 {
		return RateLimit{}, fmt.Errorf("%s: invalid count %q", key, parts[0])
	}
	win, err := time.ParseDuration(strings.TrimSpace(parts[1]))
	if err != nil || win <= 0 {
		return RateLimit{}, fmt.Errorf("%s: invalid window %q", key, parts[1])
	}
	return RateLimit{Count: count, Window: win}, nil
}

// splitLowerList splits on spaces or commas, trims and lowercases, and drops
// empties; for lists of group names.
func splitLowerList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitLowerCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// NetworkNamesAsWritten returns each network's name in NETWORK_RANGES as
// written, by its lower-case name: "RCH=10.0.0.0/8" names "rch" "RCH". It
// reads only the names; ParseNetworkRanges checks the value.
func NetworkNamesAsWritten(v string) map[string]string {
	out := map[string]string{}
	for _, entry := range strings.Split(v, ";") {
		name, _, ok := strings.Cut(strings.TrimSpace(entry), "=")
		if name = strings.TrimSpace(name); ok && name != "" {
			out[strings.ToLower(name)] = name
		}
	}
	return out
}

// ParseNetworkRanges parses NETWORK_RANGES: networks separated by ";", each
// "name=prefix[,prefix...]". A name is lower-case letters, digits, "-" or
// "_". A bare address is read as a single-host prefix. Empty means none.
func ParseNetworkRanges(v string) (map[string][]netip.Prefix, error) {
	out := map[string][]netip.Prefix{}
	for _, entry := range strings.Split(v, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, list, ok := strings.Cut(entry, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		if !ok || !validNetworkName(name) {
			return nil, fmt.Errorf("NETWORK_RANGES: %q must read name=prefix[,prefix...]", entry)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("NETWORK_RANGES: network %q is listed twice", name)
		}
		var prefixes []netip.Prefix
		for _, raw := range strings.Split(list, ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			pfx, err := netip.ParsePrefix(raw)
			if err != nil {
				addr, aerr := netip.ParseAddr(raw)
				if aerr != nil {
					return nil, fmt.Errorf("NETWORK_RANGES: %q in network %q is not an address or prefix", raw, name)
				}
				pfx = netip.PrefixFrom(addr, addr.BitLen())
			}
			if pfx.Bits() == 0 {
				return nil, fmt.Errorf("NETWORK_RANGES: %q in network %q would admit every address", raw, name)
			}
			prefixes = append(prefixes, pfx.Masked())
		}
		if len(prefixes) == 0 {
			return nil, fmt.Errorf("NETWORK_RANGES: network %q has no prefixes", name)
		}
		out[name] = prefixes
	}
	return out, nil
}

func validNetworkName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
