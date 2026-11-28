// Package config loads and validates the auth service configuration from the
// environment. It fails fast on missing or nonsensical values so a
// misconfigured container never boots into a half-working state.
package config

import (
	"fmt"
	"net/netip"
	"net/url"
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
	AdminEmails     []string
	DefaultRedirect string

	// RetiredSet names the retired settings that are still set
	// (ALLOWED_EMAIL_DOMAINS, OPEN_REGISTRATION_HOSTS). Neither is read: the
	// gateway logs a warning for each at start and otherwise ignores it.
	// Remove this after one release.
	RetiredSet []string

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

	// RouteAccessFile is the scaffold-rendered manifest of each site's access
	// rules ("host<TAB>kind<TAB>value", .generated/caddy/route-access.tsv).
	// When set, the admin overview shows a "who can reach what" table.
	RouteAccessFile string

	// AppRolesFile is the scaffold-rendered manifest of each app's roles
	// ("app<TAB>role<TAB>label<TAB>hosts" lines). A guard that names an app
	// (X-Auth-App) is decided by role assignments, and only against the apps
	// and roles listed here. It is required.
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
	// (MEMBER_READERS_FILE and MEMBER_READERS together, tokens in
	// MEMBER_READER_TOKEN_<APP>), served on MembersListenAddr, a port Caddy
	// never proxies. UnusableMemberReaders are apps the file lists without a
	// usable token, whose reads are refused. MembersListenAddr is empty, and
	// there is no endpoint, when neither setting is set or when the address
	// is unusable and the readers come only from the file.
	MemberReadersFile     string
	MemberReaders         []MemberReader
	UnusableMemberReaders []UnusableMemberReader
	MembersListenAddr     string
	// MembersAlias is the host name the gateway has on its members networks
	// (the host in MEMBERS_LISTEN_ADDR). It is set whenever MEMBER_READERS
	// or MEMBER_READERS_FILE is, and the public listener refuses connections
	// on its addresses even when MembersListenAddr is empty. MembersRequired
	// is true when MEMBER_READERS lists an app: a members listener that cannot
	// start then stops the gateway; otherwise it is logged.
	MembersAlias    string
	MembersRequired bool
	// MembersReadersSet is true when MEMBER_READERS or MEMBER_READERS_FILE
	// is set; a members alias that does not resolve is then logged.
	MembersReadersSet bool
	// MemberReadersFileRead is true when MEMBER_READERS_FILE was read whole;
	// MemberReadersFilePairs are every app's groups in it, usable or not;
	// MemberReadersEnvApps are the apps in MEMBER_READERS. The gateway clears
	// an approval at start-up only when the file was read and its pair is
	// not in the file, and never for an app in MEMBER_READERS.
	MemberReadersFileRead  bool
	MemberReadersFilePairs map[string][]string
	MemberReadersEnvApps   []string
	FeedInterval           time.Duration
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

	// PasskeysEnabled offers passkey sign-in on phones, and on a computer
	// whose owner asks for one (PASSKEYS_ENABLED, off by default). It is the
	// only setting that puts a script on the sign-in pages, so a deployment
	// turns it on deliberately.
	PasskeysEnabled bool

	// Break-the-glass QR codes.
	BreakGlassSessionTTL     time.Duration
	BreakGlassRedirect       string // default redirect after a break-glass grant
	BreakGlassWebhookURL     string // optional notification webhook
	BreakGlassWebhookTimeout time.Duration
	BreakGlassNotifyEmails   []string // recipients of use-notifications
	// BreakGlassRefusedGroups (BREAKGLASS_REFUSED_GROUPS, space or comma
	// separated) is deprecated and read for one release only. A list that
	// holds any app role other than User is staff only (staffOnlyLists); the
	// lists named here are staff only as well, and the gateway logs at start
	// that the setting is deprecated.
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

	for _, k := range RetiredSettings {
		if getenv(k, "") != "" {
			c.RetiredSet = append(c.RetiredSet, k)
		}
	}

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
	envReaders, err := parseMemberReaders(getenv("MEMBER_READERS", ""))
	if err != nil {
		return nil, err
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

	// The member readers come after every other secret is known, so that no
	// reader's token can be one of them.
	c.MemberReadersFile = strings.TrimSpace(getenv("MEMBER_READERS_FILE", ""))
	fileGroups, fileOrder, fileRead := readMemberReadersFile(c.MemberReadersFile, logPrintf)
	c.MemberReadersFileRead, c.MemberReadersFilePairs = fileRead, fileGroups
	for _, r := range envReaders {
		c.MemberReadersEnvApps = append(c.MemberReadersEnvApps, r.App)
	}
	c.MemberReaders, c.UnusableMemberReaders = mergeMemberReaders(envReaders, fileGroups, fileOrder, c.secrets(), logPrintf)
	if err := c.membersListen(len(envReaders) > 0, logPrintf); err != nil {
		return nil, err
	}

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}
