// Package config loads and validates the auth service configuration from the
// environment. It fails fast on missing or nonsensical values so a
// misconfigured container never boots into a half-working state.
package config

import (
	"encoding/hex"
	"fmt"
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
	AllowedDomains  []string
	AdminEmails     []string
	DefaultRedirect string

	SessionSecret      []byte
	CookieDomain       string
	CookieInsecure     bool // dev only: drop the Secure attribute (no TLS)
	SessionTTL         time.Duration
	SessionRenew       time.Duration
	SessionRememberTTL time.Duration // "remember me" lifetime (>= SessionTTL)

	// DataEncryptionKey, if set (32 bytes), encrypts at-rest secrets; otherwise
	// the key is derived from SessionSecret. Decoded from a hex env value.
	DataEncryptionKey []byte

	OTPTTL         time.Duration
	OTPLength      int
	OTPMaxAttempts int

	EmailBackend string // smtp | resend | log
	EmailFrom    string
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	ResendAPIKey string

	TOTPEnabled bool
	TOTPIssuer  string

	// Break-the-glass QR codes.
	BreakGlassSessionTTL     time.Duration
	BreakGlassRedirect       string // default redirect after a break-glass grant
	BreakGlassWebhookURL     string // optional notification webhook
	BreakGlassWebhookTimeout time.Duration
	BreakGlassNotifyEmails   []string // recipients of use-notifications
	BreakGlassPDFHeader      string
	BreakGlassPDFBody        string

	RateLimitPerEmail RateLimit
	RateLimitPerIP    RateLimit

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
		AllowedDomains:  splitLowerCSV(getenv("ALLOWED_EMAIL_DOMAINS", "")),
		AdminEmails:     splitLowerCSV(getenv("ADMIN_EMAILS", "")),
		DefaultRedirect: getenv("DEFAULT_REDIRECT", ""),
		SessionSecret:   []byte(getenv("SESSION_SECRET", "")),
		CookieDomain:    getenv("COOKIE_DOMAIN", ""),
		CookieInsecure:  getbool("COOKIE_INSECURE", false),
		EmailBackend:    strings.ToLower(getenv("EMAIL_BACKEND", "log")),
		EmailFrom:       getenv("EMAIL_FROM", ""),
		SMTPHost:        getenv("SMTP_HOST", ""),
		SMTPUsername:    getenv("SMTP_USERNAME", ""),
		SMTPPassword:    getenv("SMTP_PASSWORD", ""),
		ResendAPIKey:    getenv("RESEND_API_KEY", ""),
		TOTPEnabled:     getbool("TOTP_ENABLED", false),
		TOTPIssuer:      getenv("TOTP_ISSUER", ""),
		SQLitePath:      getenv("SQLITE_PATH", "/data/auth.db"),
		ListenAddr:      getenv("LISTEN_ADDR", ":8080"),

		BreakGlassRedirect:     getenv("BREAKGLASS_REDIRECT", ""),
		BreakGlassWebhookURL:   getenv("BREAKGLASS_WEBHOOK_URL", ""),
		BreakGlassNotifyEmails: splitLowerCSV(getenv("BREAKGLASS_NOTIFY_EMAILS", "")),
		BreakGlassPDFHeader:    getenv("BREAKGLASS_PDF_HEADER", "Emergency access"),
		BreakGlassPDFBody:      getenv("BREAKGLASS_PDF_BODY", "Scan this code to gain temporary emergency access. Every use is logged and an administrator is notified."),
	}

	var err error
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
	if c.BreakGlassSessionTTL, err = getdur("BREAKGLASS_SESSION_TTL", 8*time.Hour); err != nil {
		return nil, err
	}
	if c.BreakGlassWebhookTimeout, err = getdur("BREAKGLASS_WEBHOOK_TIMEOUT", 5*time.Second); err != nil {
		return nil, err
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
	if c.SMTPPort, err = getint("SMTP_PORT", 587); err != nil {
		return nil, err
	}
	if c.RateLimitPerEmail, err = getrate("RATELIMIT_PER_EMAIL", RateLimit{5, 15 * time.Minute}); err != nil {
		return nil, err
	}
	if c.RateLimitPerIP, err = getrate("RATELIMIT_PER_IP", RateLimit{20, 15 * time.Minute}); err != nil {
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

	// Break-glass notifications and redirect fall back to the existing global
	// settings when not explicitly configured.
	if c.BreakGlassRedirect == "" {
		c.BreakGlassRedirect = c.DefaultRedirect
	}
	if len(c.BreakGlassNotifyEmails) == 0 {
		c.BreakGlassNotifyEmails = c.AdminEmails
	}

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) validate() error {
	if len(c.SessionSecret) < 32 {
		return fmt.Errorf("SESSION_SECRET must be at least 32 bytes (got %d)", len(c.SessionSecret))
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
	switch c.EmailBackend {
	case "log":
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
	if c.OTPLength < 4 || c.OTPLength > 10 {
		return fmt.Errorf("OTP_LENGTH must be between 4 and 10 (got %d)", c.OTPLength)
	}
	if c.OTPMaxAttempts < 1 {
		return fmt.Errorf("OTP_MAX_ATTEMPTS must be >= 1 (got %d)", c.OTPMaxAttempts)
	}
	if c.TOTPEnabled && c.TOTPIssuer == "" {
		c.TOTPIssuer = c.Domain
	}
	if c.SessionRememberTTL < c.SessionTTL {
		return fmt.Errorf("SESSION_REMEMBER_TTL (%s) must be >= SESSION_TTL (%s)", c.SessionRememberTTL, c.SessionTTL)
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

func getbool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return b
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
