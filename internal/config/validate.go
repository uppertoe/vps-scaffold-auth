// Checks on a loaded Config: secrets, the members listener, and consistency.

package config

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// secrets lists every secret the gateway holds other than the member
// readers' tokens, as written in the environment.
func (c *Config) secrets() []string {
	out := []string{string(c.SessionSecret), c.SMTPPassword, c.ResendAPIKey, c.FeedAlertToken,
		strings.TrimSpace(getenv("DATA_ENCRYPTION_KEY", ""))}
	if len(c.DataEncryptionKey) > 0 {
		out = append(out, hex.EncodeToString(c.DataEncryptionKey), string(c.DataEncryptionKey))
	}
	for _, f := range c.GroupFeeds {
		out = append(out, f.Token)
	}
	return out
}

// membersListen sets the members listener's address and the alias whose
// addresses the public listener refuses. The alias is always set, so an app
// on a members network never reaches the public listener, whatever the
// settings; the listener's address is set whenever MEMBER_READERS or
// MEMBER_READERS_FILE is, even with no usable reader.
//
// With readers in MEMBER_READERS (required), a bad MEMBERS_LISTEN_ADDR stops
// the gateway, as it always has. With readers only from the file, it is
// logged instead: the gateway runs without the members listener and still
// refuses public connections on the alias's addresses.
func (c *Config) membersListen(required bool, logf func(string, ...any)) error {
	addr := strings.TrimSpace(getenv("MEMBERS_LISTEN_ADDR", DefaultMembersListenAddr))
	host, _, splitErr := net.SplitHostPort(addr)
	host = strings.TrimSpace(host)
	if !required && c.MemberReadersFile == "" {
		// No readers, so no members listener; but the gateway may still be on
		// a members network (the scaffold joins it whenever an app has a
		// marker), so the public listener refuses on the alias all the same.
		if host == "" {
			host, _, _ = net.SplitHostPort(DefaultMembersListenAddr)
		}
		c.MembersAlias = host
		return nil
	}
	c.MembersRequired, c.MembersReadersSet = required, true
	var problem error
	switch {
	case listenPort(addr) == 0:
		problem = fmt.Errorf("MEMBERS_LISTEN_ADDR %q needs a port, such as auth-members:8081", addr)
	case sameListener(addr, c.ListenAddr):
		problem = fmt.Errorf("MEMBERS_LISTEN_ADDR must use a different port from LISTEN_ADDR, which Caddy proxies")
	// The host names the gateway's members networks (see internal/netsplit):
	// without one the members listener would answer on every network, and
	// the public listener on the members networks.
	case splitErr != nil || host == "":
		problem = fmt.Errorf("MEMBERS_LISTEN_ADDR %q needs the name the gateway has on its members networks, such as auth-members:8081", addr)
	}
	if problem == nil {
		c.MembersListenAddr, c.MembersAlias = addr, host
		return nil
	}
	if required {
		return problem
	}
	// The renderer gives the gateway the default alias on every members
	// network, so refuse on it when the setting names no host of its own.
	if host == "" {
		host, _, _ = net.SplitHostPort(DefaultMembersListenAddr)
	}
	c.MembersAlias = host
	logf("ERROR members endpoint: %v; the gateway runs without the members listener, and the public listener still refuses connections on the addresses of %q", problem, host)
	return nil
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
	if len(c.AdminEmails) == 0 {
		return fmt.Errorf("ADMIN_EMAILS must be set")
	}
	if c.AppRolesFile == "" {
		return fmt.Errorf("APP_ROLES_FILE must be set: staff, members and guests are decided by the app roles")
	}
	if c.Domain == "" {
		return fmt.Errorf("DOMAIN must be set")
	}
	if c.PublicURL == "" {
		return fmt.Errorf("AUTH_PUBLIC_URL must be set")
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

// RetiredSettings are the settings this release no longer reads. Staff are
// the administrators in ADMIN_EMAILS and the addresses at the domains of the
// domain groups that hold an app role, and guest sign-in is open on the hosts
// of each app whose User role is held by guests. Remove after one release.
var RetiredSettings = []string{"ALLOWED_EMAIL_DOMAINS", "OPEN_REGISTRATION_HOSTS"}
