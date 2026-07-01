package config

import "testing"

// setValid sets a minimal valid environment; individual tests override pieces.
func setValid(t *testing.T) {
	t.Helper()
	t.Setenv("AUTH_PUBLIC_URL", "https://auth.example.com")
	t.Setenv("DOMAIN", "example.com")
	t.Setenv("ALLOWED_EMAIL_DOMAINS", "example.com")
	t.Setenv("ADMIN_EMAILS", "admin@example.com")
	t.Setenv("SESSION_SECRET", "0123456789abcdef0123456789abcdef") // 32 bytes
	t.Setenv("EMAIL_BACKEND", "log")
}

func TestLoadValid(t *testing.T) {
	setValid(t)
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.CookieDomain != ".example.com" {
		t.Errorf("CookieDomain default = %q, want .example.com", c.CookieDomain)
	}
	if len(c.AllowedDomains) != 1 || c.AllowedDomains[0] != "example.com" {
		t.Errorf("AllowedDomains = %v", c.AllowedDomains)
	}
	if c.OTPLength != 6 || c.SessionTTL == 0 {
		t.Errorf("defaults not applied: OTPLength=%d SessionTTL=%v", c.OTPLength, c.SessionTTL)
	}
}

func TestLoadShortSecretFails(t *testing.T) {
	setValid(t)
	t.Setenv("SESSION_SECRET", "tooshort")
	if _, err := Load(); err == nil {
		t.Error("expected error for short SESSION_SECRET")
	}
}

func TestLoadNoAudienceFails(t *testing.T) {
	setValid(t)
	t.Setenv("ALLOWED_EMAIL_DOMAINS", "")
	t.Setenv("ADMIN_EMAILS", "")
	if _, err := Load(); err == nil {
		t.Error("expected error when neither domains nor admins are set")
	}
}

func TestLoadBadEmailBackendFails(t *testing.T) {
	setValid(t)
	t.Setenv("EMAIL_BACKEND", "carrierpigeon")
	if _, err := Load(); err == nil {
		t.Error("expected error for unknown EMAIL_BACKEND")
	}
}

func TestLoadSMTPRequiresHost(t *testing.T) {
	setValid(t)
	t.Setenv("EMAIL_BACKEND", "smtp")
	t.Setenv("EMAIL_FROM", "auth@example.com")
	// no SMTP_HOST
	if _, err := Load(); err == nil {
		t.Error("expected error for smtp backend without SMTP_HOST")
	}
}

func TestSessionDefaults(t *testing.T) {
	setValid(t)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.SessionTTL.Hours() != 2 || c.SessionRememberTTL.Hours() != 24 || c.SessionRenew.Hours() != 1 {
		t.Errorf("session defaults: TTL=%v Remember=%v Renew=%v", c.SessionTTL, c.SessionRememberTTL, c.SessionRenew)
	}
}

func TestRenewMustBeBelowTTL(t *testing.T) {
	setValid(t)
	t.Setenv("SESSION_TTL", "1h")
	t.Setenv("SESSION_RENEW_AFTER", "2h") // >= TTL: a session would expire before it could renew
	if _, err := Load(); err == nil {
		t.Error("expected error when SESSION_RENEW_AFTER >= SESSION_TTL")
	}
}

func TestResendCooldownDefault(t *testing.T) {
	setValid(t)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.OTPResendCooldown.Seconds() != 60 {
		t.Errorf("OTPResendCooldown default = %v, want 60s", c.OTPResendCooldown)
	}
}

func TestResendCooldownMustBeBelowTTL(t *testing.T) {
	setValid(t)
	t.Setenv("OTP_TTL", "5m")
	t.Setenv("OTP_RESEND_COOLDOWN", "5m") // >= TTL: the code expires before the resend unlocks
	if _, err := Load(); err == nil {
		t.Error("expected error when OTP_RESEND_COOLDOWN >= OTP_TTL")
	}
}

func TestResendCooldownMustBePositive(t *testing.T) {
	setValid(t)
	t.Setenv("OTP_RESEND_COOLDOWN", "0s") // disabling the guard is not allowed
	if _, err := Load(); err == nil {
		t.Error("expected error when OTP_RESEND_COOLDOWN <= 0")
	}
}

func TestRateLimitParsing(t *testing.T) {
	setValid(t)
	t.Setenv("RATELIMIT_PER_EMAIL", "3/10m")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.RateLimitPerEmail.Count != 3 || c.RateLimitPerEmail.Window.Minutes() != 10 {
		t.Errorf("RateLimitPerEmail = %+v", c.RateLimitPerEmail)
	}
}

func TestRateLimitBadFormatFails(t *testing.T) {
	setValid(t)
	t.Setenv("RATELIMIT_PER_IP", "lots")
	if _, err := Load(); err == nil {
		t.Error("expected error for malformed rate limit")
	}
}
