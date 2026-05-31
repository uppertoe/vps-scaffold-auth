package authz

import "testing"

func TestRole(t *testing.T) {
	p := NewPolicy([]string{"Example.com", "example.org"}, []string{"Admin@Example.com"})

	cases := []struct {
		email string
		want  string
	}{
		{"admin@example.com", RoleAdmin},     // whitelist, case-insensitive
		{"ADMIN@EXAMPLE.COM", RoleAdmin},     // case-insensitive
		{"user@example.com", RoleUser},       // allowed domain
		{"user@example.org", RoleUser},       // second allowed domain
		{"user@EXAMPLE.com", RoleUser},       // domain case-insensitive
		{"user@evil.com", RoleDeny},          // domain not allowed
		{"", RoleDeny},                       // empty
		{"nobody", RoleDeny},                 // no @
		{"trailing@", RoleDeny},              // empty domain
		{"admin@evil.com", RoleDeny},         // admin local-part at wrong domain
	}
	for _, c := range cases {
		if got := p.Role(c.email); got != c.want {
			t.Errorf("Role(%q) = %q, want %q", c.email, got, c.want)
		}
	}
}

func TestAllowed(t *testing.T) {
	p := NewPolicy([]string{"example.com"}, nil)
	if !p.Allowed("a@example.com") {
		t.Error("expected allowed")
	}
	if p.Allowed("a@evil.com") {
		t.Error("expected denied")
	}
}

func TestValidateRedirect(t *testing.T) {
	const domain = "example.com"
	good := []string{
		"https://example.com/",
		"https://example.com/path?q=1",
		"https://app.example.com/dashboard",
		"https://deep.sub.example.com/",
	}
	for _, rd := range good {
		if _, ok := ValidateRedirect(rd, domain); !ok {
			t.Errorf("ValidateRedirect(%q) = false, want true", rd)
		}
	}

	bad := []string{
		"",
		"http://example.com/",            // scheme downgrade
		"//evil.com",                     // protocol-relative
		"https://evil.com/",              // wrong host
		"https://example.com.evil.com/",  // look-alike suffix
		"https://evilexample.com/",       // no dot boundary
		"https://user@example.com/",      // userinfo
		"https://user:pass@evil.com/",    // userinfo + wrong host
		"ftp://example.com/",             // wrong scheme
		"javascript:alert(1)",            // not a URL host
	}
	for _, rd := range bad {
		if v, ok := ValidateRedirect(rd, domain); ok {
			t.Errorf("ValidateRedirect(%q) = %q,true, want false", rd, v)
		}
	}
}

func TestSafeRedirect(t *testing.T) {
	const domain = "example.com"
	const fallback = "https://example.com/home"
	if got := SafeRedirect("https://evil.com/", domain, fallback); got != fallback {
		t.Errorf("SafeRedirect(bad) = %q, want fallback", got)
	}
	if got := SafeRedirect("https://app.example.com/x", domain, fallback); got != "https://app.example.com/x" {
		t.Errorf("SafeRedirect(good) = %q", got)
	}
}
