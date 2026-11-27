package authz

import "testing"

// Role answers admin only for ADMIN_EMAILS, whatever the domain: no domain
// makes an address staff here, and no "*" opens anything.
func TestRole(t *testing.T) {
	p := NewPolicy([]string{"Admin@Example.com", " "})
	cases := []struct {
		email string
		want  string
	}{
		{"admin@example.com", RoleAdmin},
		{"ADMIN@EXAMPLE.COM", RoleAdmin},
		{"user@example.com", RoleDeny},
		{"anyone@gmail.com", RoleDeny},
		{"*", RoleDeny},
		{"", RoleDeny},
		{"nobody", RoleDeny},
		{"admin@evil.com", RoleDeny},
	}
	for _, c := range cases {
		if got := p.Role(c.email); got != c.want {
			t.Errorf("Role(%q) = %q, want %q", c.email, got, c.want)
		}
	}
}

func TestValidGroupName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"reports_team", true},
		{"bg-stroke", true},
		{"abc123", true},
		{"", false},
		{"x,admin", false}, // comma would inject a role token into Remote-Groups
		{"x admin", false}, // space splits in app matchers
		{"x;admin", false}, // semicolon splits in the policy/app parsers
		{"UPPER", false},   // names are stored lowercased
		{"emoji😀", false},  // only [a-z0-9_-]
		{"a.b", false},     // dot is not allowed
	}
	for _, c := range cases {
		if got := ValidGroupName(c.name); got != c.want {
			t.Errorf("ValidGroupName(%q) = %v, want %v", c.name, got, c.want)
		}
	}
	// The separator-bearing names that would smuggle a role are not caught by
	// IsReservedGroup (which only matches whole names) — ValidGroupName is the
	// guard that stops them.
	if IsReservedGroup("x,admin") {
		t.Error("IsReservedGroup unexpectedly matched a comma-bearing name")
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
		"http://example.com/",           // scheme downgrade
		"//evil.com",                    // protocol-relative
		"https://evil.com/",             // wrong host
		"https://example.com.evil.com/", // look-alike suffix
		"https://evilexample.com/",      // no dot boundary
		"https://user@example.com/",     // userinfo
		"https://user:pass@evil.com/",   // userinfo + wrong host
		"ftp://example.com/",            // wrong scheme
		"javascript:alert(1)",           // not a URL host
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

func TestGuestEligible(t *testing.T) {
	cases := map[string]bool{
		"stranger@gmail.com":       true,
		"Someone@Uni.Edu.Au":       true,
		"x@localhost":              false, // no TLD
		"x@10.0.0.1":               false, // numeric TLD
		"@gmail.com":               false, // no local part
		"x@":                       false,
		"no-at-sign":               false,
		"breakglass:ops@rch.org.a": false, // one-letter TLD
		"x@internal":               false, // bare host
		"x@a..b.com":               false, // empty label
		"x@example.com.":           false, // trailing dot
		"x@.example.com":           false, // leading dot
		"x@example.123":            false, // numeric TLD
	}
	for in, want := range cases {
		if got := GuestEligible(in); got != want {
			t.Errorf("GuestEligible(%q) = %v, want %v", in, got, want)
		}
	}
}

// Guests are deny-by-default: only guests=allow or an explicit group opens a
// route to them, and a domain list never does, even one naming their domain.
func TestGuestIsReservedGroup(t *testing.T) {
	if !IsReservedGroup("guest") || !IsReservedGroup(" Guest ") {
		t.Error(`"guest" must be reserved so a DB group or card cannot pose as a guest`)
	}
}

func TestBuildGroupsDropsReservedStoredGroups(t *testing.T) {
	if got := BuildGroups("user", []string{"admin", "guest", "user", "team"}); got != "user,team" {
		t.Errorf("BuildGroups = %q, want user,team", got)
	}
}

func TestDomainIn(t *testing.T) {
	cases := []struct {
		email, list string
		want        bool
	}{
		{"a@rch.org.au", "rch.org.au", true},
		{"A@RCH.ORG.AU", "mcri.edu.au rch.org.au", true},
		{"a@rch.org.au", "mcri.edu.au,monashhealth.org", false},
		{"a@sub.rch.org.au", "rch.org.au", false},
		{"breakglass:Lab", "rch.org.au", false},
		{"a@rch.org.au", "", false},
	}
	for _, c := range cases {
		if got := DomainIn(c.email, c.list); got != c.want {
			t.Errorf("DomainIn(%q, %q) = %v, want %v", c.email, c.list, got, c.want)
		}
	}
}
