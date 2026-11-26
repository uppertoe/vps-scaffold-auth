package authz

import "testing"

func TestRole(t *testing.T) {
	p := NewPolicy([]string{"Example.com", "example.org"}, []string{"Admin@Example.com"})

	cases := []struct {
		email string
		want  string
	}{
		{"admin@example.com", RoleAdmin}, // whitelist, case-insensitive
		{"ADMIN@EXAMPLE.COM", RoleAdmin}, // case-insensitive
		{"user@example.com", RoleUser},   // allowed domain
		{"user@example.org", RoleUser},   // second allowed domain
		{"user@EXAMPLE.com", RoleUser},   // domain case-insensitive
		{"user@evil.com", RoleDeny},      // domain not allowed
		{"", RoleDeny},                   // empty
		{"nobody", RoleDeny},             // no @
		{"trailing@", RoleDeny},          // empty domain
		{"admin@evil.com", RoleDeny},     // admin local-part at wrong domain
	}
	for _, c := range cases {
		if got := p.Role(c.email); got != c.want {
			t.Errorf("Role(%q) = %q, want %q", c.email, got, c.want)
		}
	}
}

func TestRoleWildcard(t *testing.T) {
	// Open registration: "*" plus an explicit admin whitelist and an incidental
	// literal domain (which is now redundant but must not break anything).
	p := NewPolicy([]string{"*", "example.org"}, []string{"Admin@Example.com"})
	if !p.OpenRegistration() {
		t.Fatal("expected OpenRegistration() true when \"*\" is configured")
	}

	cases := []struct {
		email string
		want  string
	}{
		{"admin@example.com", RoleAdmin}, // whitelist still wins over wildcard
		{"user@example.org", RoleUser},   // explicit domain still works
		{"anyone@gmail.com", RoleUser},   // wildcard: any real domain
		{"person@some.co.uk", RoleUser},  // multi-label domain
		{"a@b.io", RoleUser},             // short but valid
		{"", RoleDeny},                   // empty
		{"nobody", RoleDeny},             // no @
		{"trailing@", RoleDeny},          // empty domain
		{"x@localhost", RoleDeny},        // no TLD: not a public mail domain
		{"x@internal", RoleDeny},         // bare host rejected
		{"x@a..b.com", RoleDeny},         // empty label rejected
		{"x@example.c", RoleDeny},        // one-char TLD rejected
		{"x@example.123", RoleDeny},      // numeric TLD rejected
		{"x@example.com.", RoleDeny},     // trailing dot rejected
		{"x@.example.com", RoleDeny},     // leading dot rejected
	}
	for _, c := range cases {
		if got := p.Role(c.email); got != c.want {
			t.Errorf("Role(%q) = %q, want %q", c.email, got, c.want)
		}
	}
}

func TestOpenRegistrationDefaultOff(t *testing.T) {
	p := NewPolicy([]string{"example.com"}, nil)
	if p.OpenRegistration() {
		t.Error("expected OpenRegistration() false without \"*\"")
	}
	if p.Role("anyone@gmail.com") != RoleDeny {
		t.Error("non-wildcard policy must still deny unlisted domains")
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
	}
	for in, want := range cases {
		if got := GuestEligible(in); got != want {
			t.Errorf("GuestEligible(%q) = %v, want %v", in, got, want)
		}
	}
}

// LoginRole confers a guest only for an address the allow-list denies, and only
// from an open host. A permitted address keeps its real role on an open host, so
// an admin or a department user is never downgraded to a guest.
func TestLoginRoleGuest(t *testing.T) {
	p := NewPolicy([]string{"rch.org.au"}, []string{"boss@elsewhere.com"})
	cases := []struct {
		email    string
		openHost bool
		want     string
	}{
		{"stranger@gmail.com", true, RoleGuest},
		{"stranger@gmail.com", false, RoleDeny},
		{"x@localhost", true, RoleDeny}, // not a plausible public address
		{"u@rch.org.au", true, RoleUser},
		{"u@rch.org.au", false, RoleUser},
		{"boss@elsewhere.com", true, RoleAdmin},
	}
	for _, c := range cases {
		if got := p.LoginRole(c.email, c.openHost); got != c.want {
			t.Errorf("LoginRole(%q, open=%v) = %q, want %q", c.email, c.openHost, got, c.want)
		}
	}
	// Role itself never answers "guest": that would make every stranger allowed.
	if got := p.Role("stranger@gmail.com"); got != RoleDeny {
		t.Errorf("Role(stranger) = %q, want deny", got)
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

func TestHasAllowList(t *testing.T) {
	for _, c := range []struct {
		domains []string
		want    bool
	}{
		{nil, false},
		{[]string{"", "  "}, false},
		{[]string{"example.com"}, true},
		{[]string{"*"}, true},
	} {
		if got := NewPolicy(c.domains, []string{"admin@example.com"}).HasAllowList(); got != c.want {
			t.Errorf("HasAllowList(%q) = %v, want %v", c.domains, got, c.want)
		}
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
