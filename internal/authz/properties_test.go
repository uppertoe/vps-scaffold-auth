package authz

import (
	"net/url"
	"strings"
	"testing"
)

// Property tests for the decisions every request depends on. The seeds run on
// every `go test`; `go test -fuzz=FuzzX ./internal/authz` explores further.

// FuzzValidateRedirect: whatever ValidateRedirect accepts is an https URL on
// the domain or one of its subdomains, with no credentials, and it is still so
// after a second parse of the returned string. The second parse matters
// because the browser parses the Location header again, and a string that two
// parsers read differently (a backslash, an encoded dot, a stray @) is how an
// open redirect usually slips past a check.
func FuzzValidateRedirect(f *testing.F) {
	for _, s := range []string{
		"https://app.example.com/x", "https://example.com", "https://evil.com",
		"https://app.example.com.evil.com/", "https://evil.com\\@app.example.com",
		"https://evil.com#@app.example.com", "https://user:pw@app.example.com/",
		"https://app.example.com%2eevil.com/", "//app.example.com", "http://app.example.com",
		"https:/\\evil.com", "https://APP.EXAMPLE.COM/", "https://app.example.com:443/",
		"https://[::1]/", "https://evil.com%40app.example.com/", "https://app.example.com\t.evil.com",
		"javascript:alert(1)//app.example.com", "https://xn--exmple-cua.com/",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, rd string) {
		out, ok := ValidateRedirect(rd, "example.com")
		if !ok {
			return
		}
		// Read the output as Go does and as a browser does (WHATWG URL
		// clean-up: tabs and newlines removed anywhere, leading and trailing
		// C0 controls and spaces trimmed, a backslash read as a slash in an
		// https URL). Both readings must land on the domain.
		for _, s := range []string{out, browserView(out)} {
			u, err := url.Parse(s)
			if err != nil {
				t.Fatalf("accepted %q but %q does not parse: %v", rd, s, err)
			}
			host := strings.ToLower(u.Hostname())
			if u.Scheme != "https" || u.User != nil || u.Opaque != "" {
				t.Fatalf("accepted %q, read as %q: scheme %q, user %v, opaque %q", rd, s, u.Scheme, u.User, u.Opaque)
			}
			if host != "example.com" && !strings.HasSuffix(host, ".example.com") {
				t.Fatalf("accepted %q, read as %q, which leaves the domain (host %q)", rd, s, host)
			}
		}
	})
}

// browserView applies the parts of the WHATWG URL parser that make a browser
// read a string differently from Go's url.Parse.
func browserView(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
	s = strings.TrimFunc(s, func(r rune) bool { return r <= ' ' })
	return strings.ReplaceAll(s, `\`, "/")
}

// FuzzCanAccessApp checks the access decision's three containment rules on
// arbitrary inputs:
//   - a break-glass session is admitted only through a group it carries;
//   - a guest is admitted only where guests are allowed, or through a group;
//   - with a non-empty rule, anyone else is admitted only by a listed domain
//     or a listed group.
func FuzzCanAccessApp(f *testing.F) {
	f.Add("ops@rch.org.au", "bg_lab", true, false, "rch.org.au", "", false)
	f.Add("breakglass:ops@rch.org.au", "user", true, false, "rch.org.au", "user", false)
	f.Add("a@stranger.net", "guest", false, true, "stranger.net", "", false)
	f.Add("a@stranger.net", "guest,reports", false, true, "", "reports", false)
	f.Add("a@rch.org.au", "user", false, false, "", "", false)
	f.Add("a@rch.org.au", "user,x", false, false, "mcri.edu.au", "x,admin", true)
	f.Add("a@RCH.org.au", "user", false, false, "rch.org.au", "", false)
	f.Fuzz(func(t *testing.T, email, groups string, bg, guest bool, doms, grps string, allowGuests bool) {
		if !CanAccessApp(email, groups, bg, guest, doms, grps, allowGuests) {
			return
		}
		viaGroup := false
		for _, g := range splitList(grps) {
			if HasGroup(groups, g) {
				viaGroup = true
			}
		}
		viaDomain := false
		if d := DomainOf(email); d != "" {
			for _, want := range splitList(doms) {
				if d == want {
					viaDomain = true
				}
			}
		}
		emptyRule := strings.TrimSpace(doms) == "" && strings.TrimSpace(grps) == ""
		switch {
		case guest:
			if !allowGuests && !viaGroup {
				t.Fatalf("guest %q admitted without guests=allow or a group (doms %q, grps %q)", email, doms, grps)
			}
		case bg:
			if !viaGroup {
				t.Fatalf("break-glass %q (groups %q) admitted without a listed group (doms %q, grps %q)", email, groups, doms, grps)
			}
		case !emptyRule:
			if !viaDomain && !viaGroup {
				t.Fatalf("%q (groups %q) admitted by neither a listed domain nor group (doms %q, grps %q)", email, groups, doms, grps)
			}
		}
	})
}

// FuzzBuildGroupsKeepsRoleFirst: the role is always the first entry of the
// groups header, and no group name that passes ValidGroupName can add a
// reserved role to the set.
func FuzzBuildGroupsKeepsRoleFirst(f *testing.F) {
	f.Add("user", "reports")
	f.Add("guest", "x,admin")
	f.Add("user", "admin")
	f.Fuzz(func(t *testing.T, role, group string) {
		if role != RoleUser && role != RoleGuest {
			return
		}
		if !ValidGroupName(group) || IsReservedGroup(group) {
			return
		}
		got := BuildGroups(role, []string{group})
		parts := strings.Split(got, ",")
		if parts[0] != role {
			t.Fatalf("BuildGroups(%q, %q) = %q: role not first", role, group, got)
		}
		for _, p := range parts[1:] {
			if IsReservedGroup(p) {
				t.Fatalf("group %q added the reserved role %q (%q)", group, p, got)
			}
		}
	})
}
