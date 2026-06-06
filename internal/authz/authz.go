// Package authz decides who is allowed in and where it is safe to redirect
// them. Access is intentionally permissive-by-design within the configured
// boundary: anyone with a verified email at an allowed domain is a regular
// user, and an explicit whitelist grants admin.
package authz

import (
	"net/url"
	"strings"
)

// Roles emitted to downstream apps via the Remote-Groups header.
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
	RoleDeny  = ""
)

// Policy captures the access rules. Domains and emails are stored lowercased.
type Policy struct {
	allowedDomains map[string]struct{}
	adminEmails    map[string]struct{}
}

// NewPolicy builds a Policy from the configured allowed domains and admin
// emails.
func NewPolicy(allowedDomains, adminEmails []string) *Policy {
	p := &Policy{
		allowedDomains: make(map[string]struct{}, len(allowedDomains)),
		adminEmails:    make(map[string]struct{}, len(adminEmails)),
	}
	for _, d := range allowedDomains {
		p.allowedDomains[strings.ToLower(strings.TrimSpace(d))] = struct{}{}
	}
	for _, e := range adminEmails {
		p.adminEmails[strings.ToLower(strings.TrimSpace(e))] = struct{}{}
	}
	return p
}

// Role returns the role for an email address: RoleAdmin, RoleUser, or RoleDeny
// (empty string) if the email is not permitted.
func (p *Policy) Role(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return RoleDeny
	}
	if _, ok := p.adminEmails[email]; ok {
		return RoleAdmin
	}
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return RoleDeny
	}
	domain := email[at+1:]
	if _, ok := p.allowedDomains[domain]; ok {
		return RoleUser
	}
	return RoleDeny
}

// Allowed reports whether the email may authenticate at all.
func (p *Policy) Allowed(email string) bool {
	return p.Role(email) != RoleDeny
}

// BuildGroups composes the comma-separated Remote-Groups value baked into a
// session: the base role (admin/user) first, followed by any DB-managed group
// names, de-duplicated and with blanks dropped. Keeping the role in the set
// preserves compatibility with existing role-equality Caddy matchers and the
// admin-UI gate.
func BuildGroups(role string, dbGroups []string) string {
	seen := make(map[string]struct{})
	var out []string
	add := func(g string) {
		g = strings.TrimSpace(g)
		if g == "" {
			return
		}
		if _, ok := seen[g]; ok {
			return
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	add(role)
	for _, g := range dbGroups {
		add(g)
	}
	return strings.Join(out, ",")
}

// IsReservedGroup reports whether name collides with a base role. A DB group or
// a break-glass target group with such a name would be indistinguishable from
// the role in the Remote-Groups set, silently conferring admin/user privilege,
// so callers must reject these names.
func IsReservedGroup(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case RoleAdmin, RoleUser:
		return true
	}
	return false
}

// ValidGroupName reports whether name is a safe group identifier: a non-empty
// run of lowercase letters, digits, hyphen, and underscore. The constraint is a
// security boundary, not cosmetics: group names are joined with "," into the
// Remote-Groups set (see BuildGroups) and split back out on "," (and, in app
// matchers, on whitespace/";" too). A name carrying a separator would smuggle an
// extra token into that set — e.g. a group "x,admin" injects the "admin" role —
// slipping past IsReservedGroup, which only matches whole names. Callers must
// reject names that fail this before persisting them. Human-friendly display
// text belongs in a group's separate label field, which has no such constraint.
func ValidGroupName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// HasGroup reports whether the comma-separated groups string contains target.
func HasGroup(groups, target string) bool {
	for _, g := range strings.Split(groups, ",") {
		if strings.TrimSpace(g) == target {
			return true
		}
	}
	return false
}

// DomainOf returns the lowercased domain part of an email, or "" if there
// isn't one. Break-glass principals (e.g. "breakglass:Lab 1") have no domain,
// so they never satisfy a domain-based requirement.
func DomainOf(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return email[at+1:]
}

// splitList parses a comma/space/semicolon/newline-separated list, lowercased,
// trimmed, with blanks dropped. Used for the per-app requirement headers and
// matches how group names and domains are stored (lowercased).
func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';' || r == '\n' || r == '\r' || r == '\t'
	}) {
		out = append(out, strings.ToLower(f))
	}
	return out
}

// CanAccessApp decides whether a principal may reach a specific app, given that
// app's declared requirements (the comma/space-separated allow-lists a Caddy
// snippet passes in the single X-Auth-Policy header, parsed by the server into
// reqDomains/reqGroups). email and groups come from the validated session;
// breakGlass marks an emergency QR session.
//
//   - No requirement declared: a normal session is allowed (status quo), but a
//     break-glass session is DENIED — emergency access must be explicitly opted
//     into by group, so it can never reach a plain `import protected` app.
//   - Requirement declared: allowed when the email's domain is in reqDomains OR
//     the session's groups intersect reqGroups (an OR across the two lists).
func CanAccessApp(email, groups string, breakGlass bool, reqDomains, reqGroups string) bool {
	if strings.TrimSpace(reqDomains) == "" && strings.TrimSpace(reqGroups) == "" {
		return !breakGlass
	}
	// A break-glass session must NEVER satisfy a domain requirement — emergency
	// access is opt-in by group only. The principal is "breakglass:<label>" with
	// an admin-supplied label, and DomainOf would otherwise parse a domain out of
	// a label that happens to contain an "@" (e.g. "ops@rch.org.au"), letting a
	// card reach domain-restricted apps it was never scoped to. Gating on
	// !breakGlass enforces the invariant regardless of the label's content.
	if d := DomainOf(email); d != "" && !breakGlass {
		for _, want := range splitList(reqDomains) {
			if d == want {
				return true
			}
		}
	}
	for _, want := range splitList(reqGroups) {
		if HasGroup(groups, want) {
			return true
		}
	}
	return false
}

// ValidateRedirect returns a safe post-login redirect target. It accepts only
// absolute https URLs whose host is exactly domain or a subdomain of it. This
// blocks open-redirect tricks (//evil, scheme downgrade, userinfo, look-alike
// suffixes such as example.com.evil.com). The empty string with ok=false means
// the caller should fall back to its default redirect.
func ValidateRedirect(rd, domain string) (string, bool) {
	if rd == "" {
		return "", false
	}
	u, err := url.Parse(rd)
	if err != nil {
		return "", false
	}
	if u.Scheme != "https" {
		return "", false
	}
	if u.User != nil { // reject user[:pass]@host
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	domain = strings.ToLower(strings.TrimPrefix(domain, "."))
	if host == "" || domain == "" {
		return "", false
	}
	if host != domain && !strings.HasSuffix(host, "."+domain) {
		return "", false
	}
	return u.String(), true
}

// SafeRedirect returns rd if it is valid, otherwise the fallback.
func SafeRedirect(rd, domain, fallback string) string {
	if v, ok := ValidateRedirect(rd, domain); ok {
		return v
	}
	return fallback
}
