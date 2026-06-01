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

// HasGroup reports whether the comma-separated groups string contains target.
func HasGroup(groups, target string) bool {
	for _, g := range strings.Split(groups, ",") {
		if strings.TrimSpace(g) == target {
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
