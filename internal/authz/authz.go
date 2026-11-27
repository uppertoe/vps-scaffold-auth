// Package authz decides who is allowed in and where it is safe to redirect
// them. Access is intentionally permissive-by-design within the configured
// boundary: anyone with a verified email at an allowed domain is a regular
// user, and an explicit whitelist grants admin.
package authz

import (
	"net/url"
	"strings"
)

// The base roles. A session's groups begin with one of them (see
// BuildGroups); apps never see them, since apps decide by Remote-Roles.
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
	RoleDeny  = ""
	// RoleGuest is the base role of a guest session: an address the allow-list
	// does not permit, signed in through a host listed in OPEN_REGISTRATION_HOSTS.
	// It is never returned by Role (which answers "is this address permitted?");
	// LoginRole confers it, and only an app role held by guests (or by a list
	// the guest was explicitly placed in) admits it.
	RoleGuest = "guest"
	// RoleMember is the base role of an address the allow-list does not
	// permit but that holds an app role (or has accepted an invitation). It
	// is never sent to an app: such a session's groups carry the guest tier
	// token, and a role guard decides it by its roles.
	RoleMember = "member"
)

// Wildcard is the ALLOWED_EMAIL_DOMAINS entry that opts the WHOLE instance into
// open registration (the global form; prefer per-host OPEN_REGISTRATION_HOSTS
// guest sessions on a shared server, which leave every other app closed): any email at a syntactically valid domain becomes a regular
// user. Safe only because login is email-verified (OTP) — the code proves the
// visitor controls that mailbox — so a wildcard grants no access to an address
// the visitor cannot actually receive mail at. Admin remains an exact allow-list
// regardless, and app roles are unchanged: with a wildcard, a role held by a
// domain group still admits only that group's domains.
const Wildcard = "*"

// Policy captures the access rules. Domains and emails are stored lowercased.
type Policy struct {
	allowedDomains map[string]struct{}
	adminEmails    map[string]struct{}
	openReg        bool // ALLOWED_EMAIL_DOMAINS contained "*": any valid domain is a user
}

// NewPolicy builds a Policy from the configured allowed domains and admin
// emails. A "*" entry in allowedDomains enables open registration (see Wildcard).
func NewPolicy(allowedDomains, adminEmails []string) *Policy {
	p := &Policy{
		allowedDomains: make(map[string]struct{}, len(allowedDomains)),
		adminEmails:    make(map[string]struct{}, len(adminEmails)),
	}
	for _, d := range allowedDomains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if d == Wildcard {
			p.openReg = true
			continue // not a literal domain; never store "*" in the exact set
		}
		p.allowedDomains[d] = struct{}{}
	}
	for _, e := range adminEmails {
		p.adminEmails[strings.ToLower(strings.TrimSpace(e))] = struct{}{}
	}
	return p
}

// OpenRegistration reports whether any verified email is accepted as a user
// (the "*" wildcard). Callers use it to suppress domain-specific login hints.
func (p *Policy) OpenRegistration() bool { return p.openReg }

// HasAllowList reports whether ALLOWED_EMAIL_DOMAINS names any domain, or the
// "*" wildcard. Without one, the gateway takes its staff domains from the
// domain groups instead (see the server's knownRole).
func (p *Policy) HasAllowList() bool { return p.openReg || len(p.allowedDomains) > 0 }

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
	// Open registration: any address at a syntactically valid, deliverable-looking
	// domain is a user. The dot requirement rejects bare hosts like "localhost" or
	// "internal" that can't receive public mail; real security rests on OTP, which
	// only lets in someone who can read the code at that address.
	if p.openReg && validPublicDomain(domain) {
		return RoleUser
	}
	return RoleDeny
}

// GuestEligible reports whether email may be signed in as a guest: it has a
// local part and its domain passes validPublicDomain. This is the same sanity
// gate as the wildcard path — not a trust decision. What makes a guest safe is
// that OTP proves mailbox control and a role guard admits a guest only where
// an app role is held by guests.
func GuestEligible(email string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return false
	}
	return validPublicDomain(email[at+1:])
}

// LoginRole is the role a completed email-code login confers. It is Role(email)
// whenever that permits the address, so an admin or an allow-listed user is
// never downgraded to a guest. Only when Role denies, and the login was reached
// from an open-registration host, does a syntactically valid public address
// become RoleGuest; otherwise the answer stays RoleDeny. openHost is derived by
// the caller from the (validated) post-login destination.
func (p *Policy) LoginRole(email string, openHost bool) string {
	if role := p.Role(email); role != RoleDeny {
		return role
	}
	if openHost && GuestEligible(email) {
		return RoleGuest
	}
	return RoleDeny
}

// validPublicDomain reports whether domain is plausibly a public, mail-carrying
// domain: at least one dot, no empty labels, and a non-numeric TLD. It is a
// sanity gate for the open-registration path, not a substitute for OTP delivery.
func validPublicDomain(domain string) bool {
	if domain == "" || len(domain) > 253 {
		return false
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false // needs a TLD, so "localhost" is rejected
	}
	for _, l := range labels {
		if l == "" {
			return false // no empty label (rejects "a..b")
		}
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return false
	}
	for _, r := range tld {
		if r < 'a' || r > 'z' { // TLDs are alphabetic (a-z after lowercasing)
			return false
		}
	}
	return true
}

// Allowed reports whether the email may authenticate at all.
func (p *Policy) Allowed(email string) bool {
	return p.Role(email) != RoleDeny
}

// BuildGroups composes the comma-separated groups baked into a session: the
// base role (admin, user or guest) first, followed by any DB-managed group
// names, de-duplicated and with blanks dropped. The gateway reads the base
// role for the admin gate and the session's tier, and the lists for list
// assignments; the value is never sent to an app.
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
		// A stored group named after a role (legacy data, manual SQL) must
		// never confer that role through a session's groups.
		if IsReservedGroup(g) {
			continue
		}
		add(g)
	}
	return strings.Join(out, ",")
}

// IsReservedGroup reports whether name collides with a base role. A DB group or
// a break-glass target group with such a name would be indistinguishable from
// the role in a session's groups, silently conferring admin/user privilege,
// so callers must reject these names.
//
// "guest" is reserved for the same reason in the other direction: the gateway
// reads a leading "guest" in a session's groups as "this is a stranger", so a
// DB group of that name must not be able to stamp it onto a regular user, nor
// a break-glass card make itself look like one.
func IsReservedGroup(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case RoleAdmin, RoleUser, RoleGuest:
		return true
	}
	return false
}

// ValidGroupName reports whether name is a safe group identifier: a non-empty
// run of lowercase letters, digits, hyphen, and underscore. The constraint is a
// security boundary, not cosmetics: group names are joined with "," into a
// session's groups (see BuildGroups) and split back out on ",". A name
// carrying a separator would smuggle an extra token into that set — e.g. a
// group "x,admin" injects the "admin" role — slipping past IsReservedGroup,
// which only matches whole names. Callers must
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

// DomainIn reports whether email's domain is in list, a comma/space-separated
// list of domains. An address with no domain never is.
func DomainIn(email, list string) bool {
	d := DomainOf(email)
	if d == "" {
		return false
	}
	for _, want := range splitList(list) {
		if d == want {
			return true
		}
	}
	return false
}

// splitList parses a comma/space/semicolon/newline-separated list, lowercased,
// trimmed, with blanks dropped, matching how domains are stored (lowercased).
func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';' || r == '\n' || r == '\r' || r == '\t'
	}) {
		out = append(out, strings.ToLower(f))
	}
	return out
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
