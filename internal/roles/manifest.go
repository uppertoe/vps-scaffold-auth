// Package roles holds the app-roles model: the manifest of each app's roles,
// which the scaffold renders from the apps' Caddy snippets, and the pure
// decision of which roles a request holds. The gateway's store keeps who has
// been given each role; this package only reads those assignments.
package roles

import (
	"bufio"
	"io"
	"sort"
	"strings"
)

// The manifest (APP_ROLES_FILE) is plain text, one record per line, fields
// separated by a single TAB. Blank lines and lines starting with "#" are
// skipped. {$DOMAIN} in a host is replaced by the gateway's domain.
//
// A role line declares one role of one app. It is the original format and
// is unchanged:
//
//	app<TAB>role<TAB>label<TAB>hosts
//
// hosts is comma-separated. Every app must declare the "user" role, or the
// whole app is left out.
//
// Every other line starts with a keyword beginning "@", which no app name
// can (see ValidName), so the two kinds of line can never be confused. Each
// keyword line names an app already declared by a role line (anywhere in the
// file):
//
//	@label<TAB>app<TAB>label          the app's display name (default: app)
//	@source<TAB>app<TAB>file          the snippet the app was declared in
//	@path<TAB>app<TAB>paths<TAB>role  paths that need role
//	@open<TAB>app<TAB>paths<TAB>reason  paths open by design, and why
//	@card-page<TAB>app<TAB>path<TAB>label  a page a break-glass card may open
//
// paths is one or more space-separated patterns. A pattern is an exact path
// ("/faq") or a prefix ending in "*" ("/admin/*"); a lone "*" stands for
// every path the app's other lines do not name ("Everything else"). The most
// specific pattern decides a path, as Caddy's handle blocks do: an exact
// match first, then the longest prefix, then "*".
//
// A card page must be an exact path that a "user" @path line decides,
// because a card holds only its app's user role. A malformed line, a line for
// an undeclared app or role, a pattern declared twice and a card page outside
// the user role are each logged and skipped. A keyword the gateway does not
// know is logged and skipped, so a newer scaffold can add one.
const (
	lineLabel    = "@label"
	lineSource   = "@source"
	linePath     = "@path"
	lineOpen     = "@open"
	lineCardPage = "@card-page"
)

// App is one app in the manifest.
type App struct {
	Name  string
	Label string            // display name; Name when no @label line
	Roles map[string]string // role -> label
	// RoleOrder lists the roles with the user role first, then in the order
	// the manifest declares them.
	RoleOrder []string
	Hosts     []string
	Source    string     // the snippet file, from @source; "" when not given
	Paths     []Path     // @path and @open lines, in file order
	CardPages []CardPage // @card-page lines, in file order
}

// Path is one @path or @open line: a set of patterns and what they need.
type Path struct {
	Patterns []string // e.g. ["/", "/faq"]; ["*"] for everything else
	Role     string   // the role needed; "" for an open path
	Reason   string   // why an open path is open
}

// Open reports whether the paths are open by design.
func (p Path) Open() bool { return p.Role == "" }

// Rest reports whether the line is the "*" line: every path the app's other
// lines do not name.
func (p Path) Rest() bool { return len(p.Patterns) == 1 && p.Patterns[0] == "*" }

// CardPage is a page a break-glass card for the app may open.
type CardPage struct {
	Path  string
	Label string
}

// Manifest is every app the gateway decides by role.
type Manifest struct {
	Apps map[string]*App
}

// Has reports whether app declares role.
func (m Manifest) Has(app, role string) bool {
	a, ok := m.Apps[app]
	if !ok {
		return false
	}
	_, ok = a.Roles[role]
	return ok
}

// Sorted returns the apps ordered by label, then name.
func (m Manifest) Sorted() []*App {
	out := make([]*App, 0, len(m.Apps))
	for _, a := range m.Apps {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		li, lj := strings.ToLower(out[i].Label), strings.ToLower(out[j].Label)
		if li != lj {
			return li < lj
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// PathsFor returns the lines that need role, in file order.
func (a *App) PathsFor(role string) []Path {
	var out []Path
	for _, p := range a.Paths {
		if p.Role == role {
			out = append(out, p)
		}
	}
	return out
}

// OpenPaths returns the lines open by design, in file order.
func (a *App) OpenPaths() []Path {
	var out []Path
	for _, p := range a.Paths {
		if p.Open() {
			out = append(out, p)
		}
	}
	return out
}

// Decide returns the line that decides path: an exact pattern first, then
// the longest matching prefix, then the "*" line. ok is false when no line
// decides it.
func (a *App) Decide(path string) (Path, bool) {
	best, score := Path{}, -1
	for _, p := range a.Paths {
		for _, pat := range p.Patterns {
			s := matchScore(pat, path)
			if s > score {
				best, score = p, s
			}
		}
	}
	return best, score >= 0
}

// matchScore ranks how specifically pattern matches path, or -1 for no
// match: "*" scores 0, a prefix its length, an exact path above any prefix.
func matchScore(pattern, path string) int {
	switch {
	case pattern == "*":
		return 0
	case strings.HasSuffix(pattern, "*"):
		prefix := strings.TrimSuffix(pattern, "*")
		if strings.HasPrefix(path, prefix) {
			return 1 + len(prefix)
		}
		return -1
	case pattern == path:
		return 1 << 20
	}
	return -1
}

// validPattern reports whether s is "*", an exact path, or a path prefix
// ending in "*", with no other "*" and no space or control character.
func validPattern(s string) bool {
	if s == "*" {
		return true
	}
	if !strings.HasPrefix(s, "/") || strings.Contains(strings.TrimSuffix(s, "*"), "*") {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

// keywordLine is a keyword line kept until every role line has been read.
type keywordLine struct {
	n int
	f []string
}

// ParseManifest reads the app-roles manifest (the format is described at the
// top of this file). A malformed line is logged and skipped, and an app
// without a user role is logged and left out entirely, so a guard naming it
// is refused rather than half-decided.
func ParseManifest(r io.Reader, domain string, logf func(format string, args ...any)) Manifest {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	apps := map[string]*App{}
	hosts := map[string]map[string]struct{}{}
	var keywords []keywordLine
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if strings.HasPrefix(f[0], "@") {
			keywords = append(keywords, keywordLine{n: n, f: f})
			continue
		}
		if len(f) != 4 {
			logf("app roles: line %d: want 4 tab-separated fields, got %d", n, len(f))
			continue
		}
		app, role, label := strings.TrimSpace(f[0]), strings.TrimSpace(f[1]), strings.TrimSpace(f[2])
		if !ValidName(app) || !ValidName(role) {
			logf("app roles: line %d: app %q and role %q must be lower-case letters, digits, - or _", n, app, role)
			continue
		}
		a := apps[app]
		if a == nil {
			a = &App{Name: app, Label: app, Roles: map[string]string{}}
			apps[app] = a
			hosts[app] = map[string]struct{}{}
		}
		if _, dup := a.Roles[role]; dup {
			logf("app roles: line %d: %s declares role %q twice", n, app, role)
			continue
		}
		if label == "" {
			label = role
		}
		a.Roles[role] = label
		a.RoleOrder = append(a.RoleOrder, role)
		for _, h := range strings.Split(f[3], ",") {
			h = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(h, "{$DOMAIN}", domain)))
			if h != "" {
				hosts[app][h] = struct{}{}
			}
		}
	}
	if err := sc.Err(); err != nil {
		logf("app roles: %v", err)
	}
	for name, a := range apps {
		if _, ok := a.Roles[UserRole]; !ok {
			logf("app roles: %s declares no %q role, so it is left out and its guards are refused", name, UserRole)
			delete(apps, name)
			continue
		}
		for h := range hosts[name] {
			a.Hosts = append(a.Hosts, h)
		}
		sort.Strings(a.Hosts)
		order := []string{UserRole}
		for _, r := range a.RoleOrder {
			if r != UserRole {
				order = append(order, r)
			}
		}
		a.RoleOrder = order
	}
	// Card pages are checked against the paths, so they are read last.
	var cards []keywordLine
	for _, k := range keywords {
		if k.f[0] == lineCardPage {
			cards = append(cards, k)
			continue
		}
		parseKeyword(apps, k, logf)
	}
	for _, k := range cards {
		parseKeyword(apps, k, logf)
	}
	return Manifest{Apps: apps}
}

// keywordFields is how many fields each keyword line has.
var keywordFields = map[string]int{lineLabel: 3, lineSource: 3, linePath: 4, lineOpen: 4, lineCardPage: 4}

func parseKeyword(apps map[string]*App, k keywordLine, logf func(string, ...any)) {
	want, known := keywordFields[k.f[0]]
	if !known {
		logf("app roles: line %d: unknown keyword %q", k.n, k.f[0])
		return
	}
	if len(k.f) != want {
		logf("app roles: line %d: %s wants %d tab-separated fields, got %d", k.n, k.f[0], want, len(k.f))
		return
	}
	f := make([]string, len(k.f))
	for i, v := range k.f {
		f[i] = strings.TrimSpace(v)
	}
	a := apps[f[1]]
	if a == nil {
		logf("app roles: line %d: %s names app %q, which declares no roles here", k.n, f[0], f[1])
		return
	}
	switch f[0] {
	case lineLabel:
		if f[2] == "" || a.Label != a.Name {
			logf("app roles: line %d: %s needs one non-empty label", k.n, f[0])
			return
		}
		a.Label = f[2]
	case lineSource:
		if f[2] == "" || a.Source != "" {
			logf("app roles: line %d: %s needs one non-empty file", k.n, f[0])
			return
		}
		a.Source = f[2]
	case linePath, lineOpen:
		pats := strings.Fields(f[2])
		if len(pats) == 0 {
			logf("app roles: line %d: %s has no paths", k.n, f[0])
			return
		}
		seen := map[string]bool{}
		for _, p := range a.Paths {
			for _, q := range p.Patterns {
				seen[q] = true
			}
		}
		for _, p := range pats {
			if !validPattern(p) || (p == "*" && len(pats) > 1) || seen[p] {
				logf("app roles: line %d: path %q is malformed, mixed with \"*\" or declared twice", k.n, p)
				return
			}
			seen[p] = true
		}
		p := Path{Patterns: pats}
		if f[0] == linePath {
			if _, ok := a.Roles[f[3]]; !ok {
				logf("app roles: line %d: %s does not declare role %q", k.n, a.Name, f[3])
				return
			}
			p.Role = f[3]
		} else {
			if f[3] == "" {
				logf("app roles: line %d: an open path needs a reason", k.n)
				return
			}
			p.Reason = f[3]
		}
		a.Paths = append(a.Paths, p)
	case lineCardPage:
		path, label := f[2], f[3]
		if !validPattern(path) || strings.Contains(path, "*") || label == "" {
			logf("app roles: line %d: a card page needs an exact path and a label", k.n)
			return
		}
		if d, ok := a.Decide(path); !ok || d.Role != UserRole {
			logf("app roles: line %d: card page %q is not under a path that needs the %q role in %s", k.n, path, UserRole, a.Name)
			return
		}
		for _, c := range a.CardPages {
			if c.Path == path {
				logf("app roles: line %d: card page %q declared twice", k.n, path)
				return
			}
		}
		a.CardPages = append(a.CardPages, CardPage{Path: path, Label: label})
	}
}

// ValidName reports whether s is a usable app or role name.
func ValidName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
