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

// App is one app in the manifest: its roles (role -> label) and its hosts.
type App struct {
	Name  string
	Roles map[string]string
	Hosts []string
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

// ParseManifest reads the app-roles manifest: one role per line,
// "app<TAB>role<TAB>label<TAB>hosts", hosts comma-separated, with {$DOMAIN}
// replaced by domain. Blank lines and # comments are skipped. A malformed line
// is logged and skipped, and an app without a user role is logged and left
// out entirely, so a guard naming it is refused rather than half-decided.
func ParseManifest(r io.Reader, domain string, logf func(format string, args ...any)) Manifest {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	apps := map[string]*App{}
	hosts := map[string]map[string]struct{}{}
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		f := strings.Split(line, "\t")
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
			a = &App{Name: app, Roles: map[string]string{}}
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
	}
	return Manifest{Apps: apps}
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
