package config

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// MemberReader is an app allowed to ask the gateway who is in some groups,
// for work it does outside a request (a weekly digest, say). Readers are
// configured here, on the server, and never from the admin pages.
type MemberReader struct {
	App    string   // the app's name, used in the audit
	Token  string   // bearer token the app sends
	Groups []string // the groups the app may read
}

// MemberReaderTokenEnv is the environment variable holding a reader's token:
// MEMBER_READER_TOKEN_ plus the app name upper-cased with "-" as "_".
func MemberReaderTokenEnv(app string) string {
	return "MEMBER_READER_TOKEN_" + strings.ToUpper(strings.ReplaceAll(app, "-", "_"))
}

// DefaultMembersListenAddr is where the members endpoint listens when
// MEMBER_READERS is set and MEMBERS_LISTEN_ADDR is not. Caddy proxies only
// LISTEN_ADDR, so this port is reachable only from the Docker network.
const DefaultMembersListenAddr = "auth-members:8081"

// parseMemberReaders reads MEMBER_READERS: whitespace-separated
// "app=group,group" entries. Each app needs its token in
// MemberReaderTokenEnv(app), 32 or more characters, and no two apps may share
// a token. The base roles can never be read.
func parseMemberReaders(raw string) ([]MemberReader, error) {
	var out []MemberReader
	seenApp := map[string]bool{}
	seenToken := map[string]string{}
	for _, entry := range strings.Fields(raw) {
		app, groups, ok := strings.Cut(entry, "=")
		app = strings.ToLower(strings.TrimSpace(app))
		if !ok || app == "" || groups == "" {
			return nil, fmt.Errorf("MEMBER_READERS entry %q: want app=group,group", entry)
		}
		if !feedGroupName.MatchString(app) {
			return nil, fmt.Errorf("MEMBER_READERS: %q is not a usable app name", app)
		}
		if seenApp[app] {
			return nil, fmt.Errorf("MEMBER_READERS: app %q listed twice", app)
		}
		r := MemberReader{App: app}
		seenGroup := map[string]bool{}
		for _, g := range strings.Split(groups, ",") {
			g = strings.ToLower(strings.TrimSpace(g))
			if !feedGroupName.MatchString(g) || g == "admin" || g == "user" || g == "guest" {
				return nil, fmt.Errorf("MEMBER_READERS: %q may not read %q", app, g)
			}
			if !seenGroup[g] {
				seenGroup[g] = true
				r.Groups = append(r.Groups, g)
			}
		}
		r.Token = strings.TrimSpace(os.Getenv(MemberReaderTokenEnv(app)))
		if len(r.Token) < 32 {
			return nil, fmt.Errorf("MEMBER_READERS: %q needs %s (32+ characters)", app, MemberReaderTokenEnv(app))
		}
		if other, dup := seenToken[r.Token]; dup {
			return nil, fmt.Errorf("MEMBER_READERS: %q and %q share a token; give each app its own", other, app)
		}
		seenApp[app], seenToken[r.Token] = true, app
		out = append(out, r)
	}
	return out, nil
}

// sameListener reports whether two listen addresses would share a port, so
// the members endpoint can never be served where Caddy proxies.
func sameListener(a, b string) bool {
	return listenPort(a) != 0 && listenPort(a) == listenPort(b)
}

// listenPort is the port number of a listen address (":http" is 80,
// "08080" is 8080), or 0 if it has none.
func listenPort(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, err := net.LookupPort("tcp", p)
	if err != nil {
		return 0
	}
	return n
}
