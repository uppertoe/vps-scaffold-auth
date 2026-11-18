package config

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
)

// MemberReader is an app allowed to ask the gateway who is in some groups,
// for work it does outside a request (a weekly digest, say). Readers are
// configured here, on the server, and never from the admin pages.
type MemberReader struct {
	App    string   // the app's name, used in the audit
	Token  string   // bearer token the app sends
	Groups []string // the groups the app may read
	// FromFile is true for an app from MEMBER_READERS_FILE: each of its
	// groups is served only once an administrator has approved the pair on
	// the Member readers page. An app in MEMBER_READERS is operator-reviewed and
	// needs no approval.
	FromFile bool
}

// UnusableMemberReader is a read the gateway refuses that the Member readers page
// lists: an app without a usable token, whose every read is refused as an
// unknown token, or (Problem ProblemEnvWins) an app in MEMBER_READERS whose
// readers-file rows name groups MEMBER_READERS does not, which it may not
// read.
type UnusableMemberReader struct {
	App      string
	Groups   []string
	TokenEnv string // the environment variable the app's token belongs in
	Problem  string // why the token cannot be used, as a sentence
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
			if !authz.ValidGroupName(g) || authz.IsReservedGroup(g) {
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

// readMemberReadersFile reads MEMBER_READERS_FILE, the scaffold-rendered list
// of the groups each app may read: one "app<TAB>group" row per line, with
// blank lines and lines starting with "#" skipped. It returns each app's
// groups in file order, without repeats, the apps in file order, and whether
// the whole file was read.
//
// Like the other rendered manifests (APP_ROLES_FILE, ROUTE_GROUPS_FILE), the
// file never stops the gateway from starting: a missing or unreadable file is
// logged and read as empty, and a malformed row, a bad name or a base role is
// logged and skipped. A gateway that refused to start would take sign-in away
// from every app on the server.
func readMemberReadersFile(path string, logf func(string, ...any)) (map[string][]string, []string, bool) {
	groups := map[string][]string{}
	var order []string
	if path == "" {
		return groups, nil, false
	}
	f, err := os.Open(path)
	if err != nil {
		logf("ERROR member readers: %v; no app may read group members through MEMBER_READERS_FILE until the file can be read", err)
		return groups, nil, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 2 {
			logf("ERROR member readers: %s line %d: want app<TAB>group; the line is skipped", path, n)
			continue
		}
		app := strings.ToLower(strings.TrimSpace(fields[0]))
		g := strings.ToLower(strings.TrimSpace(fields[1]))
		if !feedGroupName.MatchString(app) {
			logf("ERROR member readers: %s line %d: %q is not a usable app name; the line is skipped", path, n, app)
			continue
		}
		if !authz.ValidGroupName(g) || authz.IsReservedGroup(g) {
			logf("ERROR member readers: %s line %d: %q may not read %q; the line is skipped", path, n, app, g)
			continue
		}
		if _, seen := groups[app]; !seen {
			order = append(order, app)
		}
		if !containsString(groups[app], g) {
			groups[app] = append(groups[app], g)
		}
	}
	if err := sc.Err(); err != nil {
		logf("ERROR member readers: reading %s: %v; the rows before the problem are used", path, err)
		return groups, order, false
	}
	return groups, order, true
}

// Problems shown on the Member readers page for an app whose reads the gateway
// refuses (see UnusableMemberReader).
const (
	ProblemNoToken      = "The gateway has no token for this app."
	ProblemShortToken   = "The token is shorter than 32 characters."
	ProblemSimpleToken  = "The token is too simple; use 32 or more random characters, such as the output of openssl rand -hex 32."
	ProblemSecretToken  = "The token is the same as another of the gateway's secrets; each app needs its own."
	ProblemEnvWins      = "This app is also listed in MEMBER_READERS, which decides its groups; the rows in the readers file were ignored."
	problemSharedFormat = "The token is the same as the token for %s; each app needs its own."
)

// minTokenSymbols is the fewest distinct characters a reader's token may
// have: more than eight. A token from openssl rand -hex 32 has sixteen; a
// typed or repeated string fails.
const minTokenSymbols = 9

// tokenProblem returns why a reader's token cannot be used, or "" when it
// can. secrets are the gateway's other secrets, which no token may equal.
func tokenProblem(token string, secrets []string) string {
	switch {
	case token == "":
		return ProblemNoToken
	case len(token) < 32:
		return ProblemShortToken
	case distinctBytes([]byte(token)) < minTokenSymbols:
		return ProblemSimpleToken
	}
	for _, s := range secrets {
		if s != "" && s == token {
			return ProblemSecretToken
		}
	}
	return ""
}

// mergeMemberReaders combines the readers from MEMBER_READERS (env) with the
// apps from MEMBER_READERS_FILE.
//
// An app in MEMBER_READERS keeps exactly the groups listed there: that entry
// is the reviewed scope, so the file's rows for the app are ignored, logged,
// and listed on the Member readers page. An app only in the file needs its token as
// an app in MEMBER_READERS does. Every token, from either source, must also
// pass tokenProblem; an app whose token does not is left without access,
// logged once and listed on the Member readers page, and is never fatal, so the
// other apps and sign-in carry on. (MEMBER_READERS's own checks, a token of
// 32 or more characters that no other app in it shares, stay fatal in
// parseMemberReaders.)
func mergeMemberReaders(env []MemberReader, fileGroups map[string][]string, order []string, secrets []string, logf func(string, ...any)) ([]MemberReader, []UnusableMemberReader) {
	var out []MemberReader
	var unusable []UnusableMemberReader
	refuse := func(r MemberReader, problem string) {
		unusable = append(unusable, UnusableMemberReader{App: r.App, Groups: r.Groups, TokenEnv: MemberReaderTokenEnv(r.App), Problem: problem})
	}
	inEnv := map[string]bool{}
	tokenOwner := map[string]string{}
	for _, r := range env {
		inEnv[r.App] = true
		tokenOwner[r.Token] = r.App
		if p := tokenProblem(r.Token, secrets); p != "" {
			refuse(r, p)
			continue
		}
		out = append(out, r)
	}
	var notes []UnusableMemberReader // apps in both: informational rows
	var added []MemberReader
	for _, app := range order {
		if inEnv[app] {
			var envGroups []string
			for _, r := range env {
				if r.App == app {
					envGroups = r.Groups
				}
			}
			var extra []string
			for _, g := range fileGroups[app] {
				if !containsString(envGroups, g) {
					extra = append(extra, g)
				}
			}
			if len(extra) == 0 {
				logf("ERROR member readers: %q is listed in both MEMBER_READERS and MEMBER_READERS_FILE; MEMBER_READERS decides its groups, and the file's rows for it were ignored", app)
				continue
			}
			logf("ERROR member readers: %q is listed in both MEMBER_READERS and MEMBER_READERS_FILE; MEMBER_READERS decides its groups, so the gateway refuses its reads of %s, which only the file lists",
				app, strings.Join(extra, ", "))
			notes = append(notes, UnusableMemberReader{App: app, Groups: extra, TokenEnv: MemberReaderTokenEnv(app), Problem: ProblemEnvWins})
			continue
		}
		r := MemberReader{App: app, Groups: fileGroups[app], FromFile: true}
		r.Token = strings.TrimSpace(os.Getenv(MemberReaderTokenEnv(app)))
		if p := tokenProblem(r.Token, secrets); p != "" {
			refuse(r, p)
			continue
		}
		added = append(added, r)
	}
	// No two apps may share a token. An app from the file whose token another
	// app also has is left out, as is the other app when it too comes only
	// from the file; an app in MEMBER_READERS keeps its access.
	count := map[string]int{}
	for _, r := range added {
		count[r.Token]++
	}
	for _, r := range added {
		other, envOwner := tokenOwner[r.Token]
		if envOwner || count[r.Token] > 1 {
			if !envOwner {
				var names []string
				for _, o := range added {
					if o.Token == r.Token && o.App != r.App {
						names = append(names, o.App)
					}
				}
				sort.Strings(names)
				other = strings.Join(names, ", ")
			}
			refuse(r, fmt.Sprintf(problemSharedFormat, other))
			continue
		}
		out = append(out, r)
	}
	sort.SliceStable(unusable, func(i, j int) bool { return unusable[i].App < unusable[j].App })
	for _, u := range unusable {
		logf("ERROR member readers: the gateway refuses reads from %q. %s Set %s to 32 or more random characters that no other app or setting uses, such as the output of openssl rand -hex 32, then recreate the gateway.",
			u.App, u.Problem, u.TokenEnv)
	}
	return out, append(unusable, notes...)
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// logPrintf is the logger the file reading uses; tests replace it.
var logPrintf = log.Printf
