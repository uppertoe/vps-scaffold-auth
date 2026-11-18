package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const readerToken = "0123456789abcdef0123456789abcdef-a"

func TestMemberReaders(t *testing.T) {
	setValid(t)
	t.Setenv("MEMBER_READER_TOKEN_TEACHING_CASES", readerToken)
	t.Setenv("MEMBER_READERS", "teaching-cases=teaching_cases_coordinators,Rch-Consultants,rch-consultants")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.MemberReaders) != 1 || c.MemberReaders[0].App != "teaching-cases" ||
		strings.Join(c.MemberReaders[0].Groups, " ") != "teaching_cases_coordinators rch-consultants" ||
		c.MembersListenAddr != DefaultMembersListenAddr {
		t.Fatalf("readers = %+v on %q", c.MemberReaders, c.MembersListenAddr)
	}
}

func TestMemberReadersOffByDefault(t *testing.T) {
	setValid(t)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.MemberReaders) != 0 || c.MembersListenAddr != "" {
		t.Fatalf("readers = %+v on %q", c.MemberReaders, c.MembersListenAddr)
	}
	// The alias is still set, so a gateway on a members network refuses
	// public connections there.
	if c.MembersAlias != "auth-members" || c.MembersReadersSet {
		t.Fatalf("alias %q, readers set %v", c.MembersAlias, c.MembersReadersSet)
	}
}

func TestMemberReadersRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		readers string
		env     map[string]string
		want    string
	}{
		"a base role":      {"app=admin", map[string]string{"MEMBER_READER_TOKEN_APP": readerToken}, "may not read"},
		"guest":            {"app=staff,guest", map[string]string{"MEMBER_READER_TOKEN_APP": readerToken}, "may not read"},
		"a capital role":   {"app=staff,Admin", map[string]string{"MEMBER_READER_TOKEN_APP": readerToken}, "may not read"},
		"no token":         {"app=staff", nil, "needs MEMBER_READER_TOKEN_APP"},
		"a short token":    {"app=staff", map[string]string{"MEMBER_READER_TOKEN_APP": "short-token-0123456789"}, "32+"},
		"a shared token":   {"app=staff two=staff", map[string]string{"MEMBER_READER_TOKEN_APP": readerToken, "MEMBER_READER_TOKEN_TWO": readerToken}, "share a token"},
		"no groups":        {"app=", map[string]string{"MEMBER_READER_TOKEN_APP": readerToken}, "want app=group"},
		"a bad group name": {"app=Staff!", map[string]string{"MEMBER_READER_TOKEN_APP": readerToken}, "may not read"},
		"listed twice":     {"app=a app=b", map[string]string{"MEMBER_READER_TOKEN_APP": readerToken}, "listed twice"},
		"the public port":  {"app=staff", map[string]string{"MEMBER_READER_TOKEN_APP": readerToken, "LISTEN_ADDR": ":8080", "MEMBERS_LISTEN_ADDR": "0.0.0.0:8080"}, "different port"},
		"the port by name": {"app=staff", map[string]string{"MEMBER_READER_TOKEN_APP": readerToken, "LISTEN_ADDR": ":80", "MEMBERS_LISTEN_ADDR": ":http"}, "different port"},
		"a padded port":    {"app=staff", map[string]string{"MEMBER_READER_TOKEN_APP": readerToken, "LISTEN_ADDR": ":8080", "MEMBERS_LISTEN_ADDR": ":08080"}, "different port"},
		"no port":          {"app=staff", map[string]string{"MEMBER_READER_TOKEN_APP": readerToken, "MEMBERS_LISTEN_ADDR": "auth"}, "needs a port"},
		"no network name":  {"app=staff", map[string]string{"MEMBER_READER_TOKEN_APP": readerToken, "MEMBERS_LISTEN_ADDR": ":8081"}, "needs the name"},
	} {
		t.Run(name, func(t *testing.T) {
			setValid(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			t.Setenv("MEMBER_READERS", tc.readers)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// writeReadersFile writes a member-readers manifest and points
// MEMBER_READERS_FILE at it.
func writeReadersFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "member-readers.tsv")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MEMBER_READERS_FILE", path)
	return path
}

// captureLogs collects what the member-readers code logs.
func captureLogs(t *testing.T) *[]string {
	t.Helper()
	var lines []string
	old := logPrintf
	logPrintf = func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	t.Cleanup(func() { logPrintf = old })
	return &lines
}

func readerGroups(c *Config) map[string]string {
	out := map[string]string{}
	for _, r := range c.MemberReaders {
		out[r.App] = strings.Join(r.Groups, " ")
	}
	return out
}

func TestMemberReadersFile(t *testing.T) {
	setValid(t)
	logs := captureLogs(t)
	t.Setenv("MEMBER_READER_TOKEN_TEACHING_CASES", readerToken)
	t.Setenv("MEMBER_READER_TOKEN_DIGEST", readerToken+"-digest")
	writeReadersFile(t, strings.Join([]string{
		"# rendered from the apps' scaffold-members markers",
		"",
		"   ",
		"teaching-cases\tteaching_cases_coordinators",
		"Teaching-Cases\tRCH-Consultants\r",
		"teaching-cases\tteaching_cases_coordinators", // a duplicate row
		"digest\treviewers",
		"digest\tadmin",            // a base role: skipped
		"digest\tguest",            // a base role: skipped
		"digest\tUser",             // a base role in capitals: skipped
		"digest reviewers",         // no tab: skipped
		"digest\treviewers\textra", // three fields: skipped
		"bad app!\treviewers",      // a bad app name: skipped
		"digest\tBad Group",        // a bad group name: skipped
		"",
	}, "\n"))
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	got := readerGroups(c)
	if len(got) != 2 || got["teaching-cases"] != "teaching_cases_coordinators rch-consultants" || got["digest"] != "reviewers" {
		t.Fatalf("readers = %v", got)
	}
	if c.MembersListenAddr != DefaultMembersListenAddr || len(c.UnusableMemberReaders) != 0 {
		t.Fatalf("listen %q, unusable %+v", c.MembersListenAddr, c.UnusableMemberReaders)
	}
	if n := len(*logs); n != 7 {
		t.Errorf("logged %d lines, want one per skipped row: %q", n, *logs)
	}
	for _, l := range *logs {
		if !strings.HasPrefix(l, "ERROR member readers:") || !strings.Contains(l, "skipped") {
			t.Errorf("log line %q", l)
		}
	}
}

// An app in MEMBER_READERS keeps exactly its groups there: the file's rows
// for it are ignored, and any group only the file names is listed as refused.
// An app only in the file keeps its own groups.
func TestMemberReadersEnvDecidesAnAppInBoth(t *testing.T) {
	setValid(t)
	logs := captureLogs(t)
	t.Setenv("MEMBER_READER_TOKEN_DIGEST", readerToken)
	t.Setenv("MEMBER_READER_TOKEN_ROSTER", readerToken+"-roster")
	t.Setenv("MEMBER_READER_TOKEN_PLANNER", readerToken+"-planner")
	t.Setenv("MEMBER_READERS", "digest=coordinators,leads roster=fellows")
	writeReadersFile(t, "digest\tleads\ndigest\texecutive\ndigest\tadmins\nroster\tfellows\nplanner\tconsultants\n")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	got := readerGroups(c)
	if len(got) != 3 || got["digest"] != "coordinators leads" || got["roster"] != "fellows" || got["planner"] != "consultants" {
		t.Fatalf("readers = %v", got)
	}
	if len(c.UnusableMemberReaders) != 1 || c.UnusableMemberReaders[0].App != "digest" ||
		strings.Join(c.UnusableMemberReaders[0].Groups, " ") != "executive admins" || c.UnusableMemberReaders[0].Problem != ProblemEnvWins {
		t.Fatalf("unusable = %+v", c.UnusableMemberReaders)
	}
	// One line for each app in both: digest names the ignored groups, and
	// roster, whose rows add nothing, is still noted.
	if len(*logs) != 2 || !strings.Contains((*logs)[0], "executive, admins") || !strings.Contains((*logs)[1], `"roster"`) {
		t.Errorf("logs = %q", *logs)
	}
}

// A token must have more than eight distinct characters and must not be any
// of the gateway's other secrets. A token that fails leaves its app without
// access, from either setting, and never stops the gateway.
func TestMemberReadersWeakTokens(t *testing.T) {
	setValid(t)
	logs := captureLogs(t)
	t.Setenv("RESEND_API_KEY", "re_0123456789abcdefghijklmnopqrstuvwxyz")
	t.Setenv("MEMBER_READER_TOKEN_REPEAT", strings.Repeat("a", 40))             // env, too simple
	t.Setenv("MEMBER_READER_TOKEN_EIGHT", strings.Repeat("abcdefgh", 5))        // file, eight symbols
	t.Setenv("MEMBER_READER_TOKEN_SESSION", "0123456789abcdef0123456789abcdef") // SESSION_SECRET
	t.Setenv("MEMBER_READER_TOKEN_RESEND", "re_0123456789abcdefghijklmnopqrstuvwxyz")
	t.Setenv("MEMBER_READER_TOKEN_NINE", strings.Repeat("abcdefghi", 4)) // nine symbols: enough
	t.Setenv("MEMBER_READERS", "repeat=staff session=staff")
	writeReadersFile(t, "eight\tstaff\nresend\tstaff\nnine\tstaff\n")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := readerGroups(c); len(got) != 1 || got["nine"] != "staff" {
		t.Fatalf("readers = %v", got)
	}
	want := map[string]string{
		"repeat":  ProblemSimpleToken,
		"eight":   ProblemSimpleToken,
		"session": ProblemSecretToken,
		"resend":  ProblemSecretToken,
	}
	if len(c.UnusableMemberReaders) != len(want) {
		t.Fatalf("unusable = %+v", c.UnusableMemberReaders)
	}
	for _, u := range c.UnusableMemberReaders {
		if want[u.App] != u.Problem {
			t.Errorf("%s: problem %q, want %q", u.App, u.Problem, want[u.App])
		}
	}
	if len(*logs) != len(want) {
		t.Errorf("logs = %q", *logs)
	}
	for _, l := range *logs {
		if strings.Contains(l, "0123456789abcdef") || strings.Contains(l, "re_0123") {
			t.Errorf("a secret reached the log: %q", l)
		}
	}
}

// The file and MEMBER_READERS accept exactly the gateway's own group names:
// lower case after lower-casing, letters, digits, "-" and "_", no dots.
func TestMemberReadersGroupGrammar(t *testing.T) {
	setValid(t)
	captureLogs(t)
	t.Setenv("MEMBER_READER_TOKEN_DIGEST", readerToken)
	writeReadersFile(t, "digest\t_leads\ndigest\tnight-shift.v2\ndigest\tRCH-Registrars\n")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := readerGroups(c); got["digest"] != "_leads rch-registrars" {
		t.Fatalf("readers = %v", got)
	}
	setValid(t)
	t.Setenv("MEMBER_READERS_FILE", "")
	t.Setenv("MEMBER_READERS", "digest=night-shift.v2")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "may not read") {
		t.Fatalf("err = %v", err)
	}
}

// The members alias is set whenever either setting is, even with no usable
// reader, so the public listener always refuses the members networks. With
// readers only from the file, a bad MEMBERS_LISTEN_ADDR is logged, not
// fatal, and the gateway runs without the members listener.
func TestMembersListenFromTheFile(t *testing.T) {
	for name, tc := range map[string]struct {
		addr, listen, alias string
	}{
		"default":         {"", DefaultMembersListenAddr, "auth-members"},
		"no host":         {":8081", "", "auth-members"},
		"no port":         {"auth", "", "auth-members"},
		"the public port": {"members:8080", "", "members"},
	} {
		t.Run(name, func(t *testing.T) {
			setValid(t)
			logs := captureLogs(t)
			t.Setenv("LISTEN_ADDR", ":8080")
			if tc.addr != "" {
				t.Setenv("MEMBERS_LISTEN_ADDR", tc.addr)
			}
			writeReadersFile(t, "# no apps yet\n")
			c, err := Load()
			if err != nil {
				t.Fatal(err)
			}
			if c.MembersListenAddr != tc.listen || c.MembersAlias != tc.alias || c.MembersRequired {
				t.Fatalf("listen %q alias %q required %v", c.MembersListenAddr, c.MembersAlias, c.MembersRequired)
			}
			if (tc.listen == "") != (len(*logs) == 1) {
				t.Errorf("logs = %q", *logs)
			}
		})
	}
}

// A problem with the file never stops the gateway: a missing file is logged
// and the environment's readers still apply.
func TestMemberReadersFileMissing(t *testing.T) {
	setValid(t)
	logs := captureLogs(t)
	t.Setenv("MEMBER_READER_TOKEN_DIGEST", readerToken)
	t.Setenv("MEMBER_READERS", "digest=coordinators")
	t.Setenv("MEMBER_READERS_FILE", filepath.Join(t.TempDir(), "absent.tsv"))
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := readerGroups(c); len(got) != 1 || got["digest"] != "coordinators" || c.MembersListenAddr == "" {
		t.Fatalf("readers = %v on %q", got, c.MembersListenAddr)
	}
	// An unreadable file must never clear approvals.
	if c.MemberReadersFileRead || strings.Join(c.MemberReadersEnvApps, " ") != "digest" {
		t.Fatalf("file read %v, env apps %v", c.MemberReadersFileRead, c.MemberReadersEnvApps)
	}
	if len(*logs) != 1 || !strings.Contains((*logs)[0], "ERROR member readers") || !strings.Contains((*logs)[0], "absent.tsv") {
		t.Errorf("logs = %q", *logs)
	}

	// With nothing else configured, a missing file leaves no reader, but
	// the members alias is still refused on the public listener.
	setValid(t)
	t.Setenv("MEMBER_READERS", "")
	c, err = Load()
	if err != nil || len(c.MemberReaders) != 0 || c.MembersAlias != "auth-members" {
		t.Fatalf("readers = %+v on %q, %v", c.MemberReaders, c.MembersAlias, err)
	}
}

// An app the file lists without a usable token is left without access and
// logged once, naming the variable it needs; the gateway still starts, the
// other apps keep their access, and the listener runs so that its reads are
// refused as an unknown token.
func TestMemberReadersFileAppWithoutToken(t *testing.T) {
	setValid(t)
	logs := captureLogs(t)
	t.Setenv("MEMBER_READER_TOKEN_DIGEST", readerToken)
	t.Setenv("MEMBER_READER_TOKEN_SHORT_ONE", "short-token-0123456789")
	t.Setenv("MEMBER_READER_TOKEN_COPY", readerToken)           // the same as digest's
	t.Setenv("MEMBER_READER_TOKEN_TWIN_A", readerToken+"-twin") // two file apps share
	t.Setenv("MEMBER_READER_TOKEN_TWIN_B", readerToken+"-twin") // this token
	t.Setenv("MEMBER_READERS", "digest=coordinators")
	writeReadersFile(t, "teaching-cases\tcoordinators\nteaching-cases\tleads\nshort-one\treviewers\ncopy\treviewers\ntwin-a\tleads\ntwin-b\tleads\n")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := readerGroups(c); len(got) != 1 || got["digest"] != "coordinators" {
		t.Fatalf("readers = %v", got)
	}
	if c.MembersListenAddr != DefaultMembersListenAddr {
		t.Fatalf("listen %q", c.MembersListenAddr)
	}
	// The file was read, and every app it lists counts for its approvals,
	// usable or not.
	if !c.MemberReadersFileRead || strings.Join(c.MemberReadersFilePairs["teaching-cases"], " ") != "coordinators leads" {
		t.Fatalf("file read %v, pairs %v", c.MemberReadersFileRead, c.MemberReadersFilePairs)
	}
	want := map[string]string{
		"copy":           "MEMBER_READER_TOKEN_COPY",
		"short-one":      "MEMBER_READER_TOKEN_SHORT_ONE",
		"teaching-cases": "MEMBER_READER_TOKEN_TEACHING_CASES",
		"twin-a":         "MEMBER_READER_TOKEN_TWIN_A",
		"twin-b":         "MEMBER_READER_TOKEN_TWIN_B",
	}
	if len(c.UnusableMemberReaders) != len(want) {
		t.Fatalf("unusable = %+v", c.UnusableMemberReaders)
	}
	for _, u := range c.UnusableMemberReaders {
		if want[u.App] != u.TokenEnv || u.Problem == "" {
			t.Errorf("unusable %+v", u)
		}
		if u.App == "teaching-cases" && strings.Join(u.Groups, " ") != "coordinators leads" {
			t.Errorf("teaching-cases groups = %v", u.Groups)
		}
	}
	if len(*logs) != len(want) {
		t.Fatalf("logs = %q", *logs)
	}
	for _, l := range *logs {
		if !strings.HasPrefix(l, "ERROR member readers:") || !strings.Contains(l, "MEMBER_READER_TOKEN_") {
			t.Errorf("log line %q", l)
		}
	}

	// Only an app without a token: the endpoint still runs, and answers it
	// as an unknown token.
	setValid(t)
	t.Setenv("MEMBER_READERS", "")
	writeReadersFile(t, "teaching-cases\tcoordinators\n")
	c, err = Load()
	if err != nil || len(c.MemberReaders) != 0 || len(c.UnusableMemberReaders) != 1 || c.MembersListenAddr != DefaultMembersListenAddr {
		t.Fatalf("readers = %+v, unusable %+v on %q, %v", c.MemberReaders, c.UnusableMemberReaders, c.MembersListenAddr, err)
	}
}

// Problems in MEMBER_READERS itself still stop the gateway, with the file set.
func TestMemberReadersEnvStillRefusedWithFile(t *testing.T) {
	setValid(t)
	captureLogs(t)
	writeReadersFile(t, "digest\tcoordinators\n")
	t.Setenv("MEMBER_READERS", "app=staff")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "needs MEMBER_READER_TOKEN_APP") {
		t.Fatalf("err = %v", err)
	}
}
