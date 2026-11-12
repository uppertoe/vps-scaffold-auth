package roles

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

func parseLogged(t *testing.T, lines ...string) (Manifest, []string) {
	t.Helper()
	var logs []string
	m := ParseManifest(strings.NewReader(strings.Join(lines, "\n")), "example.org", func(f string, a ...any) {
		logs = append(logs, fmt.Sprintf(f, a...))
	})
	return m, logs
}

func TestManifestKeywordLines(t *testing.T) {
	m, logs := parseLogged(t,
		// Keyword lines may come before the role lines they refer to.
		"@card-page\tenq\t/apply\tApply",
		"@label\tenq\tFellowship enquiries",
		"enq\tuser\tUser\tenq.{$DOMAIN}",
		"enq\tadmin\tAdministrator\tenq.{$DOMAIN}",
		"@source\tenq\tapps/fellows/fellows.caddy",
		"@open\tenq\t/ /faq\tRead before signing in",
		"@path\tenq\t/admin/*\tadmin",
		"@path\tenq\t*\tuser",
		"@card-page\tenq\t/admin/x\tAdmin page", // under the admin role: refused
		"@card-page\tenq\t/faq\tQuestions",      // open, not user: refused
		"@card-page\tenq\t/x*\tWildcard",        // not an exact path: refused
		"@path\tenq\t/admin/*\tuser",            // pattern declared twice
		"@path\tenq\t/z\tnobody",                // undeclared role
		"@path\tenq\t/a *\tuser",                // "*" mixed with others
		"@path\tenq\tnoslash\tuser",             // malformed pattern
		"@open\tenq\t/q\t",                      // open with no reason
		"@path\tghost\t*\tuser",                 // undeclared app
		"@bogus\tenq\tx",                        // unknown keyword
		"@source\tenq",                          // too few fields
		"@source\tenq\tagain.caddy",             // second source
	)
	a := m.Apps["enq"]
	if a == nil {
		t.Fatal("enq missing")
	}
	if a.Label != "Fellowship enquiries" || a.Source != "apps/fellows/fellows.caddy" {
		t.Errorf("label %q source %q", a.Label, a.Source)
	}
	if want := []string{"user", "admin"}; !reflect.DeepEqual(a.RoleOrder, want) {
		t.Errorf("role order %v, want %v", a.RoleOrder, want)
	}
	wantPaths := []Path{
		{Patterns: []string{"/", "/faq"}, Reason: "Read before signing in"},
		{Patterns: []string{"/admin/*"}, Role: "admin"},
		{Patterns: []string{"*"}, Role: "user"},
	}
	if !reflect.DeepEqual(a.Paths, wantPaths) {
		t.Errorf("paths %+v, want %+v", a.Paths, wantPaths)
	}
	if want := []CardPage{{Path: "/apply", Label: "Apply"}}; !reflect.DeepEqual(a.CardPages, want) {
		t.Errorf("card pages %+v, want %+v", a.CardPages, want)
	}
	if len(logs) != 12 {
		t.Errorf("logged %d problems, want 12:\n%s", len(logs), strings.Join(logs, "\n"))
	}
	if !a.Paths[0].Open() || a.Paths[1].Open() || !a.Paths[2].Rest() {
		t.Error("Open or Rest wrong")
	}
	if got := a.PathsFor("admin"); len(got) != 1 || got[0].Patterns[0] != "/admin/*" {
		t.Errorf("PathsFor(admin) = %+v", got)
	}
	if got := a.OpenPaths(); len(got) != 1 {
		t.Errorf("OpenPaths = %+v", got)
	}
}

func TestManifestDecide(t *testing.T) {
	m, _ := parseLogged(t,
		"r\tuser\tUser\tr.{$DOMAIN}",
		"r\tadmin\tAdministrator\tr.{$DOMAIN}",
		"@open\tr\t/admin/health /feeds/*\tProbes",
		"@path\tr\t/admin/*\tadmin",
		"@path\tr\t*\tuser",
	)
	a := m.Apps["r"]
	for path, want := range map[string]string{
		"/admin/x":      "admin",
		"/admin/health": "", // exact beats the prefix
		"/feeds/a":      "",
		"/":             "user",
		"/adminx":       "user",
	} {
		d, ok := a.Decide(path)
		if !ok || d.Role != want {
			t.Errorf("Decide(%q) = %+v %v, want role %q", path, d, ok, want)
		}
	}
	// Without a "*" line an unnamed path is decided by nothing, so no card
	// page can be checked against it.
	m, logs := parseLogged(t,
		"s\tuser\tUser\ts.{$DOMAIN}",
		"@path\ts\t/app/*\tuser",
		"@card-page\ts\t/other\tOther",
		"@card-page\ts\t/app/home\tHome",
	)
	if _, ok := m.Apps["s"].Decide("/other"); ok {
		t.Error("an unnamed path was decided with no * line")
	}
	if len(m.Apps["s"].CardPages) != 1 || len(logs) != 1 {
		t.Errorf("card pages %+v, logs %q", m.Apps["s"].CardPages, logs)
	}
}

func TestManifestRoleLinesUnchanged(t *testing.T) {
	// A manifest of role lines only, as phase 1 wrote it, reads as before:
	// no label, source, paths or card pages.
	m, logs := parseLogged(t, "caffeine\tuser\tUser\tcaffeine.{$DOMAIN}")
	a := m.Apps["caffeine"]
	if a == nil || len(logs) != 0 || a.Label != "caffeine" || a.Source != "" || a.Paths != nil || a.CardPages != nil {
		t.Errorf("app %+v logs %q", a, logs)
	}
}

func TestSampleManifestParsesCleanly(t *testing.T) {
	f, err := os.Open("../../deploy/app-roles.sample.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var logs []string
	m := ParseManifest(f, "example.org", func(fm string, a ...any) { logs = append(logs, fmt.Sprintf(fm, a...)) })
	if len(logs) != 0 {
		t.Errorf("the sample manifest logs problems: %q", logs)
	}
	if len(m.Apps) < 5 || m.Apps["enquiries"].Source == "" || len(m.Apps["handbook"].CardPages) != 3 {
		t.Errorf("sample manifest read as %+v", m.Apps)
	}
}
