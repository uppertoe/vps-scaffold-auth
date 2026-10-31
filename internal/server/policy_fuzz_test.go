package server

import (
	"strings"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
)

// FuzzParsePolicy: a rule header the gateway accepts admits a signed-in
// person who matches no domain and no group only if the header says "any" as
// a field of its own. Any other value that would collapse to "any signed-in
// user" (an empty list, a misspelt field, stray separators) must be refused.
func FuzzParsePolicy(f *testing.F) {
	for _, s := range []string{
		"any", "any;guests=allow", "domains=rch.org.au", "groups=admin", "domains=a.org;groups=b",
		"", ";", "domains=", "groups= ", "gruops=admin", "any;domains=a.org", "Any", "any ",
		"guests=allow", "guests=yes;any", "domains=a.org;;", "mode=any", "any=1", "anyway",
		"domains=a.org;domains=", "groups=admin;gruops=x",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, h string) {
		domains, groups, _, ok := parsePolicy(h)
		if !ok {
			return
		}
		sawAny := false
		for _, field := range strings.Split(h, ";") {
			if strings.TrimSpace(field) == "any" {
				sawAny = true
			}
		}
		// A stranger to every list: an address at a domain no rule names, in no
		// group a rule could name.
		admitted := authz.CanAccessApp("nobody@unlisted.invalid", "user", false, false, domains, groups, false)
		if admitted && !sawAny {
			t.Fatalf("policy %q admits anyone signed in, but does not say \"any\" (domains %q, groups %q)", h, domains, groups)
		}
		if sawAny && (domains != "" || groups != "") {
			t.Fatalf("policy %q combines any with a list and was accepted", h)
		}
	})
}
