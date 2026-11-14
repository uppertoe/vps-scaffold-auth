package server

import "testing"

func TestWithArticle(t *testing.T) {
	for domain, want := range map[string]string{
		"rch.org.au":        "an rch.org.au",
		"mcri.edu.au":       "an mcri.edu.au",
		"monashhealth.org":  "a monashhealth.org",
		"health.nsw.gov.au": "a health.nsw.gov.au",
		"alfred.org.au":     "an alfred.org.au",
		"svha.org.au":       "an svha.org.au",
		"unimelb.edu.au":    "a unimelb.edu.au",
		"petermac.org":      "a petermac.org",
		"uq.edu.au":         "a uq.edu.au",
	} {
		if got := withArticle(domain); got != want {
			t.Errorf("withArticle(%q) = %q, want %q", domain, got, want)
		}
	}
}
