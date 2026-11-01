package config

import "testing"

func TestParseGroupFeeds(t *testing.T) {
	t.Setenv("GROUP_FEED_TOKEN_RCH_CONSULTANTS", "0123456789abcdef0123")
	feeds, err := parseGroupFeeds("rch-consultants=https://roster.example.org/feeds/consultants.json", false)
	if err != nil || len(feeds) != 1 || feeds[0].Group != "rch-consultants" || feeds[0].Token == "" {
		t.Fatalf("feeds = %+v, err = %v", feeds, err)
	}
	bad := []struct {
		raw  string
		http bool
	}{
		{"rch-consultants=http://roster.example.org/x", false},          // plain http
		{"rch-consultants=https://user:pw@roster.example.org/x", false}, // userinfo
		{"admin=https://roster.example.org/x", false},                   // reserved
		{"Bad Name=https://roster.example.org/x", false},                // splits into junk
		{"no-token=https://roster.example.org/x", false},                // token missing
		{"rch-consultants=https://a.example.org/x rch-consultants=https://b.example.org/x", false},
	}
	for _, b := range bad {
		if _, err := parseGroupFeeds(b.raw, b.http); err == nil {
			t.Errorf("accepted %q", b.raw)
		}
	}
	if _, err := parseGroupFeeds("rch-consultants=http://roster.localhost/x", true); err != nil {
		t.Errorf("http refused in dev: %v", err)
	}
}

func TestFeedAlertToken(t *testing.T) {
	setValid(t)
	t.Setenv("GROUP_FEED_ALERT_TOKEN", "tk_abc")
	if _, err := Load(); err == nil {
		t.Error("token without a URL was accepted")
	}
	t.Setenv("GROUP_FEED_ALERT_URL", "https://ntfy.example.com/alerts")
	c, err := Load()
	if err != nil || c.FeedAlertToken != "tk_abc" {
		t.Fatalf("token with URL = %+v, %v", c, err)
	}
	t.Setenv("GROUP_FEED_ALERT_TOKEN", "tk_a bc")
	if _, err := Load(); err == nil {
		t.Error("token with whitespace was accepted")
	}
}
