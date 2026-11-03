package config

import (
	"testing"
	"time"
)

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

func TestFeedAutoApplyAfter(t *testing.T) {
	setValid(t)
	if c, err := Load(); err != nil || c.FeedAutoApplyAfter != 0 {
		t.Fatalf("default = %v, %v; want off", c.FeedAutoApplyAfter, err)
	}
	t.Setenv("GROUP_FEED_AUTO_APPLY_AFTER", "12h")
	if c, err := Load(); err != nil || c.FeedAutoApplyAfter != 12*time.Hour {
		t.Fatalf("12h = %v, %v", c.FeedAutoApplyAfter, err)
	}
	for _, v := range []string{"30m", "0", "soon", "-1h"} {
		t.Setenv("GROUP_FEED_AUTO_APPLY_AFTER", v)
		if _, err := Load(); err == nil {
			t.Errorf("GROUP_FEED_AUTO_APPLY_AFTER=%q accepted", v)
		}
	}
}

func TestFeedRotating(t *testing.T) {
	setValid(t)
	t.Setenv("GROUP_FEED_TOKEN_RCH_REGISTRARS", "0123456789abcdef0123")
	t.Setenv("GROUP_FEED_TOKEN_RCH_CONSULTANTS", "0123456789abcdef0123")
	t.Setenv("GROUP_FEEDS", "rch-registrars=https://roster.example.org/r.json rch-consultants=https://roster.example.org/c.json")
	t.Setenv("GROUP_FEED_ROTATING", "rch-registrars")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range c.GroupFeeds {
		if f.Rotating != (f.Group == "rch-registrars") {
			t.Errorf("%s rotating = %v", f.Group, f.Rotating)
		}
	}
	t.Setenv("GROUP_FEED_ROTATING", "rch-registrars rch-fellows")
	if _, err := Load(); err == nil {
		t.Error("a rotating group with no feed was accepted")
	}
}
