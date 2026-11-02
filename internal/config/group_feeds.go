package config

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// GroupFeed is a gateway group whose members come from an endpoint (for
// example the consultants roster published by roster-insights). Feeds are
// configured here, on the server, and never from the admin pages, so nobody
// can point the gateway at an arbitrary address from a browser.
type GroupFeed struct {
	Group string // the gateway group the feed fills
	URL   string // https endpoint returning a JSON list of addresses
	Token string // bearer token sent to the endpoint
	// Rotating marks a group whose members are replaced wholesale at a
	// changeover (registrars, fellows), named in GROUP_FEED_ROTATING. A
	// change that empties most of the group, or doubles it, is normal there,
	// so it waits out GROUP_FEED_AUTO_APPLY_AFTER like any other held change
	// instead of waiting for an administrator.
	Rotating bool
}

var feedGroupName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// FeedTokenEnv is the environment variable holding a feed's bearer token:
// GROUP_FEED_TOKEN_ plus the group name upper-cased with "-" as "_".
func FeedTokenEnv(group string) string {
	return "GROUP_FEED_TOKEN_" + strings.ToUpper(strings.ReplaceAll(group, "-", "_"))
}

// parseGroupFeeds reads GROUP_FEEDS: whitespace-separated "group=url" pairs.
// Each feed needs its token in FeedTokenEnv(group). Plain http is accepted
// only when allowHTTP is set (development, COOKIE_INSECURE).
func parseGroupFeeds(raw string, allowHTTP bool) ([]GroupFeed, error) {
	var out []GroupFeed
	seen := map[string]bool{}
	for _, entry := range strings.Fields(raw) {
		group, rawURL, ok := strings.Cut(entry, "=")
		group = strings.ToLower(strings.TrimSpace(group))
		if !ok || group == "" || rawURL == "" {
			return nil, fmt.Errorf("GROUP_FEEDS entry %q: want group=url", entry)
		}
		if !feedGroupName.MatchString(group) || group == "admin" || group == "user" || group == "guest" {
			return nil, fmt.Errorf("GROUP_FEEDS: %q is not a usable group name", group)
		}
		if seen[group] {
			return nil, fmt.Errorf("GROUP_FEEDS: group %q listed twice", group)
		}
		u, err := url.Parse(rawURL)
		if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && !(allowHTTP && u.Scheme == "http")) {
			return nil, fmt.Errorf("GROUP_FEEDS: feed for %q needs an https URL", group)
		}
		token := strings.TrimSpace(os.Getenv(FeedTokenEnv(group)))
		if len(token) < 16 {
			return nil, fmt.Errorf("GROUP_FEEDS: feed for %q needs %s (16+ characters)", group, FeedTokenEnv(group))
		}
		seen[group] = true
		out = append(out, GroupFeed{Group: group, URL: u.String(), Token: token})
	}
	return out, nil
}

// DefaultFeedInterval is how often feeds are fetched unless
// GROUP_FEED_INTERVAL says otherwise.
const DefaultFeedInterval = time.Hour
