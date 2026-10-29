package server

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
)

// requestFrom posts /request for email as if from ip (Caddy's X-Forwarded-For).
func requestFrom(c *client, ip, email string) {
	c.postWith("/request", url.Values{"email": {email}}, map[string]string{"X-Forwarded-For": ip})
}

// sentCount drains and counts the emails sent so far.
func sentCount(s *captureSender) int {
	n := 0
	deadline := time.After(300 * time.Millisecond)
	for {
		select {
		case <-s.sent:
			n++
		case <-deadline:
			return n
		}
	}
}

// Many people signing in correctly behind one address (a hospital NAT) are
// never throttled by the wrong-code limit: a correct code is refunded.
func TestCorrectCodesBehindOneAddressAreFree(t *testing.T) {
	srv, sender := testServerWith(t, func(c *config.Config) {
		c.RateLimitWrongCodesPerIP = config.RateLimit{Count: 2, Window: time.Hour}
	})
	for _, who := range []string{"a@example.com", "b@example.com", "c@example.com", "d@example.com", "e@example.com"} {
		loginAs(t, newClient(t, srv.Handler()), sender, who, nil)
	}
}

// Wrong codes from one address are still limited.
func TestWrongCodesLimitedPerAddress(t *testing.T) {
	srv, _ := testServerWith(t, func(c *config.Config) {
		c.RateLimitWrongCodesPerIP = config.RateLimit{Count: 2, Window: time.Hour}
	})
	c := newClient(t, srv.Handler())
	c.postForm("/request", url.Values{"email": {"user@example.com"}})
	for i, want := range []int{http.StatusUnauthorized, http.StatusUnauthorized, http.StatusTooManyRequests} {
		if got := c.postForm("/verify-code", url.Values{"code": {"00000000"}}).Code; got != want {
			t.Errorf("wrong code %d: status %d, want %d", i+1, got, want)
		}
	}
}

// A stranger who spends the send allowance for an address from their own IP
// does not stop the owner, elsewhere, receiving a code.
func TestStrangerCannotSpendOwnersSendAllowance(t *testing.T) {
	srv, sender := testServerWith(t, func(c *config.Config) {
		c.RateLimitPerEmail = config.RateLimit{Count: 2, Window: time.Hour}
		c.OTPResendCooldown = 0
	})
	attacker := newClient(t, srv.Handler())
	for i := 0; i < 4; i++ {
		requestFrom(attacker, "198.51.100.7", "victim@example.com")
	}
	if n := sentCount(sender); n != 2 {
		t.Fatalf("stranger triggered %d emails, want 2", n)
	}
	requestFrom(newClient(t, srv.Handler()), "203.0.113.9", "victim@example.com")
	if n := sentCount(sender); n != 1 {
		t.Errorf("owner's own request sent %d emails, want 1", n)
	}
}

// The per-address ceiling bounds a flood spread across many IPs.
func TestEmailCeilingBoundsDistributedFlood(t *testing.T) {
	srv, sender := testServerWith(t, func(c *config.Config) {
		c.RateLimitPerEmailCeiling = config.RateLimit{Count: 2, Window: time.Hour}
		c.OTPResendCooldown = 0
	})
	for _, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"} {
		requestFrom(newClient(t, srv.Handler()), ip, "victim@example.com")
	}
	if n := sentCount(sender); n != 2 {
		t.Errorf("distributed flood sent %d emails, want 2", n)
	}
}
