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

// An address that signed in from an IP passes the send ceilings there, so a
// flood elsewhere cannot lock the owner out of their usual network; a new IP
// for the same address is still bounded.
func TestKnownDeviceBypassesCeiling(t *testing.T) {
	srv, sender := testServerWith(t, func(c *config.Config) {
		c.RateLimitPerEmailCeiling = config.RateLimit{Count: 1, Window: time.Hour}
		c.OTPResendCooldown = 0
	})
	loginAs(t, newClient(t, srv.Handler()), sender, "owner@example.com", nil) // from 10.0.0.1
	sentCount(sender)
	for _, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		requestFrom(newClient(t, srv.Handler()), ip, "owner@example.com")
	}
	if n := sentCount(sender); n != 0 {
		t.Fatalf("flood sent %d emails past an empty ceiling", n)
	}
	newClient(t, srv.Handler()).postForm("/request", url.Values{"email": {"owner@example.com"}})
	if n := sentCount(sender); n != 1 {
		t.Errorf("owner's usual IP got %d emails, want 1", n)
	}
	requestFrom(newClient(t, srv.Handler()), "203.0.113.9", "owner@example.com")
	if n := sentCount(sender); n != 0 {
		t.Errorf("an unknown IP got %d emails past the ceiling, want 0", n)
	}
}

// One IP cannot cause more than its send cap across many addresses.
func TestSendsPerIPCap(t *testing.T) {
	srv, sender := testServerWith(t, func(c *config.Config) {
		c.RateLimitSendsPerIP = config.RateLimit{Count: 2, Window: time.Hour}
	})
	c := newClient(t, srv.Handler())
	for _, who := range []string{"a@example.com", "b@example.com", "c@example.com", "d@example.com"} {
		requestFrom(c, "198.51.100.7", who)
	}
	if n := sentCount(sender); n != 2 {
		t.Errorf("one IP caused %d emails, want 2", n)
	}
}

// An over-limit decoy does not start the resend cooldown, so an attacker who
// burns the owner's code and re-requests cannot make the owner's own request
// from their usual IP a no-op.
func TestOverLimitDecoyDoesNotBlockOwner(t *testing.T) {
	srv, sender := testServerWith(t, func(c *config.Config) {
		c.RateLimitPerEmailCeiling = config.RateLimit{Count: 1, Window: time.Hour}
		c.OTPResendCooldown = time.Minute
	})
	loginAs(t, newClient(t, srv.Handler()), sender, "owner@example.com", nil) // from 10.0.0.1, spends the ceiling
	sentCount(sender)
	requestFrom(newClient(t, srv.Handler()), "198.51.100.1", "owner@example.com") // over the ceiling: decoy
	if n := sentCount(sender); n != 0 {
		t.Fatalf("attacker's over-limit request sent %d emails", n)
	}
	newClient(t, srv.Handler()).postForm("/request", url.Values{"email": {"owner@example.com"}})
	if n := sentCount(sender); n != 1 {
		t.Errorf("owner's request from the usual IP sent %d emails, want 1", n)
	}
}

// An IP that has filled its own send cap cannot spend an owner's ceiling.
func TestFullSendCapDoesNotDrainCeiling(t *testing.T) {
	srv, sender := testServerWith(t, func(c *config.Config) {
		c.RateLimitSendsPerIP = config.RateLimit{Count: 2, Window: time.Hour}
		c.RateLimitPerEmailCeiling = config.RateLimit{Count: 1, Window: time.Hour}
		c.OTPResendCooldown = 0
	})
	attacker := newClient(t, srv.Handler())
	for _, who := range []string{"x1@example.org", "x2@example.org"} { // not permitted: decoys, no mail
		requestFrom(attacker, "198.51.100.7", who)
	}
	for i := 0; i < 5; i++ {
		requestFrom(attacker, "198.51.100.7", "victim@example.com")
	}
	if n := sentCount(sender); n != 0 {
		t.Fatalf("attacker caused %d emails", n)
	}
	requestFrom(newClient(t, srv.Handler()), "203.0.113.9", "victim@example.com")
	if n := sentCount(sender); n != 1 {
		t.Errorf("victim's own request sent %d emails, want 1", n)
	}
}
