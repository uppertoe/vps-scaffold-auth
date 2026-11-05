package server

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/email"
)

// noticesAfter waits briefly for the security notices sent so far.
func noticesAfter(s *captureSender, want int) []email.Message {
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		s.mu.Lock()
		n := len(s.notices)
		s.mu.Unlock()
		if n >= want && want > 0 {
			break
		}
	}
	time.Sleep(50 * time.Millisecond) // let any extra notice arrive
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]email.Message(nil), s.notices...)
}

func dailyServer(t *testing.T, daily int) (*Server, *captureSender) {
	return testServerWith(t, func(c *config.Config) {
		c.RateLimitPerEmailCeiling = config.RateLimit{Count: 100, Window: time.Hour}
		c.RateLimitPerEmailDaily = config.RateLimit{Count: daily, Window: 24 * time.Hour}
		c.OTPResendCooldown = 0
	})
}

// The daily ceiling bounds a flood that stays under the hourly one, and the
// owner's usual network still gets a code.
func TestDailyCeilingBoundsASlowFlood(t *testing.T) {
	srv, sender := dailyServer(t, 3)
	loginAs(t, newClient(t, srv.Handler()), sender, "owner@example.com", nil) // from 10.0.0.1, spends one
	sentCount(sender)
	for i := 1; i <= 5; i++ {
		requestFrom(newClient(t, srv.Handler()), fmt.Sprintf("198.51.100.%d", i), "owner@example.com")
	}
	if n := sentCount(sender); n != 2 {
		t.Fatalf("slow flood sent %d codes, want 2 (3 a day, one spent signing in)", n)
	}
	newClient(t, srv.Handler()).postForm("/request", url.Values{"email": {"owner@example.com"}})
	if n := sentCount(sender); n != 1 {
		t.Errorf("owner's usual network got %d codes past the daily ceiling, want 1", n)
	}
}

// Reaching the daily ceiling tells every administrator, once a day for the
// address however often it is reached.
func TestDailyCeilingAlertsAdministratorsOnce(t *testing.T) {
	srv, sender := dailyServer(t, 1)
	srv.cfg.AdminEmails = []string{"admin@example.com", "boss@example.com"}
	for i := 1; i <= 6; i++ {
		requestFrom(newClient(t, srv.Handler()), fmt.Sprintf("198.51.100.%d", i), "victim@example.com")
	}
	got := noticesAfter(sender, 2)
	if len(got) != 2 {
		t.Fatalf("alerts = %d, want one to each of two administrators: %+v", len(got), got)
	}
	to := map[string]bool{}
	for _, m := range got {
		to[m.To] = true
		if m.Subject != "Sign-in codes for victim@example.com have reached the daily limit" {
			t.Errorf("subject = %q", m.Subject)
		}
		if !strings.Contains(m.Text, "/admin/access?email=victim%40example.com") {
			t.Errorf("alert has no link to the person's access log:\n%s", m.Text)
		}
	}
	if !to["admin@example.com"] || !to["boss@example.com"] {
		t.Errorf("alert recipients = %v", to)
	}

	// The next day the address is reported again.
	srv.now = func() time.Time { return time.Now().Add(25 * time.Hour) }
	srv.alertAboutCodes("victim@example.com", codeAlertDaily, srv.now())
	if got := noticesAfter(sender, 4); len(got) != 4 {
		t.Errorf("alerts after a day = %d, want 4", len(got))
	}
}

// An address the policy does not permit gets only decoy codes, so naming it
// must not put it in front of the administrators.
func TestNoCodeAlertForAnAddressNotPermitted(t *testing.T) {
	srv, sender := dailyServer(t, 1)
	for i := 1; i <= 4; i++ {
		requestFrom(newClient(t, srv.Handler()), fmt.Sprintf("198.51.100.%d", i), "stranger@other.org")
	}
	if got := noticesAfter(sender, 0); len(got) != 0 {
		t.Errorf("alerts for an address not permitted = %+v, want none", got)
	}
}

// Many addresses at once cannot flood the administrators.
func TestCodeAlertsAreCappedPerDay(t *testing.T) {
	srv, sender := dailyServer(t, 1)
	for a := 0; a < maxCodeAlertsPerDay+3; a++ {
		addr := fmt.Sprintf("person%d@example.com", a)
		for i := 1; i <= 2; i++ {
			requestFrom(newClient(t, srv.Handler()), fmt.Sprintf("198.51.%d.%d", a, i), addr)
		}
	}
	got := noticesAfter(sender, maxCodeAlertsPerDay+1)
	if len(got) != maxCodeAlertsPerDay+1 {
		t.Fatalf("alerts = %d, want the cap of %d and one saying alerts have stopped", len(got), maxCodeAlertsPerDay)
	}
	stopped := 0
	for _, m := range got {
		if m.Subject == "Sign-in codes for many addresses have reached their limits" {
			stopped++
		}
	}
	if stopped != 1 {
		t.Errorf("alerts-have-stopped notices = %d, want 1", stopped)
	}
}

// A code destroyed by wrong guesses from several networks tells the
// administrators; wrong guesses short of the total do not.
func TestBurnedCodeAlertsAdministrators(t *testing.T) {
	srv, sender := testServerWith(t, func(c *config.Config) {
		c.OTPMaxAttempts = 2
		c.OTPMaxTotalAttempts = 3
	})
	c := newClient(t, srv.Handler())
	c.postForm("/request", url.Values{"email": {"user@example.com"}})
	guess := func(ip string) {
		c.postWith("/verify-code", url.Values{"code": {"000000"}}, map[string]string{"X-Forwarded-For": ip})
	}
	guess("198.51.100.1")
	guess("198.51.100.2")
	if got := noticesAfter(sender, 0); len(got) != 0 {
		t.Fatalf("alert before the code was destroyed: %+v", got)
	}
	guess("198.51.100.3") // the third, and the code's total
	got := noticesAfter(sender, 1)
	if len(got) != 1 || got[0].To != "admin@example.com" || got[0].Subject != "A sign-in code for user@example.com has been destroyed" {
		t.Fatalf("alerts = %+v, want one destroyed-code alert to the administrator", got)
	}
	if !strings.Contains(got[0].Text, "received 3 wrong guesses") {
		t.Errorf("alert does not give the number of guesses:\n%s", got[0].Text)
	}
}
