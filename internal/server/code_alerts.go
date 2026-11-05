package server

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/email"
)

// Every limit on sign-in codes bounds how fast a guesser can work, and none
// stops one who keeps going for weeks. The administrators are therefore told
// when an address reaches its daily ceiling or one of its codes is destroyed
// by wrong guesses, so that a slow attack is noticed. The person concerned is
// receiving codes they did not ask for, and the alert lets an administrator
// ask them.

type codeAlert int

const (
	codeAlertDaily  codeAlert = iota // the address reached its daily ceiling
	codeAlertBurned                  // a code was destroyed by wrong guesses
)

// maxCodeAlertsPerDay bounds the alerts sent for all addresses together, so
// that a party trying many addresses at once cannot flood the administrators'
// inboxes. Each alert is still logged.
const maxCodeAlertsPerDay = 10

// dailyOnce says yes to a key at most once a day.
type dailyOnce struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func (d *dailyOnce) due(key string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.last == nil {
		d.last = map[string]time.Time{}
	}
	if t, ok := d.last[key]; ok && now.Sub(t) < 24*time.Hour {
		return false
	}
	// Forget entries more than a day old, so the map holds at most a day of
	// alerted addresses.
	for k, t := range d.last {
		if now.Sub(t) >= 24*time.Hour {
			delete(d.last, k)
		}
	}
	d.last[key] = now
	return true
}

// dailyCount allows a fixed number of events in a day that starts at the
// first of them.
type dailyCount struct {
	mu    sync.Mutex
	start time.Time
	n     int
}

func (d *dailyCount) allow(limit int, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.start.IsZero() || now.Sub(d.start) >= 24*time.Hour {
		d.start, d.n = now, 0
	}
	if d.n >= limit {
		return false
	}
	d.n++
	return true
}

// alertAboutCodes emails the administrators about an address's sign-in codes,
// at most once a day for each address. Only an address the policy permits is
// reported: a code for any other address is a decoy that sends no mail, and a
// stranger could otherwise name addresses of their choosing in the
// administrators' inboxes.
func (s *Server) alertAboutCodes(addr string, kind codeAlert, now time.Time) {
	if s.policy.Role(addr) == authz.RoleDeny || len(s.cfg.AdminEmails) == 0 {
		return
	}
	if !s.codeAlerts.due(addr, now) {
		return
	}
	if !s.alertsPerDay.allow(maxCodeAlertsPerDay, now) {
		log.Printf("code alert for %s not sent: %d alerts have been sent in the past day", addr, maxCodeAlertsPerDay)
		// Someone could spend the cap on other addresses first and then
		// work on the one they want unseen, so the first alert held back
		// says that alerts have stopped, once a day.
		if s.codeAlerts.due(overflowKey, now) {
			s.sendCodeAlerts(func(to string) email.Message { return s.codeAlertOverflowEmail(to, now) })
		}
		return
	}
	log.Printf("code alert for %s (%s)", addr, kind)
	s.sendCodeAlerts(func(to string) email.Message { return s.codeAlertEmail(to, addr, kind, now) })
}

// overflowKey marks the day's "alerts have stopped" notice among the
// addresses in codeAlerts. It has no "@", so it is never an address.
const overflowKey = "overflow"

func (s *Server) sendCodeAlerts(build func(to string) email.Message) {
	for _, to := range s.cfg.AdminEmails {
		msg := build(to)
		s.sendNotice("code alert to "+to, func(ctx context.Context) error { return s.sender.Send(ctx, msg) })
	}
}

func (k codeAlert) String() string {
	if k == codeAlertBurned {
		return "code destroyed by wrong guesses"
	}
	return "daily ceiling reached"
}

// codeAlertEmail is the plain-text alert to one administrator.
func (s *Server) codeAlertEmail(to, addr string, kind codeAlert, now time.Time) email.Message {
	when := now.In(s.loc)
	stamp := strings.ToLower(when.Format("3:04 pm")) + " on " + when.Format("2 January 2006")
	var subject, first string
	switch kind {
	case codeAlertBurned:
		subject = "A sign-in code for " + addr + " has been destroyed"
		first = fmt.Sprintf("At %s, a sign-in code sent to %s received %d wrong guesses, so the gateway destroyed it. Nobody signed in with it.", stamp, addr, s.cfg.OTPMaxTotalAttempts)
	default:
		subject = "Sign-in codes for " + addr + " have reached the daily limit"
		first = fmt.Sprintf("At %s, %s reached the daily limit on sign-in codes. The gateway will send no more codes to this address today, except to a network it has recently signed in from.", stamp, addr)
	}
	link := s.cfg.PublicURL + "/admin/access?email=" + url.QueryEscape(addr)
	text := first + "\n\n" +
		"If the person was not trying to sign in, someone else may be trying to guess their codes, and you may wish to ask them.\n\n" +
		"The access log shows each attempt: " + link + "\n\n" +
		"The gateway sends this alert at most once a day for each address.\n"
	return email.Message{To: to, Subject: subject, Text: text}
}

// codeAlertOverflowEmail tells an administrator that the day's alerts have
// stopped.
func (s *Server) codeAlertOverflowEmail(to string, now time.Time) email.Message {
	text := fmt.Sprintf("More than %d addresses have reached the daily limit on sign-in codes, or had a code destroyed by wrong guesses, in the past day. The gateway will send no further alerts of this kind for up to a day. This may be a scripted attempt on many accounts.\n\n", maxCodeAlertsPerDay) +
		"The access log shows each attempt: " + s.cfg.PublicURL + "/admin/access\n"
	return email.Message{To: to, Subject: "Sign-in codes for many addresses have reached their limits", Text: text}
}
