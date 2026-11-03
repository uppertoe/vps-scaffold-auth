package server

import (
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// The access log keeps one app-access row per person, site and hour, and one
// auth-event row per step of a sign-in. The page folds both: app access into
// one row per person and site over the chosen period, and the steps of each
// sign-in into one row.

// accessPeriods are the periods the access log offers, shortest first.
var accessPeriods = []struct {
	Key   string
	Label string
	Dur   time.Duration
}{
	{"1d", "Last 24 hours", 24 * time.Hour},
	{"7d", "Last 7 days", 7 * 24 * time.Hour},
	{"30d", "Last 30 days", 30 * 24 * time.Hour},
	{"90d", "Last 90 days", 90 * 24 * time.Hour},
	{"365d", "Last year", 365 * 24 * time.Hour},
}

const (
	defaultAccessPeriod = "7d"
	// signInScan bounds the auth-event rows read for one page, and
	// signInShown the folded sign-ins shown.
	signInScan  = 2000
	signInShown = 200
	// Without a person chosen, fewer sign-ins are shown, so that the page
	// stays a summary.
	signInShownAll = 50
)

type accessView struct {
	Person, Site, Period string
	ProblemsOnly         bool
	Periods              []accessPeriodOption
	Sites                []string // offered in the site menu
	SiteSummary          []accessSiteView
	Uses                 []accessUseView    // one row per site, when a person is chosen
	People               []accessPersonView // one row per person, otherwise
	SignIns              []signInView
	SignInsCapped        bool
	SignInsShown         int
	// Links that keep the other filters: everything, and refused only.
	AllLink, ProblemsLink string
	Filtered              bool
}

// link is the access-log URL for these filters.
func (v *accessView) link(person, site string, problems bool) string {
	q := url.Values{}
	if person != "" {
		q.Set("email", person)
	}
	if site != "" {
		q.Set("site", site)
	}
	if v.Period != defaultAccessPeriod {
		q.Set("period", v.Period)
	}
	if problems {
		q.Set("show", "problems")
	}
	if len(q) == 0 {
		return "/admin/access"
	}
	return "/admin/access?" + q.Encode()
}

type accessPeriodOption struct {
	Key, Label string
	Selected   bool
}

// accessSiteView is one site's use over the period.
type accessSiteView struct {
	Host, Link string
	People     int
	Last       string
}

// accessUseView is one person's use of one site over the period.
type accessUseView struct {
	Email, Host  string
	PersonLink   string
	Guest, Break bool
	First, Last  string
	Days, Hours  int
}

// accessPersonView is one person's use of every site over the period.
type accessPersonView struct {
	Email, Link  string
	Sites        []string
	Guest, Break bool
	Last         string
	Days, Hours  int
}

// signInView is one sign-in, or one refused step of one.
type signInView struct {
	Time, Email string
	OK          bool
	Result      string // what happened, e.g. "Signed in", "Wrong email code"
	How         string // how a successful sign-in was made
	IP, Device  string
}

func (s *Server) handleAdminAccess(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	person := normalizeEmail(q.Get("email"))
	site := strings.ToLower(strings.TrimSpace(q.Get("site")))
	period := q.Get("period")
	dur := time.Duration(0)
	for _, p := range accessPeriods {
		if p.Key == period {
			dur = p.Dur
		}
	}
	if dur == 0 {
		period = defaultAccessPeriod
		dur = 7 * 24 * time.Hour
	}
	now := s.now()
	problems := q.Get("show") == "problems"
	// A whole address matches only that person; part of one matches every
	// address containing it.
	f := store.AccessFilter{Email: person, EmailExact: plainAddress(person), Host: site, Since: now.Add(-dur), RefusedOnly: problems}
	_, offset := now.In(s.tzloc()).Zone()

	sums, err := s.store.SummariseAppAccess(r.Context(), f, offset)
	if err != nil {
		s.adminError(w, r)
		return
	}
	hosts, err := s.store.AppAccessHosts(r.Context(), now.Add(-accessPeriods[len(accessPeriods)-1].Dur))
	if err != nil {
		s.adminError(w, r)
		return
	}
	events, err := s.store.ListAuthEventsFiltered(r.Context(), f, signInScan)
	if err != nil {
		s.adminError(w, r)
		return
	}
	v := &accessView{Person: person, Site: site, Period: period, ProblemsOnly: problems, Sites: hosts}
	for _, p := range accessPeriods {
		v.Periods = append(v.Periods, accessPeriodOption{Key: p.Key, Label: p.Label, Selected: p.Key == period})
	}
	v.SiteSummary, v.Uses = s.accessUses(sums)
	for i := range v.SiteSummary {
		v.SiteSummary[i].Link = v.link(person, v.SiteSummary[i].Host, v.ProblemsOnly)
	}
	for i := range v.Uses {
		v.Uses[i].PersonLink = v.link(v.Uses[i].Email, site, v.ProblemsOnly)
	}
	v.AllLink, v.ProblemsLink = v.link(person, site, false), v.link(person, site, true)
	v.Filtered = person != "" || site != "" || period != defaultAccessPeriod
	if person == "" {
		people, err := s.store.SummarisePeople(r.Context(), f, offset)
		if err != nil {
			s.adminError(w, r)
			return
		}
		for _, p := range people {
			v.People = append(v.People, accessPersonView{
				Email: p.Email, Link: v.link(p.Email, site, v.ProblemsOnly),
				Sites: p.Sites,
				Guest: slices.Contains(p.Kinds, session.KindGuest), Break: slices.Contains(p.Kinds, session.KindBreakGlass),
				Last: s.stampMin(p.Last), Days: p.Days, Hours: p.Hours,
			})
		}
		v.Uses = nil
	}
	v.SignIns = s.foldSignIns(events)
	// Events older than the scan were not read, so the list is incomplete.
	v.SignInsCapped = len(events) == signInScan
	v.SignInsShown = signInShown
	if person == "" {
		v.SignInsShown = signInShownAll
	}
	if len(v.SignIns) > v.SignInsShown {
		v.SignIns, v.SignInsCapped = v.SignIns[:v.SignInsShown], true
	}
	data := adminData{Title: "Access log", FilterEmail: person, Access: v}
	// The passkeys panel needs one whole address, not part of one.
	if s.cfg.PasskeysEnabled && plainAddress(person) {
		keys, err := s.store.ListPasskeys(r.Context(), person)
		if err != nil {
			s.adminError(w, r)
			return
		}
		data.PasskeysOn = true
		data.Passkeys = s.passkeyRows(keys)
		data.PasskeyRenew = renewWithin(s.cfg.SessionRenew)
		data.PasskeysRemoved = q.Get("passkeys_removed") == "1"
	}
	s.renderAdmin(w, r, http.StatusOK, "admin_access", data)
}

// accessUses turns the per person, site and kind summaries into the site
// table and the person-and-site table.
func (s *Server) accessUses(sums []store.AccessSummary) ([]accessSiteView, []accessUseView) {
	type siteAgg struct {
		people map[string]bool
		last   time.Time
	}
	bySite := map[string]*siteAgg{}
	uses := make([]accessUseView, 0, len(sums))
	for _, a := range sums {
		agg := bySite[a.Host]
		if agg == nil {
			agg = &siteAgg{people: map[string]bool{}}
			bySite[a.Host] = agg
		}
		agg.people[a.Email] = true
		if a.Last.After(agg.last) {
			agg.last = a.Last
		}
		uses = append(uses, accessUseView{
			Email: a.Email, Host: a.Host,
			Guest: a.Kind == session.KindGuest, Break: a.Kind == session.KindBreakGlass,
			First: s.stampMin(a.First), Last: s.stampMin(a.Last),
			Days: a.Days, Hours: a.Hours,
		})
	}
	sites := make([]accessSiteView, 0, len(bySite))
	for h, agg := range bySite {
		sites = append(sites, accessSiteView{Host: h, People: len(agg.people), Last: s.stampMin(agg.last)})
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].People != sites[j].People {
			return sites[i].People > sites[j].People
		}
		return sites[i].Host < sites[j].Host
	})
	return sites, uses
}

// foldSignIns turns the auth events (newest first) into one row per sign-in,
// newest first. The steps before a successful sign-in (the email code or
// passkey, and an administrator's authenticator code) become its "how"; a
// refused step is a row of its own.
func (s *Server) foldSignIns(events []store.AuthEvent) []signInView {
	type pending struct {
		first string // "email code" or "passkey"
		totp  bool
		at    time.Time
	}
	open := map[string]*pending{}
	var out []signInView
	for i := len(events) - 1; i >= 0; i-- { // oldest first
		e := events[i]
		row := signInView{Time: s.stamp(e.CreatedAt), Email: e.Email, IP: e.ClientIP, Device: deviceOf(e.UserAgent)}
		ok := e.Outcome == store.AuthOutcomeOK
		switch {
		case ok && e.EventType == store.AuthEventVerify:
			open[e.Email] = &pending{first: "Email code", at: e.CreatedAt}
			continue
		case ok && e.EventType == store.AuthEventPasskey:
			open[e.Email] = &pending{first: "Passkey", at: e.CreatedAt}
			continue
		case ok && e.EventType == store.AuthEventTOTP:
			if p := open[e.Email]; p != nil {
				p.totp = true
			}
			continue
		case ok && e.EventType == store.AuthEventLogin:
			// How is unknown if the first step was not read (it fell
			// outside the scan) or was not recorded.
			row.OK, row.Result, row.How = true, "Signed in", "Unknown"
			if p := open[e.Email]; p != nil && e.CreatedAt.Sub(p.at) <= 30*time.Minute {
				row.How = p.first
				if p.totp {
					row.How += " and authenticator"
				}
			}
			delete(open, e.Email)
		case ok && e.EventType == store.AuthEventPasskeyAdd:
			row.OK, row.Result, row.How = true, "Passkey added", "Passkey"
		case ok && e.EventType == store.AuthEventPasskeyRemove:
			row.OK, row.Result, row.How = true, "Passkey removed", "Passkey"
		default:
			row.Result, row.How = refusedLabel(e.EventType, e.Outcome), stepLabel(e.EventType)
		}
		out = append(out, row)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// refusedLabel names a refused sign-in step.
func refusedLabel(step, outcome string) string {
	switch outcome {
	case store.AuthOutcomeDenied:
		return "Address not permitted"
	case store.AuthOutcomeExpired:
		return "Email code expired"
	case store.AuthOutcomeNoSecret:
		return "Authenticator not set up"
	case store.AuthOutcomeReplayed:
		return "Authenticator code used twice"
	case store.AuthOutcomeUnknownPasskey:
		return "Passkey not recognised"
	case store.AuthOutcomeBadPasskey:
		if step == store.AuthEventPasskeyAdd {
			return "Passkey not added"
		}
		return "Passkey refused"
	case store.AuthOutcomePasskeyCounter:
		return "Passkey refused as a possible copy"
	case store.AuthOutcomeWrongCode:
		if step == store.AuthEventTOTP {
			return "Wrong authenticator code"
		}
		return "Wrong email code"
	case store.AuthOutcomeLockedOut:
		if step == store.AuthEventTOTP {
			return "Too many wrong authenticator codes"
		}
		return "Too many wrong email codes"
	}
	return step + ": " + outcome
}

// stepLabel names the sign-in step an event belongs to.
func stepLabel(step string) string {
	switch step {
	case store.AuthEventTOTP:
		return "Authenticator"
	case store.AuthEventPasskey, store.AuthEventPasskeyAdd, store.AuthEventPasskeyRemove:
		return "Passkey"
	}
	return "Email code"
}

// deviceOf names the kind of device from a user agent, or "" if unknown.
func deviceOf(ua string) string {
	switch {
	case strings.Contains(ua, "iPhone"):
		return "iPhone"
	case strings.Contains(ua, "iPad"):
		return "iPad"
	case strings.Contains(ua, "Android"):
		return "Android"
	case strings.Contains(ua, "Macintosh"):
		return "Mac"
	case strings.Contains(ua, "Windows"):
		return "Windows"
	case strings.Contains(ua, "CrOS"):
		return "Chromebook"
	case strings.Contains(ua, "Linux"):
		return "Linux"
	}
	return ""
}
