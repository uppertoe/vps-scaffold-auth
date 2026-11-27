package server

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// The Sessions page lists every signed-in session, or one person's, with
// "Sign out" for a session, "Sign out on every device" for a person and "Sign
// out everyone" for an incident. Each is confirmed in place (?confirm=one,
// person or everyone), audited, and emailed to the other administrators.

const sessionsPath = "/admin/sessions"

// The strings the Sessions page, its emails and the Access log's link show.
// Change them only with the owner's agreement.
const (
	msgSessMenu          = "Sessions"
	msgSessLead          = "Each session is one browser that is signed in. A person who has been signed out can sign in again with an email code."
	msgSessCountMany     = "%s browsers are signed in."
	msgSessCountOne      = "One browser is signed in."
	msgSessCountNone     = "Nobody is signed in."
	msgSessPersonMany    = "%s is signed in on %s browsers."
	msgSessPersonOne     = "%s is signed in on one browser."
	msgSessPersonNone    = "%s is not signed in on any browser."
	msgSessAskOne        = "Once you sign out this session, %s needs to sign in again on %s."
	msgSessAskPerson     = "Signing out on every device ends every session %s has, including one someone else may be using."
	msgSessAskEveryone   = "Signing everyone out ends every session except your own, including break-glass sessions. Everyone else then needs to sign in again."
	msgSessThatBrowser   = "that browser"
	msgSessColPerson     = "Person"
	msgSessColKind       = "Kind"
	msgSessColSignedIn   = "Signed in"
	msgSessColLastSeen   = "Last seen"
	msgSessColDevice     = "Device"
	msgSessKindStaff     = "Staff"
	msgSessKindMember    = "Member"
	msgSessKindGuest     = "Guest"
	msgSessKindCard      = "Break-glass card"
	msgSessDeviceUnknown = "Not known"
	msgSessThisBrowser   = "This browser"
	msgSessSignOut       = "Sign out"
	msgSessSignOutPerson = "Sign out on every device"
	msgSessSignOutAll    = "Sign out everyone"
	msgSessShowEveryone  = "Show every session"
	msgSessCancel        = "Cancel"
	msgSessSubjectOne    = "A session of %s has ended."
	msgSessSubjectPerson = "%s has been signed out on every device."
	msgSessSubjectAll    = "Everyone has been signed out."
	msgSessLineOne       = "Signed out one session of %s, on %s"
	msgSessLinePerson    = "Signed out %s on every device"
	msgSessLineAll       = "Signed out every session except their own, %d in all"
	msgAccessSessBefore  = "This person's sessions are listed on the "
	msgAccessSessAfter   = " page."
)

// sessionsView is the Sessions page.
type sessionsView struct {
	Lead, Strip, StripTone string
	// Person is the address the page is narrowed to, if any.
	Person string
	Rows   []sessionRow
	// Asking is "one", "person" or "everyone" while that confirmation is
	// shown beside the strip; AskID is the session "one" asks about.
	Asking string
	AskID  int64
	// AskHref opens the confirmation of the page-wide action: signing the
	// person out on every device, or signing everyone out.
	AskHref, AllHref, CancelHref string
	Col                          map[string]string
	Btn                          map[string]string
}

// sessionRow is one session: the same cells on every row.
type sessionRow struct {
	ID                                    int64
	Email, PersonHref                     string
	Kind, SignedIn, LastSeen, Device      string
	DeviceMissing, Mine, Confirming, Card bool
	AskHref                               string
}

func sessionKind(x store.Session) string {
	switch x.Kind {
	case session.KindBreakGlass:
		return msgSessKindCard
	case session.KindGuest:
		return msgSessKindGuest
	case session.KindMember:
		return msgSessKindMember
	}
	return msgSessKindStaff
}

func sessionsHref(email string, q url.Values) string {
	if q == nil {
		q = url.Values{}
	}
	if email != "" {
		q.Set("email", email)
	}
	if len(q) == 0 {
		return sessionsPath
	}
	return sessionsPath + "?" + q.Encode()
}

// handleAdminSessions shows the Sessions page. A GET never changes anything:
// ?confirm= only draws the confirming form.
func (s *Server) handleAdminSessions(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	q := r.URL.Query()
	person := ""
	if e := normalizeEmail(q.Get("email")); plainAddress(e) {
		person = e
	}
	mine := int64(0)
	if id, ok := s.readSession(r, now); ok {
		mine = id.SID
	}
	list := s.liveSessionsNow(person, now)
	v := &sessionsView{
		Lead: msgSessLead, Person: person, CancelHref: sessionsHref(person, nil), AllHref: sessionsPath,
		Col: map[string]string{"Person": msgSessColPerson, "Kind": msgSessColKind, "SignedIn": msgSessColSignedIn, "LastSeen": msgSessColLastSeen, "Device": msgSessColDevice},
		Btn: map[string]string{"One": msgSessSignOut, "Person": msgSessSignOutPerson, "All": msgSessSignOutAll, "Cancel": msgSessCancel, "ShowAll": msgSessShowEveryone, "Mine": msgSessThisBrowser},
	}
	if person != "" {
		v.AskHref = sessionsHref(person, url.Values{"confirm": {"person"}})
	} else {
		v.AskHref = sessionsHref("", url.Values{"confirm": {"everyone"}})
	}
	confirmID, _ := strconv.ParseInt(q.Get("id"), 10, 64)
	for _, x := range list {
		row := sessionRow{
			ID: x.ID, Email: x.Email, Kind: sessionKind(x), Card: x.Kind == session.KindBreakGlass,
			SignedIn: s.stampMin(x.SignedIn), LastSeen: s.stampMin(x.LastSeen), Device: x.Device,
			Mine:    x.ID == mine,
			AskHref: sessionsHref(person, url.Values{"confirm": {"one"}, "id": {strconv.FormatInt(x.ID, 10)}}),
		}
		if row.Card {
			row.Email = strings.TrimPrefix(x.Email, "breakglass:") // the card's label
		} else {
			row.PersonHref = sessionsHref(x.Email, nil)
		}
		if row.Device == "" {
			row.Device, row.DeviceMissing = msgSessDeviceUnknown, true
		}
		if q.Get("confirm") == "one" && x.ID == confirmID && !row.Mine {
			row.Confirming = true
			where := x.Device
			if where == "" {
				where = msgSessThatBrowser
			}
			v.Asking, v.AskID = "one", x.ID
			v.Strip, v.StripTone = fmt.Sprintf(msgSessAskOne, x.Email, where), "ask"
		}
		v.Rows = append(v.Rows, row)
	}
	if v.Strip == "" {
		switch c := q.Get("confirm"); {
		case c == "person" && person != "":
			v.Asking, v.Strip, v.StripTone = "person", fmt.Sprintf(msgSessAskPerson, person), "ask"
		case c == "everyone" && person == "":
			v.Asking, v.Strip, v.StripTone = "everyone", msgSessAskEveryone, "ask"
		default:
			v.Strip, v.StripTone = sessionsCount(person, len(list)), "none"
		}
	}
	notice, warning := s.takeNotice(w, r)
	if notice != "" {
		v.Strip, v.StripTone, v.Asking = notice, "ok", ""
	} else if warning != "" {
		v.Strip, v.StripTone, v.Asking = warning, "warn", ""
	}
	s.renderAdmin(w, r, http.StatusOK, "admin_sessions", adminData{Title: msgSessMenu, Sessions: v, NoticeInPage: true})
}

func sessionsCount(person string, n int) string {
	switch {
	case person != "" && n == 0:
		return fmt.Sprintf(msgSessPersonNone, person)
	case person != "" && n == 1:
		return fmt.Sprintf(msgSessPersonOne, person)
	case person != "":
		return fmt.Sprintf(msgSessPersonMany, person, numberWord(n))
	case n == 0:
		return msgSessCountNone
	case n == 1:
		return msgSessCountOne
	}
	return fmt.Sprintf(msgSessCountMany, capFirst(numberWord(n)))
}

// handleAdminEndSession signs out one session.
func (s *Server) handleAdminEndSession(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	id, _ := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	back := sessionsPath
	if e := normalizeEmail(r.PostFormValue("email")); plainAddress(e) {
		back = sessionsHref(e, nil)
	}
	var ended *store.Session
	n, err := s.endSessionsWhere(r.Context(), func(x *store.Session) bool {
		if x.ID == id && id != 0 {
			cp := *x
			ended = &cp
			return true
		}
		return false
	})
	if err != nil {
		s.adminError(w, r)
		return
	}
	if n == 0 || ended == nil {
		s.redirectDone(w, r, back, "session-gone", "")
		return
	}
	where := ended.Device
	if where == "" {
		where = msgSessDeviceUnknown
	}
	s.auditAdmin(r, store.AdminActionSessionEnd, ended.Email, where)
	s.emailOtherAdmins(s.adminActor(r), fmt.Sprintf(msgSessSubjectOne, ended.Email), []string{fmt.Sprintf(msgSessLineOne, ended.Email, where)})
	s.redirectDone(w, r, back, "session-ended", "")
}

// handleAdminEndAllSessions signs everyone out except the administrator
// doing it, for an incident.
func (s *Server) handleAdminEndAllSessions(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	now := s.now()
	mine := int64(0)
	if id, ok := s.readSession(r, now); ok {
		mine = id.SID
	}
	// An old-format cookie not yet seen is refused when it arrives
	// (session_legacy.go).
	if err := s.store.EndSessionsBefore(r.Context(), everyoneKey, now); err != nil {
		s.adminError(w, r)
		return
	}
	n, err := s.endSessionsWhere(r.Context(), func(x *store.Session) bool { return x.ID != mine })
	if err != nil {
		s.adminError(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionSessionsEndAll, "", strconv.Itoa(n))
	s.emailOtherAdmins(s.adminActor(r), msgSessSubjectAll, []string{fmt.Sprintf(msgSessLineAll, n)})
	s.redirectDone(w, r, sessionsPath, "everyone-ended", "")
}
