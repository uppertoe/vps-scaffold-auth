package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/email"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// Your sessions (/sessions) is a person's own list of the browsers they are
// signed in on, linked from the welcome page and the passkeys page. Each
// other session can be signed out, and "Sign out on every other device" ends
// all of them but this browser's. "Sign out on every device" is the existing
// one on the sign-out page.
//
// Only a person's own sign-in has the page (personSession): a break-glass
// card's session and a guest's are sent to sign in. A session is named by its
// row ID, never its token, and a row is ended only if, under the lock every
// revocation takes, it belongs to the person and the person's own session is
// still live. Each action is confirmed in place (?confirm=one or others),
// needs the form token and a same-origin post, is recorded in the sign-in
// audit and is emailed to the person.

const ownSessionsPath = "/sessions"

// The strings Your sessions and its emails show. Change them only with the
// owner's agreement. The row's "This browser", "Sign out" and "Cancel", and
// the notices "The session has ended." and "The session had already ended,
// so nothing has changed.", are the Sessions page's (admin_sessions.go,
// admin_notices.go).
const (
	msgOwnTitle          = "Your sessions"
	msgOwnLead           = "Each session is one browser in which you are signed in. If you do not recognise a session, sign out on every other device."
	msgOwnCountMany      = "You are signed in on %s browsers."
	msgOwnCountOne       = "You are signed in on this browser and no other."
	msgOwnAskOne         = "Once you sign out this session, you need to sign in again on %s."
	msgOwnAskOthers      = "Signing out on every other device ends every session you have except the one in this browser."
	msgOwnSignedIn       = "Signed in %s"
	msgOwnLastSeen       = "Last seen %s"
	msgOwnToday          = "today at %s"
	msgOwnDeviceUnknown  = "Browser not known"
	msgOwnSignOutOthers  = "Sign out on every other device"
	msgOwnSignOutAll     = "Sign out on every device"
	msgOwnPasskeysLink   = "Your passkeys"
	msgOwnExpired        = "This page had expired, so nothing has been signed out. Open Your sessions and try again."
	msgOwnFailed         = "Nothing has been signed out, because the gateway could not end the sessions. Open Your sessions and try again."
	msgOwnOthersEnded    = "Your sessions on every other device have ended."
	msgOwnOthersGone     = "The other sessions had already ended, so nothing has changed."
	msgOwnThisBrowser    = "The session in this browser has not been signed out. To sign out here, use Sign out on the welcome page."
	msgOwnSubjectOne     = "One of your sessions has been signed out"
	msgOwnSubjectOthers  = "Your other sessions have been signed out"
	msgOwnFirstOne       = "Your session on %s at %s was signed out on %s"
	msgOwnFirstOneAny    = "One of your sessions at %s was signed out on %s"
	msgOwnFirstOthers    = "Your sessions on every other device at %s were signed out on %s"
	msgOwnFirstFrom      = ", from %s"
	msgOwnOKOne          = "If you signed out this session, there is nothing more to do."
	msgOwnOKOthers       = "If you signed out these sessions, there is nothing more to do."
	msgOwnNotYouOne      = "If you did not sign it out, someone else may be signed in as you. Sign in, open Your sessions and sign out on every device, then contact an administrator for assistance."
	msgOwnNotYouOthers   = "If you did not sign them out, someone else may be signed in as you. Sign in, open Your sessions and sign out on every device, then contact an administrator for assistance."
	msgOwnAccessEndOne   = "Signed out a session on another device"
	msgOwnAccessEndOther = "Signed out on every other device"
	msgOwnAccessHow      = "Own sessions page"
)

// ownSessionsView is Your sessions.
type ownSessionsView struct {
	Lead, Strip, StripTone string
	Rows                   []ownSessionRow
	// Asking is "one" or "others" while that confirmation is shown under the
	// strip; AskID is the session "one" asks about.
	Asking     string
	AskID      int64
	OthersHref string
	CancelHref string
	Passkeys   string // the passkeys page, when passkeys are on
	Btn        map[string]string
}

// ownSessionRow is one session: the same three facts on every row.
type ownSessionRow struct {
	ID                       int64
	Device, SignedIn, Seen   string
	DeviceMissing, Mine, Hit bool
	Phone                    bool // the device icon
	AskHref                  string
}

// ownSession reads the request's session if it is a person's own sign-in.
func (s *Server) ownSession(r *http.Request) (*session.Identity, bool) {
	id, _, ok := s.passkeySession(r)
	return id, ok
}

// ownMatch picks the sessions that belong to the person signed in as email:
// a card's session never does, whatever it is labelled.
func ownMatch(email string, x *store.Session) bool {
	return x.Kind != session.KindBreakGlass && x.Email == email
}

func ownSessionsHref(q url.Values) string {
	if len(q) == 0 {
		return ownSessionsPath
	}
	return ownSessionsPath + "?" + q.Encode()
}

// personStamp is "today at 3:04 pm" or "2 January 2006 at 3:04 pm".
func (s *Server) personStamp(t time.Time) string {
	when, now := t.In(s.tzloc()), s.now().In(s.tzloc())
	clock := strings.ToLower(when.Format("3:04 pm"))
	if when.Format("2006-01-02") == now.Format("2006-01-02") {
		return fmt.Sprintf(msgOwnToday, clock)
	}
	return when.Format("2 January 2006") + " at " + clock
}

// handleOwnSessions shows Your sessions. A GET never changes anything:
// ?confirm= only draws the confirming form.
func (s *Server) handleOwnSessions(w http.ResponseWriter, r *http.Request) {
	id, ok := s.ownSession(r)
	if !ok {
		http.Redirect(w, r, s.loginURL(s.cfg.PublicURL+ownSessionsPath), http.StatusFound)
		return
	}
	now := s.now()
	csrf, err := s.sessions.EnsureCSRF(w, r, csrfTTL, now)
	if err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong"})
		return
	}
	q := r.URL.Query()
	v := &ownSessionsView{
		Lead: msgOwnLead, CancelHref: ownSessionsPath,
		OthersHref: ownSessionsHref(url.Values{"confirm": {"others"}}),
		Btn: map[string]string{
			"One": msgSessSignOut, "Others": msgOwnSignOutOthers, "All": msgOwnSignOutAll,
			"Cancel": msgSessCancel, "Mine": msgSessThisBrowser, "Passkeys": msgOwnPasskeysLink,
		},
	}
	if s.cfg.PasskeysEnabled {
		v.Passkeys = s.passkeysURL()
	}
	confirmID, _ := strconv.ParseInt(q.Get("id"), 10, 64)
	others := 0
	for _, x := range s.liveSessionsNow(id.Email, now) {
		if !ownMatch(id.Email, &x) {
			continue
		}
		row := ownSessionRow{
			ID: x.ID, Device: x.Device, Mine: x.ID == id.SID,
			SignedIn: fmt.Sprintf(msgOwnSignedIn, s.personStamp(x.SignedIn)),
			Seen:     fmt.Sprintf(msgOwnLastSeen, s.personStamp(x.LastSeen)),
			AskHref:  ownSessionsHref(url.Values{"confirm": {"one"}, "id": {strconv.FormatInt(x.ID, 10)}}),
		}
		if row.Device == "" {
			row.Device, row.DeviceMissing = msgOwnDeviceUnknown, true
		}
		row.Phone = strings.Contains(x.Device, "iPhone") || strings.Contains(x.Device, "Android") || strings.Contains(x.Device, "iPad")
		if !row.Mine {
			others++
		}
		if q.Get("confirm") == "one" && x.ID == confirmID && !row.Mine {
			where := x.Device
			if where == "" {
				where = msgSessThatBrowser
			}
			row.Hit = true
			v.Asking, v.AskID = "one", x.ID
			v.Strip, v.StripTone = fmt.Sprintf(msgOwnAskOne, where), "ask"
		}
		// This browser is listed first.
		if row.Mine {
			v.Rows = append([]ownSessionRow{row}, v.Rows...)
		} else {
			v.Rows = append(v.Rows, row)
		}
	}
	if v.Strip == "" {
		if q.Get("confirm") == "others" && others > 0 {
			v.Asking, v.Strip, v.StripTone = "others", msgOwnAskOthers, "ask"
		} else if others == 0 {
			v.Strip, v.StripTone = msgOwnCountOne, "none"
		} else {
			v.Strip, v.StripTone = fmt.Sprintf(msgOwnCountMany, numberWord(others+1)), "none"
		}
	}
	if others == 0 {
		v.OthersHref = ""
	}
	if notice, warning := s.takeNotice(w, r); notice != "" {
		v.Strip, v.StripTone, v.Asking = notice, "ok", ""
	} else if warning != "" {
		v.Strip, v.StripTone, v.Asking = warning, "warn", ""
	}
	s.render(w, http.StatusOK, "own_sessions", pageData{Title: msgOwnTitle, OwnSessions: v, CSRF: csrf, Identity: id.Email})
}

// ownPost checks a post to Your sessions: a same-origin form with a valid
// token, from a person's own session.
func (s *Server) ownPost(w http.ResponseWriter, r *http.Request) (*session.Identity, bool) {
	if !s.requireSameOrigin(w, r) {
		return nil, false
	}
	id, ok := s.ownSession(r)
	if !ok {
		http.Redirect(w, r, s.loginURL(s.cfg.PublicURL+ownSessionsPath), http.StatusFound)
		return nil, false
	}
	if !s.sessions.VerifyCSRF(r, r.PostFormValue("csrf"), s.now()) {
		s.render(w, http.StatusForbidden, "message", pageData{Title: "Please try again", Message: msgOwnExpired})
		return nil, false
	}
	return id, true
}

// endOwnSessions ends the person's sessions that pick chooses, other than
// their own, under the lock every revocation takes, and only while their own
// session is still live: one that has been ended by then (by an administrator,
// or from another of their browsers) ends nothing. mineLive is false in that
// case.
func (s *Server) endOwnSessions(ctx context.Context, id *session.Identity, pick func(*store.Session) bool) (ended []store.Session, mineLive bool, err error) {
	l := s.live
	l.write.Lock()
	defer l.write.Unlock()
	l.mu.RLock()
	mine := l.byID[id.SID]
	mineLive = mine != nil && ownMatch(id.Email, mine)
	l.mu.RUnlock()
	if !mineLive {
		return nil, false, nil
	}
	_, err = s.endSessionsLocked(ctx, func(x *store.Session) bool {
		if x.ID == id.SID || !ownMatch(id.Email, x) || !pick(x) {
			return false
		}
		ended = append(ended, *x)
		return true
	})
	if err != nil {
		return nil, true, err
	}
	return ended, true, nil
}

// handleOwnEndSession signs out one of the person's other sessions.
func (s *Server) handleOwnEndSession(w http.ResponseWriter, r *http.Request) {
	id, ok := s.ownPost(w, r)
	if !ok {
		return
	}
	target, _ := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	if target != 0 && target == id.SID {
		s.redirectDone(w, r, ownSessionsPath, "own-this-browser", "")
		return
	}
	ended, mineLive, err := s.endOwnSessions(r.Context(), id, func(x *store.Session) bool { return target != 0 && x.ID == target })
	if err != nil {
		log.Printf("end a session of %s: %v", id.Email, err)
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Please try again", Message: msgOwnFailed})
		return
	}
	if !mineLive {
		s.sessions.ClearSession(w)
		http.Redirect(w, r, s.loginURL(s.cfg.PublicURL+ownSessionsPath), http.StatusFound)
		return
	}
	if len(ended) == 0 {
		s.redirectDone(w, r, ownSessionsPath, "session-gone", "")
		return
	}
	s.recordAuth(r, id.Email, store.AuthEventSessionEnd, store.AuthOutcomeOK)
	s.notifyOwnSessionsEnded(r, id.Email, ended, false)
	s.redirectDone(w, r, ownSessionsPath, "session-ended", "")
}

// handleOwnEndOtherSessions signs the person out on every other device. This
// browser stays signed in under a new token, so a copy of its cookie taken by
// someone else ends with the rest: the person who presses this suspects that
// someone else is signed in as them, and cannot tell a copy of this browser's
// cookie from this browser. The new token and the ending are one change
// (endOthersAndRotate): if either cannot be written, nothing has ended and
// the person is told.
func (s *Server) handleOwnEndOtherSessions(w http.ResponseWriter, r *http.Request) {
	id, ok := s.ownPost(w, r)
	if !ok {
		return
	}
	ended, mineLive, err := s.endOthersAndRotate(w, r, id, s.now(), func(x *store.Session) bool { return ownMatch(id.Email, x) })
	if err != nil {
		log.Printf("sign out every other device for %s: %v", id.Email, err)
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Please try again", Message: msgOwnFailed})
		return
	}
	if !mineLive {
		s.sessions.ClearSession(w)
		http.Redirect(w, r, s.loginURL(s.cfg.PublicURL+ownSessionsPath), http.StatusFound)
		return
	}
	if len(ended) == 0 {
		s.redirectDone(w, r, ownSessionsPath, "own-others-gone", "")
		return
	}
	s.recordAuth(r, id.Email, store.AuthEventSessionsEndOthers, store.AuthOutcomeOK)
	s.notifyOwnSessionsEnded(r, id.Email, ended, true)
	s.redirectDone(w, r, ownSessionsPath, "own-others-ended", "")
}

// notifyOwnSessionsEnded emails the person that sessions of theirs on other
// devices have been signed out. A stolen session can sign out its owner's
// other sessions; this email is how the owner learns of it.
func (s *Server) notifyOwnSessionsEnded(r *http.Request, to string, ended []store.Session, others bool) {
	msg := s.ownSessionsEndedEmail(to, ended, others, deviceSummary(r.UserAgent()), s.now())
	s.sendNotice("sessions notice to "+to, func(ctx context.Context) error { return s.sender.Send(ctx, msg) })
}

func (s *Server) ownSessionsEndedEmail(to string, ended []store.Session, others bool, from string, now time.Time) email.Message {
	host, stamp := s.relyingParty().ID, s.noticeStamp(now)
	subject, ok, notYou := msgOwnSubjectOthers, msgOwnOKOthers, msgOwnNotYouOthers
	var first string
	switch {
	case others:
		first = fmt.Sprintf(msgOwnFirstOthers, host, stamp)
	case len(ended) == 1 && ended[0].Device != "":
		subject, ok, notYou = msgOwnSubjectOne, msgOwnOKOne, msgOwnNotYouOne
		first = fmt.Sprintf(msgOwnFirstOne, ended[0].Device, host, stamp)
	default:
		subject, ok, notYou = msgOwnSubjectOne, msgOwnOKOne, msgOwnNotYouOne
		first = fmt.Sprintf(msgOwnFirstOneAny, host, stamp)
	}
	if from != "" {
		first += fmt.Sprintf(msgOwnFirstFrom, from)
	}
	return s.personalNotice(to, subject, first+".", ok, notYou, msgOwnTitle, s.cfg.PublicURL+ownSessionsPath, now)
}
