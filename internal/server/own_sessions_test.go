package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

var iPhoneUA = map[string]string{"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"}

const macChromeUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

// loginOnPhone signs email in with an emailed code on an iPhone.
func loginOnPhone(t *testing.T, c *client, sender *captureSender, email string) {
	t.Helper()
	sender.reset()
	c.do(withHeaders(httptest.NewRequest(http.MethodPost, "/request", strings.NewReader("email="+url.QueryEscape(email))), iPhoneUA))
	if rec := c.do(withHeaders(httptest.NewRequest(http.MethodPost, "/verify-code", strings.NewReader("code="+sender.code())), iPhoneUA)); rec.Code != http.StatusFound {
		t.Fatalf("phone sign-in = %d", rec.Code)
	}
}

// sessionID is the row ID of the session c holds.
func sessionID(t *testing.T, srv *Server, c *client) int64 {
	t.Helper()
	return readSession(t, srv, c).SID
}

// authEvents lists the sign-in audit's event types for email.
func authEvents(t *testing.T, srv *Server, email string) map[string]int {
	t.Helper()
	events, err := srv.store.ListAuthEvents(context.Background(), email, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, e := range events {
		out[e.EventType]++
	}
	return out
}

// noticesTo counts the notices sent to an address with a subject.
func noticesTo(sender *captureSender, to, subject string) int {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	n := 0
	for _, m := range sender.notices {
		if m.To == to && m.Subject == subject {
			n++
		}
	}
	return n
}

// A person sees their own sessions, this browser first and named, and signs
// out one of the others after confirming it in place. The person is emailed
// and the sign-in audit records it; the administrators are not emailed.
func TestOwnSessionsPage(t *testing.T) {
	srv, sender := testServerWith(t, nil)
	anyGuard(t, srv)
	phone, laptop, bob := newClient(t, srv.Handler()), newClient(t, srv.Handler()), newClient(t, srv.Handler())
	loginOnPhone(t, phone, sender, "amy@example.com")
	loginAs(t, laptop, sender, "amy@example.com", nil)
	loginAs(t, bob, sender, "bob@example.com", nil)

	if !strings.Contains(laptop.get("/welcome", nil).Body.String(), `href="/sessions"`) {
		t.Error("the welcome page does not link to Your sessions")
	}
	page := laptop.get("/sessions", nil)
	if page.Code != http.StatusOK {
		t.Fatalf("Your sessions = %d", page.Code)
	}
	body := page.Body.String()
	for _, want := range []string{msgOwnTitle, "You are signed in on two browsers.", "Safari on iPhone", msgOwnDeviceUnknown, msgSessThisBrowser, msgOwnSignOutOthers, msgOwnSignOutAll, "Signed in today at "} {
		if !strings.Contains(body, want) {
			t.Errorf("Your sessions does not show %q", want)
		}
	}
	if strings.Index(body, msgSessThisBrowser) > strings.Index(body, "Safari on iPhone") {
		t.Error("this browser is not listed first")
	}
	if strings.Contains(body, "bob@example.com") || strings.Count(body, `class="pk-row sess-row`) != 2 {
		t.Error("Your sessions lists a session that is not the person's")
	}

	phoneID := sessionID(t, srv, phone)
	ask := laptop.get("/sessions?confirm=one&id="+strconv.FormatInt(phoneID, 10), nil).Body.String()
	if !strings.Contains(ask, "Once you sign out this session, you need to sign in again on Safari on iPhone.") || !strings.Contains(ask, `action="/sessions/end-one"`) {
		t.Fatal("signing out a session is not confirmed in place")
	}
	// The person's own session is never offered as "one".
	if strings.Contains(laptop.get("/sessions?confirm=one&id="+strconv.FormatInt(sessionID(t, srv, laptop), 10), nil).Body.String(), `action="/sessions/end-one"`) {
		t.Error("Your sessions offers to sign out this browser as another session")
	}

	csrf := adminCSRF(t, laptop, "/sessions?confirm=others")
	if rec := laptop.postForm("/sessions/end-one", url.Values{"csrf": {csrf}, "id": {strconv.FormatInt(phoneID, 10)}}); rec.Code != http.StatusFound || rec.Header().Get("Location") != ownSessionsPath {
		t.Fatalf("sign out one = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if verifyAny(t, srv, phone).Code != http.StatusFound || verifyAny(t, srv, laptop).Code != http.StatusOK || verifyAny(t, srv, bob).Code != http.StatusOK {
		t.Fatal("signing out one session did not end exactly that session")
	}
	if !strings.Contains(laptop.get("/sessions", nil).Body.String(), "The session has ended.") {
		t.Error("Your sessions does not confirm the session has ended")
	}
	if authEvents(t, srv, "amy@example.com")[store.AuthEventSessionEnd] != 1 {
		t.Error("signing out one session was not audited")
	}
	m := waitNotice(t, sender, "amy@example.com", msgOwnSubjectOne)
	if !strings.Contains(m.Text, "Your session on Safari on iPhone at auth.example.com was signed out on ") || !strings.Contains(m.Text, "Your sessions: https://auth.example.com/sessions") || !strings.Contains(m.HTML, ">Your sessions</a>") {
		t.Errorf("the notice reads %q", m.Text)
	}
	if noticesTo(sender, "admin@example.com", msgOwnSubjectOne) != 0 {
		t.Error("the administrators were emailed about a person's own sign-out")
	}
	// The Access log names the action.
	admin := newClient(t, srv.Handler())
	loginAs(t, admin, sender, "admin@example.com", nil)
	if !strings.Contains(admin.get("/admin/access?email=amy@example.com", nil).Body.String(), msgOwnAccessEndOne) {
		t.Error("the Access log does not show the sign-out")
	}
	// Ending it again is reported, not acted on, and audited once.
	laptop.postForm("/sessions/end-one", url.Values{"csrf": {csrf}, "id": {strconv.FormatInt(phoneID, 10)}})
	if !strings.Contains(laptop.get("/sessions", nil).Body.String(), "The session had already ended") {
		t.Error("an ended session was not reported as already ended")
	}
	if authEvents(t, srv, "amy@example.com")[store.AuthEventSessionEnd] != 1 {
		t.Error("an ended session was audited again")
	}
}

// One person can neither see nor end another's sessions, whatever row ID
// they post; nor can they end their own current session as "another".
func TestOwnSessionsAreOnlyThePersons(t *testing.T) {
	srv, sender := testServer(t)
	anyGuard(t, srv)
	amy, bob := newClient(t, srv.Handler()), newClient(t, srv.Handler())
	loginOnPhone(t, amy, sender, "amy@example.com")
	loginAs(t, bob, sender, "bob@example.com", nil)
	bobPhone := newClient(t, srv.Handler())
	loginOnPhone(t, bobPhone, sender, "bob@example.com")
	card := mintSession(t, srv, session.Identity{Email: "breakglass:bob@example.com", Groups: "bg", Kind: session.KindBreakGlass}, time.Hour)

	if body := bob.get("/sessions", nil).Body.String(); strings.Contains(body, "amy@example.com") || strings.Count(body, `class="pk-row sess-row`) != 2 {
		t.Error("Bob's page lists a session that is not his")
	}
	amyID, cardID := sessionID(t, srv, amy), sessionID(t, srv, card)
	csrf := adminCSRF(t, bob, "/sessions?confirm=others")
	for _, id := range []int64{amyID, cardID, 0, -1, 999999} {
		bob.postForm("/sessions/end-one", url.Values{"csrf": {csrf}, "id": {strconv.FormatInt(id, 10)}})
	}
	if verifyAny(t, srv, amy).Code != http.StatusOK {
		t.Fatal("Bob ended Amy's session by posting its row ID")
	}
	if liveCount(srv, "breakglass:bob@example.com") != 1 {
		t.Fatal("Bob ended a card's session labelled with his address")
	}
	if !strings.Contains(bob.get("/sessions", nil).Body.String(), "The session had already ended") {
		t.Error("a forged row ID was not answered as an ended session")
	}
	// His own session, posted as "one", is not ended.
	bob.postForm("/sessions/end-one", url.Values{"csrf": {csrf}, "id": {strconv.FormatInt(sessionID(t, srv, bob), 10)}})
	if verifyAny(t, srv, bob).Code != http.StatusOK {
		t.Error("signing out one other session ended the person's own")
	}
	if n := authEvents(t, srv, "bob@example.com")[store.AuthEventSessionEnd]; n != 0 {
		t.Errorf("%d sign-outs audited for Bob, who ended nothing", n)
	}
	// "Every other device" ends only Bob's own.
	bob.postForm("/sessions/end-others", url.Values{"csrf": {csrf}})
	if verifyAny(t, srv, amy).Code != http.StatusOK || liveCount(srv, "breakglass:bob@example.com") != 1 {
		t.Fatal("Bob's every other device ended someone else's session")
	}
	if verifyAny(t, srv, bobPhone).Code != http.StatusFound || verifyAny(t, srv, bob).Code != http.StatusOK {
		t.Error("Bob's every other device did not end exactly his other session")
	}
}

// Every post needs the form token and a same-origin form.
func TestOwnSessionsPostsNeedTheFormToken(t *testing.T) {
	srv, sender := testServer(t)
	anyGuard(t, srv)
	phone, laptop := newClient(t, srv.Handler()), newClient(t, srv.Handler())
	loginOnPhone(t, phone, sender, "amy@example.com")
	loginAs(t, laptop, sender, "amy@example.com", nil)
	phoneID := strconv.FormatInt(sessionID(t, srv, phone), 10)
	csrf := adminCSRF(t, laptop, "/sessions?confirm=others")

	for path, form := range map[string]url.Values{
		"/sessions/end-one":    {"id": {phoneID}},
		"/sessions/end-others": {},
	} {
		if rec := laptop.postForm(path, form); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), msgOwnExpired) {
			t.Errorf("%s without the form token = %d", path, rec.Code)
		}
		bad := url.Values{"csrf": {"forged"}}
		for k, v := range form {
			bad[k] = v
		}
		if rec := laptop.postForm(path, bad); rec.Code != http.StatusForbidden {
			t.Errorf("%s with a forged form token = %d", path, rec.Code)
		}
		good := url.Values{"csrf": {csrf}}
		for k, v := range form {
			good[k] = v
		}
		if rec := laptop.postWith(path, good, map[string]string{"Origin": "https://app.example.com", "Sec-Fetch-Site": "same-site"}); rec.Code == http.StatusFound {
			t.Errorf("%s from a sibling site was accepted", path)
		}
	}
	if verifyAny(t, srv, phone).Code != http.StatusOK || verifyAny(t, srv, laptop).Code != http.StatusOK || authEvents(t, srv, "amy@example.com")[store.AuthEventSessionEnd] != 0 {
		t.Fatal("a refused post ended a session")
	}
}

// "Sign out on every other device" ends every other session of the person
// and keeps this browser signed in, under a new token, so a copy of this
// browser's cookie ends too. It is audited and emailed to the person.
func TestOwnSignOutEveryOtherDevice(t *testing.T) {
	srv, sender := testServer(t)
	anyGuard(t, srv)
	phone, tablet, laptop, bob := newClient(t, srv.Handler()), newClient(t, srv.Handler()), newClient(t, srv.Handler()), newClient(t, srv.Handler())
	loginOnPhone(t, phone, sender, "amy@example.com")
	loginAs(t, tablet, sender, "amy@example.com", nil)
	loginAs(t, laptop, sender, "amy@example.com", nil)
	loginAs(t, bob, sender, "bob@example.com", nil)
	stolen := clientWith(t, srv, laptop.cookies[session.SessionCookie])
	before := readSession(t, srv, laptop)

	if ask := laptop.get("/sessions?confirm=others", nil).Body.String(); !strings.Contains(ask, msgOwnAskOthers) || !strings.Contains(ask, `action="/sessions/end-others"`) {
		t.Fatal("signing out every other device is not confirmed in place")
	}
	csrf := adminCSRF(t, laptop, "/sessions?confirm=others")
	rec := laptop.postWith("/sessions/end-others", url.Values{"csrf": {csrf}}, map[string]string{"User-Agent": macChromeUA})
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != ownSessionsPath {
		t.Fatalf("sign out every other device = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if verifyAny(t, srv, phone).Code != http.StatusFound || verifyAny(t, srv, tablet).Code != http.StatusFound {
		t.Error("a session on another device survived")
	}
	if verifyAny(t, srv, laptop).Code != http.StatusOK {
		t.Fatal("signing out every other device ended this browser's session")
	}
	if verifyAny(t, srv, stolen).Code != http.StatusFound {
		t.Error("a copy of this browser's cookie survived signing out every other device")
	}
	if verifyAny(t, srv, bob).Code != http.StatusOK {
		t.Error("signing out every other device ended another person's session")
	}
	after := readSession(t, srv, laptop)
	if after.SID == before.SID || after.Auth != before.Auth || after.Email != before.Email || after.Groups != before.Groups {
		t.Errorf("the new token's session = %+v, was %+v", after, before)
	}
	if n := liveCount(srv, "amy@example.com"); n != 1 {
		t.Errorf("%d sessions of Amy, want 1", n)
	}
	if !strings.Contains(laptop.get("/sessions", nil).Body.String(), msgOwnOthersEnded) {
		t.Error("Your sessions does not confirm the other sessions have ended")
	}
	if authEvents(t, srv, "amy@example.com")[store.AuthEventSessionsEndOthers] != 1 {
		t.Error("signing out every other device was not audited")
	}
	m := waitNotice(t, sender, "amy@example.com", msgOwnSubjectOthers)
	if !strings.Contains(m.Text, "Your sessions on every other device at auth.example.com were signed out on ") || !strings.Contains(m.Text, ", from Chrome on Mac.") {
		t.Errorf("the notice reads %q", m.Text)
	}
	if noticesTo(sender, "admin@example.com", msgOwnSubjectOthers) != 0 {
		t.Error("the administrators were emailed about a person's own sign-out")
	}
	// With no other session left, the action is not offered.
	if strings.Contains(laptop.get("/sessions", nil).Body.String(), "confirm=others") {
		t.Error("every other device is offered with no other session")
	}
}

// A session ended while the person's own request was on its way ends
// nothing: a stolen copy that has been signed out cannot sign its owner out.
func TestOwnSessionEndedMeanwhileEndsNothing(t *testing.T) {
	srv, sender := testServer(t)
	phone, laptop := newClient(t, srv.Handler()), newClient(t, srv.Handler())
	loginOnPhone(t, phone, sender, "amy@example.com")
	loginAs(t, laptop, sender, "amy@example.com", nil)
	id := readSession(t, srv, laptop)
	if _, err := srv.endSessionsWhere(context.Background(), func(x *store.Session) bool { return x.ID == id.SID }); err != nil {
		t.Fatal(err)
	}
	ended, live, err := srv.endOwnSessions(context.Background(), id, func(*store.Session) bool { return true })
	if err != nil || live || len(ended) != 0 {
		t.Fatalf("ended %d, live %v, err %v", len(ended), live, err)
	}
	if liveCount(srv, "amy@example.com") != 1 {
		t.Error("a session that had ended signed out the person's other session")
	}
}

// A break-glass card's session and a guest's have no Your sessions, and
// cannot end anything through it; a member's has.
func TestOwnSessionsRefuseCardsAndGuests(t *testing.T) {
	srv, sender := guestServer(t)
	anyGuard(t, srv)
	srv.store.CreateGroup(context.Background(), "ward", "")
	token := mintCode(t, srv, "Ward", "ward")
	card := newClient(t, srv.Handler())
	if rec := card.scan(token); rec.Code != http.StatusFound {
		t.Fatalf("scan = %d", rec.Code)
	}
	card2 := newClient(t, srv.Handler())
	card2.scan(token)
	guest, guest2 := newClient(t, srv.Handler()), newClient(t, srv.Handler())
	loginGuest(t, guest, sender, "stranger@elsewhere.org")
	loginGuest(t, guest2, sender, "stranger@elsewhere.org")
	member := mintSession(t, srv, session.Identity{Email: "amy@example.com", Groups: "user", Kind: session.KindMember}, time.Hour)

	for name, c := range map[string]*client{"card": card, "guest": guest} {
		rec := c.get("/sessions", nil)
		if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/login") {
			t.Errorf("a %s session opened Your sessions: %d", name, rec.Code)
		}
		if strings.Contains(c.get("/welcome", nil).Body.String(), `href="/sessions"`) {
			t.Errorf("the welcome page links a %s session to Your sessions", name)
		}
		for _, path := range []string{"/sessions/end-one", "/sessions/end-others"} {
			c.postForm(path, url.Values{"csrf": {"x"}, "id": {strconv.FormatInt(sessionID(t, srv, card2), 10)}})
		}
	}
	if liveCount(srv, "breakglass:Ward") != 2 || liveCount(srv, "stranger@elsewhere.org") != 2 {
		t.Error("a card's or a guest's session ended a session")
	}
	if rec := member.get("/sessions", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), msgSessThisBrowser) {
		t.Errorf("a member's Your sessions = %d", rec.Code)
	}
}
