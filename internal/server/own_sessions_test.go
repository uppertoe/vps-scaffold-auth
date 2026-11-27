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
	// His own session, posted as "one", is not ended, and the page says so.
	bob.postForm("/sessions/end-one", url.Values{"csrf": {csrf}, "id": {strconv.FormatInt(sessionID(t, srv, bob), 10)}})
	if verifyAny(t, srv, bob).Code != http.StatusOK {
		t.Error("signing out one other session ended the person's own")
	}
	if !strings.Contains(bob.get("/sessions", nil).Body.String(), msgOwnThisBrowser) {
		t.Error("posting this browser's own session as another is not reported as such")
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

// A break-glass card's session has no Your sessions, and cannot end anything
// through it; a guest's and a member's have the page. A guest ends only its
// own sessions: a card's session is never one of them.
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

	rec := card.get("/sessions", nil)
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/login") {
		t.Errorf("a card session opened Your sessions: %d", rec.Code)
	}
	if strings.Contains(card.get("/welcome", nil).Body.String(), `href="/sessions"`) {
		t.Error("the welcome page links a card session to Your sessions")
	}
	cardID := strconv.FormatInt(sessionID(t, srv, card2), 10)
	for _, path := range []string{"/sessions/end-one", "/sessions/end-others"} {
		card.postForm(path, url.Values{"csrf": {"x"}, "id": {cardID}})
	}
	if liveCount(srv, "breakglass:Ward") != 2 || liveCount(srv, "stranger@elsewhere.org") != 2 {
		t.Fatal("a card's session ended a session")
	}

	// A guest has the page, with both of its sessions, and its form token
	// cannot end a card's session.
	page := guest.get("/sessions", nil)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), msgSessThisBrowser) {
		t.Fatalf("a guest's Your sessions = %d", page.Code)
	}
	if !strings.Contains(guest.get("/welcome", nil).Body.String(), `href="/sessions"`) {
		t.Error("the welcome page does not link a guest session to Your sessions")
	}
	tok := adminCSRF(t, guest, "/sessions?confirm=others")
	guest.postForm("/sessions/end-one", url.Values{"csrf": {tok}, "id": {cardID}})
	if liveCount(srv, "breakglass:Ward") != 2 {
		t.Error("a guest ended a card's session")
	}
	guest.postForm("/sessions/end-others", url.Values{"csrf": {tok}})
	if liveCount(srv, "breakglass:Ward") != 2 || liveCount(srv, "stranger@elsewhere.org") != 1 {
		t.Errorf("after a guest signed out on every other device: card %d, guest %d; want 2 and 1",
			liveCount(srv, "breakglass:Ward"), liveCount(srv, "stranger@elsewhere.org"))
	}
	if rec := member.get("/sessions", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), msgSessThisBrowser) {
		t.Errorf("a member's Your sessions = %d", rec.Code)
	}
}

// A card's session is never the person's, even one whose label is the
// person's bare address: it is not listed, and neither "Sign out" nor "every
// other device" ends it.
func TestOwnSessionsNeverIncludeACardSession(t *testing.T) {
	srv, sender := testServer(t)
	amy := newClient(t, srv.Handler())
	loginAs(t, amy, sender, "amy@example.com", nil)
	phone := newClient(t, srv.Handler())
	loginOnPhone(t, phone, sender, "amy@example.com")
	card := mintSession(t, srv, session.Identity{Email: "amy@example.com", Groups: "bg", Kind: session.KindBreakGlass}, time.Hour)
	cardID := sessionID(t, srv, card)
	if n := strings.Count(amy.get("/sessions", nil).Body.String(), `class="pk-row sess-row`); n != 2 {
		t.Errorf("Your sessions lists %d sessions, want 2 (not the card's)", n)
	}
	csrf := adminCSRF(t, amy, "/sessions?confirm=others")
	amy.postForm("/sessions/end-one", url.Values{"csrf": {csrf}, "id": {strconv.FormatInt(cardID, 10)}})
	amy.postForm("/sessions/end-others", url.Values{"csrf": {csrf}})
	alive := false
	for _, x := range srv.liveSessionsNow("amy@example.com", srv.now()) {
		alive = alive || x.ID == cardID
	}
	if !alive {
		t.Fatal("a card's session labelled with the person's address was ended")
	}
	if verifyAny(t, srv, phone).Code != http.StatusFound {
		t.Error("every other device did not end the person's phone")
	}
}

// A new token after signing out other sessions keeps the time the session's
// groups were worked out, so a membership change since then still reaches
// the session at its next request. Both rotations are checked: the person's
// "every other device" and an administrator's "Sign out everyone".
func TestRotationKeepsGroupsStale(t *testing.T) {
	for _, admin := range []bool{false, true} {
		srv, sender := testServer(t)
		ctx := context.Background()
		start := time.Now()
		srv.now = func() time.Time { return start }
		if err := srv.store.CreateGroup(ctx, "ward", ""); err != nil {
			t.Fatal(err)
		}
		email := "amy@example.com"
		if admin {
			email = "admin@example.com"
		}
		if err := srv.store.AddGroupMember(ctx, "ward", email); err != nil {
			t.Fatal(err)
		}
		guard := groupGuard(t, srv, "ward")
		c, other := newClient(t, srv.Handler()), newClient(t, srv.Handler())
		loginAs(t, c, sender, email, nil)
		loginAs(t, other, sender, email, nil)
		if c.get("/verify", guard).Code != http.StatusOK {
			t.Fatal("the group's member was refused before the change")
		}
		page, path := "/sessions?confirm=others", "/sessions/end-others"
		if admin {
			page, path = sessionsPath+"?confirm=everyone", "/admin/sessions/end-all"
		}
		csrf := adminCSRF(t, c, page)

		srv.now = func() time.Time { return start.Add(time.Second) }
		if err := srv.store.RemoveGroupMember(ctx, "ward", email); err != nil {
			t.Fatal(err)
		}
		srv.markGroupsChanged(srv.now())
		srv.now = func() time.Time { return start.Add(2 * time.Second) }
		if rec := c.postForm(path, url.Values{"csrf": {csrf}}); rec.Code != http.StatusFound {
			t.Fatalf("admin %v: rotate = %d", admin, rec.Code)
		}
		if verifyAny(t, srv, other).Code != http.StatusFound {
			t.Errorf("admin %v: the other session survived", admin)
		}
		if rec := c.get("/verify", guard); rec.Code == http.StatusOK {
			t.Errorf("admin %v: a session given a new token kept a group it was removed from", admin)
		}
	}
}

// rotationFailStore fails the new row or the deletion while set.
type rotationFailStore struct {
	store.Store
	failCreate, failDelete bool
}

func (f *rotationFailStore) CreateSession(ctx context.Context, x store.Session) (int64, error) {
	if f.failCreate {
		return 0, context.DeadlineExceeded
	}
	return f.Store.CreateSession(ctx, x)
}

func (f *rotationFailStore) DeleteSessions(ctx context.Context, ids []int64) error {
	if f.failDelete {
		return context.DeadlineExceeded
	}
	return f.Store.DeleteSessions(ctx, ids)
}

// If the new token or the ending cannot be written, nothing has changed and
// the person or administrator is told: every session goes on, including a
// copy of this browser's cookie, and nothing is audited or emailed as done.
func TestFailedRotationChangesNothing(t *testing.T) {
	for _, admin := range []bool{false, true} {
		for _, failCreate := range []bool{true, false} {
			srv, sender := testServer(t)
			email := "amy@example.com"
			if admin {
				email = "admin@example.com"
			}
			c, other := newClient(t, srv.Handler()), newClient(t, srv.Handler())
			loginAs(t, c, sender, email, nil)
			loginAs(t, other, sender, email, nil)
			copied := clientWith(t, srv, c.cookies[session.SessionCookie])
			page, path := "/sessions?confirm=others", "/sessions/end-others"
			if admin {
				page, path = sessionsPath+"?confirm=everyone", "/admin/sessions/end-all"
			}
			csrf := adminCSRF(t, c, page)
			fs := &rotationFailStore{Store: srv.store, failCreate: failCreate, failDelete: !failCreate}
			srv.store = fs
			rec := c.postForm(path, url.Values{"csrf": {csrf}})
			fs.failCreate, fs.failDelete = false, false
			if rec.Code != http.StatusInternalServerError || (!admin && !strings.Contains(rec.Body.String(), msgOwnFailed)) {
				t.Errorf("admin %v, create fails %v: answered %d", admin, failCreate, rec.Code)
			}
			for name, x := range map[string]*client{"this browser": c, "the copy": copied, "the other": other} {
				if verifyAny(t, srv, x).Code != http.StatusOK {
					t.Errorf("admin %v, create fails %v: %s was signed out", admin, failCreate, name)
				}
			}
			if n := liveCount(srv, email); n != 2 {
				t.Errorf("admin %v, create fails %v: %d sessions, want 2", admin, failCreate, n)
			}
			if got := authEvents(t, srv, email)[store.AuthEventSessionsEndOthers]; got != 0 {
				t.Errorf("a failed rotation was audited as done")
			}
			if events, _ := srv.store.ListAdminEvents(context.Background(), 20, 0); len(events) != 0 && admin {
				for _, e := range events {
					if e.Action == store.AdminActionSessionsEndAll {
						t.Error("a failed sign out everyone was audited as done")
					}
				}
			}
			time.Sleep(50 * time.Millisecond)
			if noticesTo(sender, email, msgOwnSubjectOthers) != 0 {
				t.Error("a failed rotation was emailed as done")
			}
		}
	}
}
