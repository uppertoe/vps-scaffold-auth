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

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/email"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// mintSession starts a session as the gateway would at sign-in, and returns
// a client holding its cookie.
func mintSession(t *testing.T, srv *Server, id session.Identity, ttl time.Duration) *client {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := srv.startSession(rec, httptest.NewRequest("GET", "/", nil), id, ttl, srv.now()); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv.Handler())
	for _, ck := range rec.Result().Cookies() {
		c.cookies[ck.Name] = ck
	}
	return c
}

// adminRemovesPasskeys removes every passkey of email from the access page,
// as an administrator would.
func adminRemovesPasskeys(t *testing.T, srv *Server, sender *captureSender, email string) {
	t.Helper()
	admin := newClient(t, srv.Handler())
	loginAs(t, admin, sender, "admin@example.com", nil)
	csrf := adminCSRF(t, admin, "/admin/access?email="+email)
	if rec := admin.postForm("/admin/passkeys/remove", url.Values{"csrf": {csrf}, "email": {email}}); rec.Code != http.StatusFound {
		t.Fatalf("admin remove passkeys: %d", rec.Code)
	}
}

// legacyCookie mints a session cookie in the format every build before the
// sessions table issued: the whole identity in a signed envelope.
func legacyCookie(t *testing.T, srv *Server, id session.Identity, exp time.Time) *http.Cookie {
	t.Helper()
	v, err := srv.sessions.EncodeLegacySession(id, exp)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: session.SessionCookie, Value: v}
}

func clientWith(t *testing.T, srv *Server, ck *http.Cookie) *client {
	c := newClient(t, srv.Handler())
	c.cookies[ck.Name] = ck
	return c
}

func liveCount(srv *Server, email string) int { return len(srv.liveSessionsNow(email, srv.now())) }

// waitNotice waits for a message to an administrator whose subject is
// subject; the notices are sent off the request.
func waitNotice(t *testing.T, sender *captureSender, to, subject string) email.Message {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		sender.mu.Lock()
		for _, m := range sender.notices {
			if m.To == to && m.Subject == subject {
				sender.mu.Unlock()
				return m
			}
		}
		sender.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no notice %q to %s", subject, to)
	return email.Message{}
}

// A deploy signs nobody out: a valid old-format cookie of each kind is
// accepted at its next request and becomes a session row, keeping its
// sign-in time, lifetime, groups and passkey, and /verify hands the browser
// the new cookie at once. The row then answers for that old cookie too, so a
// browser that has not yet stored the new cookie (parallel requests) is
// still signed in, and one row is made, not one per request.
func TestOldCookieIsConvertedWithoutSigningAnyoneOut(t *testing.T) {
	srv, _ := testServerWith(t, func(c *config.Config) { c.SessionMaxAge = 30 * 24 * time.Hour })
	now := srv.now()
	guard := anyGuard(t, srv)
	cases := []session.Identity{
		{Email: "amy@example.com", Groups: "user", Iat: now.Add(-10 * time.Minute).Unix(), Auth: now.Add(-3 * 24 * time.Hour).Unix(), TTL: 3600},
		{Email: "remembered@example.com", Groups: "user", Iat: now.Add(-2 * time.Hour).Unix(), Auth: now.Add(-20 * 24 * time.Hour).Unix(), TTL: 30 * 24 * 3600},
		{Email: "pk@example.com", Groups: "user", Iat: now.Add(-5 * time.Minute).Unix(), Auth: now.Add(-time.Hour).Unix(), PK: 7},
		{Email: "admin@example.com", Groups: "admin", Iat: now.Add(-5 * time.Minute).Unix(), Auth: now.Add(-time.Hour).Unix(), TOTP: true, Step: now.Add(-time.Hour).Unix()},
	}
	for _, id := range cases {
		ck := legacyCookie(t, srv, id, now.Add(50*time.Minute))
		c := clientWith(t, srv, ck)
		rec := c.get("/verify", guard)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: an old cookie was refused at the deploy: %d", id.Email, rec.Code)
		}
		got := c.cookies[session.SessionCookie]
		if got == nil || session.IsLegacy(got.Value) {
			t.Fatalf("%s: /verify did not hand over the new cookie", id.Email)
		}
		x := srv.liveSessionsNow(id.Email, srv.now())
		if len(x) != 1 || x[0].SignedIn.Unix() != id.Auth || x[0].Groups != id.Groups || x[0].Passkey != id.PK || x[0].TOTP != id.TOTP || x[0].Step != id.Step {
			t.Fatalf("%s: converted row = %+v", id.Email, x)
		}
		if id.TTL != 0 && int64(x[0].TTL.Seconds()) != id.TTL {
			t.Errorf("%s: the remembered lifetime was not kept: %s", id.Email, x[0].TTL)
		}
		// The same old cookie again, as a parallel request would carry it.
		if rec := clientWith(t, srv, ck).get("/verify", guard); rec.Code != http.StatusOK {
			t.Fatalf("%s: a second request with the old cookie was refused: %d", id.Email, rec.Code)
		}
		if n := liveCount(srv, id.Email); n != 1 {
			t.Fatalf("%s: %d rows for one old cookie", id.Email, n)
		}
		// The new cookie works on its own.
		if rec := c.get("/verify", guard); rec.Code != http.StatusOK {
			t.Fatalf("%s: the new cookie was refused: %d", id.Email, rec.Code)
		}
	}
}

// Once converted, an old cookie is revocable like any session, and stays
// revoked: deleting the row refuses the old cookie too, rather than
// converting it again.
func TestConvertedOldCookieIsRevocable(t *testing.T) {
	srv, sender := testServer(t)
	now := srv.now()
	guard := anyGuard(t, srv)
	id := session.Identity{Email: "amy@example.com", Groups: "user", Iat: now.Add(-time.Minute).Unix(), Auth: now.Add(-time.Hour).Unix()}
	ck := legacyCookie(t, srv, id, now.Add(time.Hour))
	browser := clientWith(t, srv, ck)
	if browser.get("/verify", guard).Code != http.StatusOK {
		t.Fatal("old cookie refused")
	}
	stolen := clientWith(t, srv, ck) // a copy taken before the deploy
	x := srv.liveSessionsNow("amy@example.com", srv.now())[0]

	admin := newClient(t, srv.Handler())
	loginAs(t, admin, sender, "admin@example.com", nil)
	csrf := adminCSRF(t, admin, sessionsPath+"?confirm=everyone")
	if rec := admin.postForm("/admin/sessions/end-one", url.Values{"csrf": {csrf}, "id": {strconv.FormatInt(x.ID, 10)}}); rec.Code != http.StatusFound {
		t.Fatalf("sign out one session: %d", rec.Code)
	}
	for name, c := range map[string]*client{"the new cookie": browser, "the old cookie": stolen} {
		if rec := c.get("/verify", guard); rec.Code != http.StatusFound {
			t.Errorf("%s still works after the session was signed out: %d", name, rec.Code)
		}
	}
	if n := liveCount(srv, "amy@example.com"); n != 0 {
		t.Errorf("the old cookie was converted again: %d rows", n)
	}
}

// A converted old cookie is honoured only until its own expiry, however long
// the row it reached is renewed through the new cookie.
func TestOldCookieGainsNoTime(t *testing.T) {
	srv, _ := testServer(t) // SESSION_TTL 1h, renewal after 30m
	start := time.Now()
	srv.now = func() time.Time { return start }
	guard := anyGuard(t, srv)
	ck := legacyCookie(t, srv, session.Identity{Email: "amy@example.com", Groups: "user", Iat: start.Unix(), Auth: start.Unix(), TTL: 3600}, start.Add(50*time.Minute))
	browser := clientWith(t, srv, ck)
	if browser.get("/verify", guard).Code != http.StatusOK {
		t.Fatal("old cookie refused")
	}
	// The real browser renews the session past the old cookie's expiry.
	srv.now = func() time.Time { return start.Add(31 * time.Minute) }
	if browser.get("/verify", guard).Code != http.StatusOK {
		t.Fatal("the converted session did not renew")
	}
	srv.now = func() time.Time { return start.Add(49 * time.Minute) }
	if clientWith(t, srv, ck).get("/verify", guard).Code != http.StatusOK {
		t.Fatal("a copy of the old cookie was refused within its own lifetime")
	}
	srv.now = func() time.Time { return start.Add(51 * time.Minute) }
	if rec := clientWith(t, srv, ck).get("/verify", guard); rec.Code != http.StatusFound {
		t.Fatalf("a copy of the old cookie outlived its own expiry: %d", rec.Code)
	}
	if browser.get("/verify", guard).Code != http.StatusOK {
		t.Fatal("the renewed session ended with the old cookie")
	}
}

// An old cookie is checked exactly as before when it arrives: one from
// before its person signed out everywhere, before its card was withdrawn,
// before "sign out everyone", from before the sign-in time was recorded, or
// past SESSION_MAX_AGE, is refused and not converted. A revocation made after
// the deploy reaches an old cookie that has not yet been seen.
func TestOldCookieIsCheckedBeforeConversion(t *testing.T) {
	srv, sender := testServerWith(t, func(c *config.Config) { c.SessionMaxAge = 7 * 24 * time.Hour })
	now := srv.now()
	guard := anyGuard(t, srv)
	old := func(email string, auth time.Time) *client {
		return clientWith(t, srv, legacyCookie(t, srv, session.Identity{Email: email, Groups: "user", Iat: now.Add(-time.Minute).Unix(), Auth: auth.Unix()}, now.Add(time.Hour)))
	}
	before := now.Add(-time.Hour)
	if err := srv.store.EndSessionsBefore(context.Background(), "gone@example.com", now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	refused := map[string]*client{
		"signed out everywhere before the deploy": old("gone@example.com", before),
		"no sign-in time":                         old("ancient@example.com", time.Unix(0, 0)),
		"past SESSION_MAX_AGE":                    old("stale@example.com", now.Add(-8*24*time.Hour)),
	}
	// After the deploy, an administrator signs bob out everywhere before his
	// old cookie has been seen.
	bob := old("bob@example.com", before)
	admin := newClient(t, srv.Handler())
	loginAs(t, admin, sender, "admin@example.com", nil)
	csrf := adminCSRF(t, admin, "/admin/access?email=bob@example.com")
	if rec := admin.postForm("/admin/sessions/end", url.Values{"csrf": {csrf}, "email": {"bob@example.com"}}); rec.Code != http.StatusFound {
		t.Fatalf("sign out everywhere: %d", rec.Code)
	}
	refused["signed out everywhere after the deploy"] = bob
	for name, c := range refused {
		if rec := c.get("/verify", guard); rec.Code != http.StatusFound {
			t.Errorf("%s: old cookie admitted: %d", name, rec.Code)
		}
	}
	if n := len(srv.liveSessionsNow("", srv.now())); n != 1 {
		t.Errorf("%d sessions, want only the administrator's", n)
	}
	// Sign out everyone reaches the old cookies not yet seen too, and keeps
	// the administrator's own session.
	carol := old("carol@example.com", before)
	csrf = adminCSRF(t, admin, sessionsPath+"?confirm=everyone")
	if rec := admin.postForm("/admin/sessions/end-all", url.Values{"csrf": {csrf}}); rec.Code != http.StatusFound {
		t.Fatalf("sign out everyone: %d", rec.Code)
	}
	if rec := carol.get("/verify", guard); rec.Code != http.StatusFound {
		t.Errorf("an old cookie outlived sign out everyone: %d", rec.Code)
	}
	if rec := admin.get(sessionsPath, nil); rec.Code != http.StatusOK {
		t.Errorf("sign out everyone signed out the administrator who did it: %d", rec.Code)
	}
}

// The Sessions page lists each session with its kind, times and device;
// signing out one session ends only that one; signing out everyone ends every
// session but the administrator's own. Each action is confirmed in place,
// audited and emailed to the other administrators.
func TestAdminSessionsPage(t *testing.T) {
	srv, sender := testServerWith(t, func(c *config.Config) {
		c.AdminEmails = []string{"admin@example.com", "other@example.com"}
	})
	anyGuard(t, srv)
	phone, laptop := newClient(t, srv.Handler()), newClient(t, srv.Handler())
	phoneUA := map[string]string{"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"}
	sender.reset()
	phone.do(withHeaders(httptest.NewRequest(http.MethodPost, "/request", strings.NewReader("email=amy%40example.com")), phoneUA))
	phone.do(withHeaders(httptest.NewRequest(http.MethodPost, "/verify-code", strings.NewReader("code="+sender.code())), phoneUA))
	loginAs(t, laptop, sender, "amy@example.com", nil)
	admin := newClient(t, srv.Handler())
	loginAs(t, admin, sender, "admin@example.com", nil)

	page := admin.get(sessionsPath+"?email=amy@example.com", nil).Body.String()
	for _, want := range []string{"amy@example.com is signed in on two browsers.", "Safari on iPhone", msgSessDeviceUnknown, msgSessKindStaff, msgSessSignOutPerson} {
		if !strings.Contains(page, want) {
			t.Errorf("the Sessions page does not show %q", want)
		}
	}
	var phoneRow store.Session
	for _, x := range srv.liveSessionsNow("amy@example.com", srv.now()) {
		if x.Device == "Safari on iPhone" {
			phoneRow = x
		}
	}
	ask := admin.get(sessionsPath+"?email=amy@example.com&confirm=one&id="+strconv.FormatInt(phoneRow.ID, 10), nil).Body.String()
	if !strings.Contains(ask, "Once you sign out this session, amy@example.com needs to sign in again on Safari on iPhone.") || !strings.Contains(ask, `action="/admin/sessions/end-one"`) {
		t.Fatal("signing out a session is not confirmed in place")
	}
	csrf := adminCSRF(t, admin, sessionsPath+"?confirm=everyone")
	if rec := admin.postForm("/admin/sessions/end-one", url.Values{"csrf": {csrf}, "id": {strconv.FormatInt(phoneRow.ID, 10)}, "email": {"amy@example.com"}}); rec.Code != http.StatusFound || rec.Header().Get("Location") != sessionsPath+"?email=amy%40example.com" {
		t.Fatalf("sign out one: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if !strings.Contains(admin.get(sessionsPath+"?email=amy@example.com", nil).Body.String(), "The session has ended.") {
		t.Error("the page does not confirm the session has ended")
	}
	if verifyAny(t, srv, phone).Code != http.StatusFound || verifyAny(t, srv, laptop).Code != http.StatusOK {
		t.Fatal("signing out one session did not end exactly that session")
	}
	waitNotice(t, sender, "other@example.com", "A session of amy@example.com has ended.")

	// Sign out everyone, from the confirmation.
	if !strings.Contains(admin.get(sessionsPath+"?confirm=everyone", nil).Body.String(), msgSessAskEveryone) {
		t.Fatal("sign out everyone is not confirmed in place")
	}
	if rec := admin.postForm("/admin/sessions/end-all", url.Values{"csrf": {csrf}}); rec.Code != http.StatusFound {
		t.Fatalf("sign out everyone: %d", rec.Code)
	}
	if verifyAny(t, srv, laptop).Code != http.StatusFound {
		t.Error("sign out everyone left a session")
	}
	if got := admin.get(sessionsPath, nil); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "Everyone except you has been signed out.") || !strings.Contains(got.Body.String(), msgSessThisBrowser) {
		t.Errorf("after sign out everyone, the administrator's page = %d", got.Code)
	}
	waitNotice(t, sender, "other@example.com", msgSessSubjectAll)
	events, _ := srv.store.ListAdminEvents(context.Background(), 20, 0)
	seen := map[string]bool{}
	for _, e := range events {
		seen[e.Action] = true
	}
	if !seen[store.AdminActionSessionEnd] || !seen[store.AdminActionSessionsEndAll] {
		t.Errorf("the actions were not audited: %v", seen)
	}
	// A session that has already ended is reported, not acted on.
	if rec := admin.postForm("/admin/sessions/end-one", url.Values{"csrf": {csrf}, "id": {strconv.FormatInt(phoneRow.ID, 10)}}); rec.Code != http.StatusFound {
		t.Fatal(rec.Code)
	}
	if !strings.Contains(admin.get(sessionsPath, nil).Body.String(), "The session had already ended") {
		t.Error("an ended session was not reported as already ended")
	}
}

func withHeaders(r *http.Request, h map[string]string) *http.Request {
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range h {
		r.Header.Set(k, v)
	}
	return r
}

// Signing out ends the session on the gateway: a copy of the cookie taken
// before no longer works.
func TestSignOutEndsTheSessionNotOnlyTheCookie(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "amy@example.com", nil)
	copied := clientWith(t, srv, c.cookies[session.SessionCookie])
	c.postForm("/logout", url.Values{})
	if rec := verifyAny(t, srv, copied); rec.Code != http.StatusFound {
		t.Fatalf("a copy of a signed-out cookie still works: %d", rec.Code)
	}
}

// Sessions survive a restart; the database holds only the token's hash; the
// last-seen time is written at most every few minutes; expired rows are
// deleted.
func TestSessionLifecycle(t *testing.T) {
	srv, sender := testServer(t)
	start := time.Now()
	srv.now = func() time.Time { return start }
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "amy@example.com", nil)
	token := c.cookies[session.SessionCookie].Value
	rows, _ := srv.store.ListSessions(context.Background(), start)
	if len(rows) != 1 || string(rows[0].Hash) == token || string(rows[0].Hash) != string(session.TokenHash(token)) {
		t.Fatal("the database does not hold only the token's hash")
	}

	srv.now = func() time.Time { return start.Add(2 * time.Minute) }
	verifyAny(t, srv, c)
	rows, _ = srv.store.ListSessions(context.Background(), start)
	if !rows[0].LastSeen.Equal(start.Truncate(time.Second)) {
		t.Errorf("last seen written after two minutes: %s", rows[0].LastSeen)
	}
	srv.now = func() time.Time { return start.Add(6 * time.Minute) }
	verifyAny(t, srv, c)
	rows, _ = srv.store.ListSessions(context.Background(), start)
	if rows[0].LastSeen.Unix() != start.Add(6*time.Minute).Unix() {
		t.Errorf("last seen not written after six minutes: %s", rows[0].LastSeen)
	}

	// A restart: a new gateway on the same database.
	again, err := New(srv.cfg, srv.store, sender)
	if err != nil {
		t.Fatal(err)
	}
	again.now = srv.now
	h := newClient(t, again.Handler())
	h.cookies = c.cookies
	if rec := h.get("/verify", anyGuard(t, again)); rec.Code != http.StatusOK {
		t.Fatalf("a session did not survive a restart: %d", rec.Code)
	}

	// Past its expiry the session is refused, and a later sign-in deletes it.
	srv.now = func() time.Time { return start.Add(3 * time.Hour) }
	if verifyAny(t, srv, c).Code != http.StatusFound {
		t.Fatal("an expired session was admitted")
	}
	loginAs(t, newClient(t, srv.Handler()), sender, "bob@example.com", nil)
	all, _ := srv.store.ListSessions(context.Background(), time.Unix(0, 0))
	for _, x := range all {
		if x.Email == "amy@example.com" {
			t.Error("an expired session was not deleted")
		}
	}
}

// With the database unavailable, existing sessions are still read, from
// memory, and an old cookie that cannot be converted is answered 503 and
// kept, not signed out. (Whether a request is then admitted is for the role
// data, which behaves as before.)
func TestDatabaseUnavailable(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "amy@example.com", nil)
	guard := anyGuard(t, srv)
	now := srv.now()
	old := clientWith(t, srv, legacyCookie(t, srv, session.Identity{Email: "bob@example.com", Groups: "user", Iat: now.Unix(), Auth: now.Unix()}, now.Add(time.Hour)))
	srv.store.Close()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(c.cookies[session.SessionCookie])
	if _, ok := srv.readSession(req, srv.now()); !ok {
		t.Error("a session could not be read while the database was unavailable")
	}
	rec := old.get("/verify", guard)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("an old cookie with the database unavailable = %d, want 503", rec.Code)
	}
	if old.cookies[session.SessionCookie] == nil {
		t.Error("the old cookie was cleared while the database was unavailable")
	}
}
