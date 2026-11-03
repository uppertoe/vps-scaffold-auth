package server

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

func adminCSRF(t *testing.T, c *client, page string) string {
	t.Helper()
	m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(c.get(page, nil).Body.String())
	if m == nil {
		t.Fatalf("no CSRF token on %s", page)
	}
	return m[1]
}

// "Sign out on every device" on the sign-out page ends the person's sessions
// everywhere, and nobody else's; they can sign in again at once.
func TestSignOutEverywhere(t *testing.T) {
	srv, sender := testServer(t)
	phone, laptop, other := newClient(t, srv.Handler()), newClient(t, srv.Handler()), newClient(t, srv.Handler())
	loginAs(t, phone, sender, "amy@example.com", nil)
	loginAs(t, laptop, sender, "amy@example.com", nil)
	loginAs(t, other, sender, "bob@example.com", nil)
	srv.now = func() time.Time { return time.Now().Add(time.Second) }

	if !strings.Contains(phone.get("/logout", nil).Body.String(), `name="everywhere" value="1"`) {
		t.Fatal("the sign-out page does not offer to sign out on every device")
	}
	if rec := phone.postForm("/logout", url.Values{"everywhere": {"1"}}); rec.Code != http.StatusFound {
		t.Fatalf("sign out everywhere = %d", rec.Code)
	}
	if rec := verifyAny(laptop); rec.Code != http.StatusFound {
		t.Errorf("the laptop's session survived: %d", rec.Code)
	}
	if rec := verifyAny(other); rec.Code != http.StatusOK {
		t.Errorf("another person's session ended: %d", rec.Code)
	}
	srv.now = func() time.Time { return time.Now().Add(2 * time.Second) }
	again := newClient(t, srv.Handler())
	loginAs(t, again, sender, "amy@example.com", nil)
	if rec := verifyAny(again); rec.Code != http.StatusOK {
		t.Errorf("signing in again after signing out everywhere = %d", rec.Code)
	}
	events, _ := srv.store.ListAuthEvents(context.Background(), "amy@example.com", 20, 0)
	found := false
	for _, e := range events {
		found = found || e.EventType == store.AuthEventSessionsEnd
	}
	if !found {
		t.Error("signing out everywhere was not recorded")
	}
	// A plain sign-out ends only this device.
	srv.now = func() time.Time { return time.Now().Add(3 * time.Second) }
	second := newClient(t, srv.Handler())
	loginAs(t, second, sender, "amy@example.com", nil)
	again.postForm("/logout", url.Values{})
	if rec := verifyAny(second); rec.Code != http.StatusOK {
		t.Errorf("a plain sign-out ended another device: %d", rec.Code)
	}
}

// An administrator can sign a person out on every device from the access
// log, and the action is audited. The cutoff survives a restart.
func TestAdminSignsAPersonOutEverywhere(t *testing.T) {
	srv, sender := testServer(t)
	user, admin := newClient(t, srv.Handler()), newClient(t, srv.Handler())
	loginAs(t, user, sender, "amy@example.com", nil)
	loginAs(t, admin, sender, "admin@example.com", nil)
	srv.now = func() time.Time { return time.Now().Add(time.Second) }

	if strings.Contains(admin.get("/admin/access?email=amy", nil).Body.String(), `action="/admin/sessions/end"`) {
		t.Error("signing out everywhere offered for part of an address")
	}
	csrf := adminCSRF(t, admin, "/admin/access?email=amy%40example.com")
	if rec := admin.postForm("/admin/sessions/end", url.Values{"csrf": {csrf}, "email": {"amy@example.com"}}); rec.Code != http.StatusFound {
		t.Fatalf("end sessions = %d", rec.Code)
	}
	stolen := map[string]*http.Cookie{}
	for k, v := range user.cookies {
		stolen[k] = v
	}
	if rec := verifyAny(user); rec.Code != http.StatusFound {
		t.Errorf("amy's session survived: %d", rec.Code)
	}
	if rec := verifyAny(admin); rec.Code != http.StatusOK {
		t.Errorf("the administrator's own session ended: %d", rec.Code)
	}
	events, _ := srv.store.ListAdminEvents(context.Background(), 10, 0)
	if len(events) == 0 || events[0].Action != store.AdminActionSessionsEnd || events[0].Target != "amy@example.com" {
		t.Errorf("not audited: %+v", events)
	}
	if rec := admin.postForm("/admin/sessions/end", url.Values{"email": {"bob@example.com"}}); rec.Code == http.StatusFound {
		t.Error("signing someone out everywhere worked without the form token")
	}
	// A new gateway on the same database still refuses the old session.
	restarted, err := New(srv.cfg, srv.store, srv.sender)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = srv.now
	rc := &client{t: t, h: restarted.Handler(), cookies: stolen}
	if rec := verifyAny(rc); rec.Code != http.StatusFound {
		t.Errorf("after a restart amy's old session works again: %d", rec.Code)
	}
}

// No session outlives SESSION_MAX_AGE from sign-in, however often it renews.
func TestSessionMaxAge(t *testing.T) {
	srv, sender := testServer(t)
	srv.cfg.SessionMaxAge = 48 * time.Hour
	start := time.Now()
	srv.now = func() time.Time { return start }
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "amy@example.com", nil)
	// Keep the session busy so it renews well before every expiry.
	step := srv.cfg.SessionRenew + time.Minute
	at := start
	for at.Add(step).Before(start.Add(48 * time.Hour)) {
		at = at.Add(step)
		now := at
		srv.now = func() time.Time { return now }
		if rec := verifyAny(c); rec.Code != http.StatusOK {
			t.Fatalf("at %s: %d", now.Sub(start), rec.Code)
		}
	}
	// The session is still live (renewed under a minute and a renewal
	// period ago), but it is past its maximum age.
	srv.now = func() time.Time { return start.Add(48*time.Hour + time.Second) }
	if rec := verifyAny(c); rec.Code != http.StatusFound {
		t.Fatalf("a session renewed past its maximum age: %d", rec.Code)
	}
}

// Removing someone from a group takes effect at their next request, not at
// their next scheduled renewal.
func TestGroupRemovalTakesEffectAtOnce(t *testing.T) {
	srv, sender := testServer(t)
	ctx := context.Background()
	srv.store.CreateGroup(ctx, "team", "")
	srv.store.AddGroupMember(ctx, "team", "amy@example.com")
	user, admin := newClient(t, srv.Handler()), newClient(t, srv.Handler())
	loginAs(t, user, sender, "amy@example.com", nil)
	loginAs(t, admin, sender, "admin@example.com", nil)
	if rec := user.get("/verify", requireGroups("team")); rec.Code != http.StatusOK {
		t.Fatalf("before removal = %d", rec.Code)
	}
	srv.now = func() time.Time { return time.Now().Add(time.Second) }
	csrf := adminCSRF(t, admin, "/admin/groups/team")
	if rec := admin.postForm("/admin/groups/team/members/delete", url.Values{"csrf": {csrf}, "email": {"amy@example.com"}}); rec.Code != http.StatusFound {
		t.Fatalf("remove member = %d", rec.Code)
	}
	if rec := user.get("/verify", requireGroups("team")); rec.Code == http.StatusOK {
		t.Fatal("a removed member still reaches the group's app")
	}
	if rec := verifyAny(user); rec.Code != http.StatusOK {
		t.Errorf("removal from a group ended the whole session: %d", rec.Code)
	}
}

// Revoking or re-minting a break-glass card ends the sessions it granted;
// another card's sessions are unaffected.
func TestRevokingACardEndsItsSessions(t *testing.T) {
	for _, action := range []string{"revoke", "remint"} {
		t.Run(action, func(t *testing.T) {
			srv, sender := testServer(t)
			ctx := context.Background()
			tokA, tokB := mintCode(t, srv, "Ward A", "ward_a"), mintCode(t, srv, "Ward B", "ward_b")
			a, b := newClient(t, srv.Handler()), newClient(t, srv.Handler())
			a.get("/break/"+tokA, nil)
			b.get("/break/"+tokB, nil)
			if a.get("/verify", requireGroups("ward_a")).Code != http.StatusOK || b.get("/verify", requireGroups("ward_b")).Code != http.StatusOK {
				t.Fatal("the cards did not grant sessions")
			}
			codes, _ := srv.store.ListBreakGlassCodes(ctx)
			var idA int64
			for _, c := range codes {
				if c.Label == "Ward A" {
					idA = c.ID
				}
			}
			srv.now = func() time.Time { return time.Now().Add(time.Second) }
			admin := newClient(t, srv.Handler())
			loginAs(t, admin, sender, "admin@example.com", nil)
			path := "/admin/break/" + strconv.FormatInt(idA, 10)
			if rec := admin.postForm(path+"/"+action, url.Values{"csrf": {adminCSRF(t, admin, path)}}); rec.Code != http.StatusFound {
				t.Fatalf("%s = %d", action, rec.Code)
			}
			if rec := a.get("/verify", requireGroups("ward_a")); rec.Code == http.StatusOK {
				t.Errorf("the card's session survived %s", action)
			}
			if rec := b.get("/verify", requireGroups("ward_b")); rec.Code != http.StatusOK {
				t.Errorf("another card's session ended: %d", rec.Code)
			}
		})
	}
}

// Replacing or removing an administrator's authenticator ends every session
// it passed; issuing a first secret ends nothing.
func TestReplacingAnAuthenticatorEndsSessions(t *testing.T) {
	srv, sender := testServer(t)
	admin, elsewhere := newClient(t, srv.Handler()), newClient(t, srv.Handler())
	loginAs(t, admin, sender, "admin@example.com", nil)
	loginAs(t, elsewhere, sender, "admin@example.com", nil)
	step := 0
	tick := func() {
		step++
		at := time.Now().Add(time.Duration(step) * time.Second)
		srv.now = func() time.Time { return at }
	}
	tick()
	if rec := admin.postForm("/admin/totp/generate", url.Values{"csrf": {adminCSRF(t, admin, "/admin/totp")}, "email": {"admin@example.com"}}); rec.Code != http.StatusOK {
		t.Fatalf("first secret = %d", rec.Code)
	}
	if rec := verifyAny(elsewhere); rec.Code != http.StatusOK {
		t.Fatalf("a first secret ended a session: %d", rec.Code)
	}
	tick()
	if rec := admin.postForm("/admin/totp/generate", url.Values{"csrf": {adminCSRF(t, admin, "/admin/totp")}, "email": {"admin@example.com"}}); rec.Code != http.StatusOK {
		t.Fatalf("replacing the secret = %d", rec.Code)
	}
	if rec := verifyAny(elsewhere); rec.Code != http.StatusFound {
		t.Fatalf("replacing the secret left a session running: %d", rec.Code)
	}
	tick()
	other := newClient(t, srv.Handler())
	loginAs(t, other, sender, "admin@example.com", nil)
	tick()
	if rec := other.postForm("/admin/totp/remove", url.Values{"csrf": {adminCSRF(t, other, "/admin/totp")}, "email": {"admin@example.com"}}); rec.Code != http.StatusFound {
		t.Fatalf("remove = %d", rec.Code)
	}
	if rec := verifyAny(other); rec.Code != http.StatusFound {
		t.Fatalf("removing the secret left a session running: %d", rec.Code)
	}
}

// When maxMailSends emails are under way, another is not sent rather than
// waiting, and the slot is freed once a send finishes.
func TestMailSendsAreBounded(t *testing.T) {
	srv, _ := testServer(t)
	release := make(chan struct{})
	started := make(chan struct{}, maxMailSends)
	for i := 0; i < maxMailSends; i++ {
		srv.sendMail("held", func(ctx context.Context) error { started <- struct{}{}; <-release; return nil })
	}
	for i := 0; i < maxMailSends; i++ {
		<-started
	}
	ran := make(chan struct{}, 1)
	srv.sendMail("extra", func(ctx context.Context) error { ran <- struct{}{}; return nil })
	select {
	case <-ran:
		t.Fatal("a send started beyond the bound")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for len(srv.mailSlots) > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	srv.sendMail("after", func(ctx context.Context) error { ran <- struct{}{}; return nil })
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("no send started once the others had finished")
	}
}
