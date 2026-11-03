package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// Each sign-in is one row however many steps it took, and a refused step is a
// row of its own.
func TestAccessLogFoldsEachSignInIntoOneRow(t *testing.T) {
	srv, _ := testServer(t)
	at := time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)
	ev := func(min int, email, step, outcome string) store.AuthEvent {
		return store.AuthEvent{Email: email, EventType: step, Outcome: outcome, UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)", CreatedAt: at.Add(time.Duration(min) * time.Minute)}
	}
	oldestFirst := []store.AuthEvent{
		ev(0, "amy@x.org", store.AuthEventVerify, store.AuthOutcomeWrongCode),
		ev(1, "amy@x.org", store.AuthEventVerify, store.AuthOutcomeOK),
		ev(1, "amy@x.org", store.AuthEventLogin, store.AuthOutcomeOK),
		ev(2, "boss@x.org", store.AuthEventPasskey, store.AuthOutcomeOK),
		ev(3, "boss@x.org", store.AuthEventTOTP, store.AuthOutcomeOK),
		ev(3, "boss@x.org", store.AuthEventLogin, store.AuthOutcomeOK),
		ev(4, "cal@x.org", store.AuthEventTOTP, store.AuthOutcomeLockedOut),
	}
	newestFirst := make([]store.AuthEvent, len(oldestFirst))
	for i, e := range oldestFirst {
		newestFirst[len(oldestFirst)-1-i] = e
	}
	got := srv.foldSignIns(newestFirst)
	want := []struct{ email, result, how string }{
		{"cal@x.org", "Too many wrong authenticator codes", "Authenticator"},
		{"boss@x.org", "Signed in", "Passkey and authenticator"},
		{"amy@x.org", "Signed in", "Email code"},
		{"amy@x.org", "Wrong email code", "Email code"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d rows, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].Email != w.email || got[i].Result != w.result || got[i].How != w.how || got[i].Device != "iPhone" {
			t.Errorf("row %d = %+v, want %+v", i, got[i], w)
		}
	}
}

// A day of visits to one site is one row on the page, and the filters narrow
// both the sites and the sign-ins.
func TestAccessLogShowsOneRowPerPersonAndSite(t *testing.T) {
	srv, sender := testServer(t)
	ctx := context.Background()
	now := time.Now()
	for h := 0; h < 8; h++ {
		at := now.Add(-time.Duration(h) * time.Hour)
		if err := srv.store.RecordAppAccess(ctx, store.AppAccess{Email: "amy@example.com", Host: "planka.example.com", Bucket: at.Unix() / 3600, CreatedAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	at := now.Add(-time.Hour)
	if err := srv.store.RecordAppAccess(ctx, store.AppAccess{Email: "bob@example.com", Host: "docs.example.com", Bucket: at.Unix() / 3600, CreatedAt: at}); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)

	// Without a person chosen, each person is one row listing their sites.
	page := c.get("/admin/access", nil).Body.String()
	if n := strings.Count(page, `>amy@example.com</a>`); n != 1 {
		t.Errorf("amy shown in %d rows, want 1", n)
	}
	if !strings.Contains(page, `<td class="num" data-label="Hours">8</td>`) {
		t.Error("amy's eight hours not counted")
	}
	// With a person chosen, each of their sites is one row.
	page = c.get("/admin/access?email=amy%40example.com", nil).Body.String()
	if n := strings.Count(page, `<td data-label="Site"><code class="mono">planka.example.com</code></td>`); n != 1 {
		t.Errorf("amy's day on planka shown as %d rows, want 1", n)
	}
	page = c.get("/admin/access?email=bob", nil).Body.String()
	if strings.Contains(page, "amy@example.com") || !strings.Contains(page, "bob@example.com") {
		t.Error("the person filter did not narrow the page to bob")
	}
	page = c.get("/admin/access?site=planka.example.com", nil).Body.String()
	if strings.Contains(page, "bob@example.com") {
		t.Error("the site filter kept a visit to another site")
	}
	// The admin's own sign-in is one row, and "Refused only" hides it.
	page = c.get("/admin/access?email=admin%40example.com", nil).Body.String()
	if n := strings.Count(page, `<span class="pill ok">Signed in</span>`); n != 1 {
		t.Errorf("the admin's sign-in shown as %d rows, want 1", n)
	}
	page = c.get("/admin/access?email=admin%40example.com&show=problems", nil).Body.String()
	if strings.Contains(page, `<span class="pill ok">Signed in</span>`) || !strings.Contains(page, "No sign-in has been refused") {
		t.Error("Refused only still shows a successful sign-in")
	}
}
