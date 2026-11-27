package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// hookStore runs hook once, inside handleTOTP after the code has been
// accepted and before the new session is started.
type hookStore struct {
	store.Store
	hook func()
}

func (h *hookStore) ClearTOTPFailures(ctx context.Context, email string) error {
	if f := h.hook; f != nil {
		h.hook = nil
		f()
	}
	return h.Store.ClearTOTPFailures(ctx, email)
}

// A "sign out on every device" (or an administrator signing the person out)
// that lands while the admin door's code is being checked ends the session:
// the admin step starts no new session in its place.
func TestStepUpRacingSignOutEverywhere(t *testing.T) {
	srv, sender := testServer(t)
	srv.cfg.TOTPEnabled = true
	secret := provisionTOTP(t, srv, "admin@example.com")
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	hs := &hookStore{Store: srv.store}
	srv.store = hs
	ended := false
	hs.hook = func() {
		if err := srv.endSessions(context.Background(), "admin@example.com", srv.now()); err != nil {
			t.Fatal(err)
		}
		ended = true
	}
	stepUp(t, c, totpNow(t, secret, time.Now()), "https://db.example.com/x")
	if !ended {
		t.Fatal("the revocation did not run during the admin step")
	}
	if verifyAny(t, srv, c).Code == http.StatusOK {
		t.Error("a session survives a sign out everywhere that landed during the admin step")
	}
	if n := liveCount(srv, "admin@example.com"); n != 0 {
		t.Errorf("%d sessions live after the sign out", n)
	}
}

// The same, with an administrator ending that one session from the Sessions
// page.
func TestStepUpRacingEndThisSession(t *testing.T) {
	srv, sender := testServer(t)
	srv.cfg.TOTPEnabled = true
	secret := provisionTOTP(t, srv, "admin@example.com")
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	sid := sessionOf(t, srv, c).SID
	hs := &hookStore{Store: srv.store}
	srv.store = hs
	hs.hook = func() {
		n, err := srv.endSessionsWhere(context.Background(), func(x *store.Session) bool { return x.ID == sid })
		if err != nil || n != 1 {
			t.Fatalf("end %d %v", n, err)
		}
	}
	stepUp(t, c, totpNow(t, secret, time.Now()), "https://db.example.com/x")
	if verifyAny(t, srv, c).Code == http.StatusOK {
		t.Error("an ended session's admin step starts a new admin-tier session")
	}
	if n := liveCount(srv, "admin@example.com"); n != 0 {
		t.Errorf("%d sessions live after the session was ended", n)
	}
}
