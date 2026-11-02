package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	pqtotp "github.com/pquerna/otp/totp"

	"github.com/uppertoe/vps-scaffold-auth/internal/passkey/passkeytest"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
)

// Found in review: an administrator's passkey added while TOTP_ENABLED=false
// was stored admin grade, and skipped the second factor once TOTP was on.
func TestPasskeyAddedWhileTOTPOffIsNotAdminGrade(t *testing.T) {
	srv, sender := pkServer(t, nil) // TOTP off (the default)
	c := newClient(t, srv.Handler())
	a := passkeytest.New()
	if rec := register(t, c, a, phoneSignIn(t, c, sender, "admin@example.com").Body.String(), nil); rec.Code != http.StatusOK {
		t.Fatalf("register: %d", rec.Code)
	}
	list, _ := srv.store.ListPasskeys(context.Background(), "admin@example.com")
	if list[0].AdminGrade {
		t.Error("a passkey added with TOTP off is admin grade")
	}

	srv.cfg.TOTPEnabled = true
	provisionTOTP(t, srv, "admin@example.com")
	c2 := newClient(t, srv.Handler())
	rec := signInWith(t, c2, a)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "authenticator") {
		t.Fatalf("a passkey added before TOTP was enabled skipped the authenticator step: %d", rec.Code)
	}
}

// Found in review: the admin pages never renew, so a session started with a
// removed passkey kept them until the cookie expired. They now check the
// passkey on every request, as does /passkeys.
func TestRemovedPasskeyLosesAdminPagesAtOnce(t *testing.T) {
	srv, sender := pkServer(t, nil)
	start := time.Now()
	srv.now = func() time.Time { return start }
	c := newClient(t, srv.Handler())
	a := passkeytest.New()
	register(t, c, a, phoneSignIn(t, c, sender, "admin@example.com").Body.String(), nil)

	thief := newClient(t, srv.Handler())
	if signInWith(t, thief, a).Code != http.StatusFound {
		t.Fatal("passkey sign-in failed")
	}
	if n, _ := srv.store.DeletePasskeys(context.Background(), "admin@example.com"); n != 1 {
		t.Fatal("not removed")
	}
	srv.now = func() time.Time { return start.Add(59 * time.Minute) } // > SessionRenew (30m), < SessionTTL (1h)
	if rec := thief.get("/admin/", nil); rec.Code == http.StatusOK {
		t.Errorf("removed passkey's session still opens /admin/ 29 minutes after renewal was due")
	}
	if rec := thief.get("/passkeys", phone); rec.Code == http.StatusOK {
		t.Errorf("removed passkey's session still opens /passkeys")
	}
}

// Found in review: a session started with a passkey counted as a recent
// sign-in, so a thief holding one passkey could add their own, which would
// survive the stolen one's removal. Only an emailed code is recent enough.
func TestAPasskeySessionCannotAddAnotherPasskey(t *testing.T) {
	srv, sender := pkServer(t, nil)
	start := time.Now()
	srv.now = func() time.Time { return start }
	owner := newClient(t, srv.Handler())
	a := passkeytest.New()
	register(t, owner, a, phoneSignIn(t, owner, sender, "user@example.com").Body.String(), nil)

	thief := newClient(t, srv.Handler())
	if signInWith(t, thief, a).Code != http.StatusFound {
		t.Fatal("passkey sign-in failed")
	}
	srv.now = func() time.Time { return start.Add(5 * time.Minute) }
	// While the stolen passkey still exists: no ceremony is offered, and a
	// registration posted with any challenge is refused.
	page := thief.get("/passkeys", phone).Body.String()
	if strings.Contains(page, "data-challenge") {
		t.Fatal("a passkey session was offered a ceremony to add another passkey")
	}
	offer := owner.get("/passkeys", phone).Body.String() // a challenge for this account
	thief.cookies[session.PasskeyRegCookie] = owner.cookies[session.PasskeyRegCookie]
	register(t, thief, passkeytest.New(), offer, nil)
	// After the removal, the session cannot even open the page.
	srv.store.DeletePasskeys(context.Background(), "user@example.com")
	if rec := thief.get("/passkeys", phone); rec.Code == http.StatusOK {
		t.Fatal("a removed passkey's session opened /passkeys")
	}
	if list, _ := srv.store.ListPasskeys(context.Background(), "user@example.com"); len(list) != 0 {
		t.Fatalf("a passkey session added a passkey: %+v", list)
	}
}

// Found in review: registration once checked an administrator's code before
// the ceremony, so posts with no ceremony spent the account's attempts. The
// code is now checked only on the confirmation page.
func TestRegistrationPostsDoNotSpendAdminCodeAttempts(t *testing.T) {
	srv, sender := pkServer(t, nil)
	srv.cfg.TOTPEnabled = true
	secret := provisionTOTP(t, srv, "admin@example.com")
	_ = secret
	start := time.Now()
	srv.now = func() time.Time { return start }
	c := newClient(t, srv.Handler())
	phoneSignIn(t, c, sender, "admin@example.com")
	// complete TOTP
	code := totpNow(t, secret, start)
	c.postWith("/totp", url.Values{"code": {code}}, phone)
	srv.now = func() time.Time { return start.Add(passkeyFreshness + time.Minute) }
	for i := 0; i < 6; i++ {
		c.get("/passkeys/confirm", phone) // mints a challenge cookie
		c.postWith("/passkeys/register", url.Values{"code": {"000000"}}, phone)
	}
	n, err := srv.store.ReserveTOTPAttempt(context.Background(), "admin@example.com", totpLockoutWindow, srv.now())
	if err != nil {
		t.Fatal(err)
	}
	if n > 6 {
		t.Errorf("%d TOTP attempts reserved by posts carrying no passkey ceremony; the account is now locked (max %d)", n-1, srv.cfg.OTPMaxAttempts)
	}
}

func totpNow(t *testing.T, secret string, at time.Time) string {
	c, err := pqtotp.GenerateCode(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
