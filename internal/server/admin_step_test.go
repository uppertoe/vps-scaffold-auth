package server

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	pqtotp "github.com/pquerna/otp/totp"

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/passkey/passkeytest"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// doorCodes hands out authenticator codes the replay guard has not seen, from
// the steps the validator accepts (skew 1), so a test can pass the door more
// than once.
type doorCodes struct {
	secret string
	used   map[string]bool
}

func (d *doorCodes) next(t *testing.T) string {
	t.Helper()
	if d.used == nil {
		d.used = map[string]bool{}
	}
	for _, off := range []time.Duration{0, 30 * time.Second, -30 * time.Second} {
		code, _ := pqtotp.GenerateCode(d.secret, time.Now().Add(off))
		if !d.used[code] {
			d.used[code] = true
			return code
		}
	}
	t.Fatal("no unused authenticator code")
	return ""
}

// passDoor signs the administrator in by email on hdr's device, opens the
// admin door and enters a code.
func passDoor(t *testing.T, c *client, sender *captureSender, codes *doorCodes, hdr map[string]string) (door string, rec *httptest.ResponseRecorder) {
	t.Helper()
	sender.reset()
	c.postWith("/request", url.Values{"email": {"admin@example.com"}}, hdr)
	c.postWith("/verify-code", url.Values{"code": {sender.code()}}, hdr)
	door = c.get("/totp?rd="+url.QueryEscape("https://app.example.com/admin"), hdr).Body.String()
	return door, c.postWith("/totp", url.Values{"code": {codes.next(t)}, "csrf": {extractCSRF(t, door)}, "rd": {"https://app.example.com/admin"}}, hdr)
}

// The second-step page says why it is there and how long the step lasts, in
// words taken from adminStepMaxAge, with and without a passkey offered.
func TestStepUpPageSaysWhy(t *testing.T) {
	if got := renewWithin(adminStepMaxAge); got != "12 hours" {
		t.Fatalf("adminStepMaxAge in words = %q, want 12 hours", got)
	}
	without := "The admin pages need a second step, which lasts 12 hours. Enter the 6-digit code from your authenticator app."
	with := "The admin pages need a second step, which lasts 12 hours. Use your passkey, or enter the 6-digit code from your authenticator app."
	if stepUpSub(false) != without || stepUpSub(true) != with {
		t.Fatalf("step-up lines: %q / %q", stepUpSub(false), stepUpSub(true))
	}

	srv, sender := pkServer(t, func(c *config.Config) { c.TOTPEnabled = true })
	codes := &doorCodes{secret: provisionTOTP(t, srv, "admin@example.com")}
	c := newClient(t, srv.Handler())
	phoneSignIn(t, c, sender, "admin@example.com")
	door := html.UnescapeString(c.get("/totp", phone).Body.String())
	if !strings.Contains(door, `<p class="sub">`+without+`</p>`) || strings.Contains(door, with) {
		t.Fatalf("the door without a passkey lacks its line:\n%s", door)
	}
	// Add an admin passkey on the phone; the door then offers it.
	offer := c.postWith("/totp", url.Values{"code": {codes.next(t)}, "csrf": {extractCSRF(t, door)}}, phone)
	if rec := register(t, c, passkeytest.New(), offer.Body.String(), nil); rec.Code != http.StatusOK {
		t.Fatalf("admin register: %d", rec.Code)
	}
	e := newClient(t, srv.Handler())
	phoneSignIn(t, e, sender, "admin@example.com")
	door = html.UnescapeString(e.get("/totp", phone).Body.String())
	if !strings.Contains(door, `<p class="sub">`+with+`</p>`) || !strings.Contains(door, `action="/passkey/login"`) {
		t.Fatalf("the door with a passkey lacks its line:\n%s", door)
	}
}

// After the code at the admin door, a computer off the listed networks is
// offered an admin passkey of its own, behind the warning, through the
// computer's ceremony. The passkey made there is admin grade and held by the
// computer, the door asks the computer for it next time, and its sign-in
// passes the second step. That computer is not offered another; "Not now"
// leads to the destination.
func TestComputerIsOfferedAnAdminPasskeyAtTheDoor(t *testing.T) {
	srv, sender := pkNetworkServer(t, func(c *config.Config) { c.TOTPEnabled = true })
	codes := &doorCodes{secret: provisionTOTP(t, srv, "admin@example.com")}
	c := newClient(t, srv.Handler())
	_, offer := passDoor(t, c, sender, codes, computer)
	body := html.UnescapeString(offer.Body.String())
	if offer.Code != http.StatusOK {
		t.Fatalf("the code at the door on a computer = %d, want the offer", offer.Code)
	}
	for _, want := range []string{
		"<title>" + msgPkComputerOfferHeading + "</title>", "<h1>" + msgPkComputerOfferHeading + "</h1>",
		msgPkComputerAdminOffer, msgPkComputerWarning, msgPkComputerAdd, msgPkComputerExists,
		"Your code has been accepted, and the admin pages are open.",
		`data-device="computer"`, `id="passkey-skip" class="pk-link">Not now</a>`,
		`href="https://app.example.com/admin" id="passkey-skip"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the computer's admin offer lacks %q", want)
		}
	}
	if strings.Contains(body, "this phone") {
		t.Error("the computer's admin offer speaks of a phone")
	}
	// The session already holds the admin tier, so "Not now" opens the pages.
	if id := readSession(t, srv, c); !id.TOTP {
		t.Fatal("the code at the door did not give the admin tier")
	}

	// A passkey the browser saved on a phone instead is refused, as on the
	// passkeys page.
	elsewhere := passkeytest.NewComputer()
	elsewhere.Attachment, elsewhere.Transports = "cross-platform", []string{"hybrid"}
	if rec := registerFrom(t, c, elsewhere, offer.Body.String(), computer); rec.Code != http.StatusBadRequest {
		t.Fatalf("a passkey held elsewhere was taken at the door: %d", rec.Code)
	}
	if list, _ := srv.store.ListPasskeys(context.Background(), "admin@example.com"); len(list) != 0 {
		t.Fatalf("a refused passkey was stored: %+v", list)
	}

	// The computer's own passkey is taken, admin grade.
	c = newClient(t, srv.Handler())
	_, offer = passDoor(t, c, sender, codes, computer)
	a := passkeytest.NewComputer()
	if rec := registerFrom(t, c, a, offer.Body.String(), computer); rec.Code != http.StatusOK {
		t.Fatalf("admin register at the door on a computer: %d %s", rec.Code, rec.Body.String())
	}
	list, _ := srv.store.ListPasskeys(context.Background(), "admin@example.com")
	if len(list) != 1 || !list[0].AdminGrade || list[0].Device != store.DeviceComputer {
		t.Fatalf("the door's computer passkey: %+v", list)
	}

	// Next time, the door asks this computer for it, and its sign-in passes
	// the second step.
	b := newClient(t, srv.Handler())
	b.cookies[passkeyHereCookie] = c.cookies[passkeyHereCookie]
	computerSignIn(t, b, sender, "admin@example.com")
	door := html.UnescapeString(b.get("/totp", computer).Body.String())
	if !strings.Contains(door, `data-allow="`+enc(a.ID)+`"`) || !strings.Contains(door, stepUpSub(true)) {
		t.Fatalf("the door did not ask the computer for its admin passkey:\n%s", door)
	}
	p := newClient(t, srv.Handler())
	p.cookies[passkeyHereCookie] = c.cookies[passkeyHereCookie]
	if _, rec := signInFromComputer(t, p, a); rec.Code != http.StatusFound {
		t.Fatalf("admin passkey sign-in on the computer: %d", rec.Code)
	}
	if id := readSession(t, srv, p); !id.TOTP || id.PK != list[0].ID {
		t.Fatalf("the door's computer passkey does not pass the second step: %+v", id)
	}
	if rec := p.get("/admin/", nil); rec.Code != http.StatusOK {
		t.Fatalf("the door's computer passkey: /admin/ = %d, want 200", rec.Code)
	}

	// The same computer, back at the door with the code, is not offered
	// another.
	_, rec := passDoor(t, b, sender, codes, computer)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://app.example.com/admin" {
		t.Fatalf("a computer holding an admin passkey was offered another: %d", rec.Code)
	}
}

// A computer on a listed network is not offered an admin passkey at the
// door: the code goes straight on, with no challenge minted.
func TestComputerOnTheNetworkIsNotOfferedAnAdminPasskey(t *testing.T) {
	srv, sender := pkNetworkServer(t, func(c *config.Config) { c.TOTPEnabled = true })
	codes := &doorCodes{secret: provisionTOTP(t, srv, "admin@example.com")}
	c := newClient(t, srv.Handler())
	_, rec := passDoor(t, c, sender, codes, computerOnNet)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://app.example.com/admin" {
		t.Fatalf("the code on the network = %d %q, want straight on", rec.Code, rec.Header().Get("Location"))
	}
	for _, ck := range rec.Result().Cookies() {
		if strings.HasSuffix(ck.Name, session.PasskeyRegCookie) {
			t.Fatal("a registration challenge was minted for a computer on the network")
		}
	}
}

// A phone at the door is as it was: offered a passkey while the account holds
// no admin passkey, whatever a computer holds, and not once it holds one. An
// admin passkey on a phone does not stop a computer being offered its own.
func TestAdminDoorOfferOnAPhoneIsUnchanged(t *testing.T) {
	srv, sender := pkNetworkServer(t, func(c *config.Config) { c.TOTPEnabled = true })
	codes := &doorCodes{secret: provisionTOTP(t, srv, "admin@example.com")}
	c := newClient(t, srv.Handler())
	_, offer := passDoor(t, c, sender, codes, phoneOnNet)
	body := offer.Body.String()
	if offer.Code != http.StatusOK || !strings.Contains(body, "<h1>Sign in faster on this phone</h1>") ||
		strings.Contains(body, `data-device="computer"`) || strings.Contains(body, msgPkComputerWarning) {
		t.Fatalf("the phone's offer at the door changed: %d", offer.Code)
	}
	if rec := register(t, c, passkeytest.New(), body, nil); rec.Code != http.StatusOK {
		t.Fatalf("admin register on a phone: %d", rec.Code)
	}
	e := newClient(t, srv.Handler())
	if _, rec := passDoor(t, e, sender, codes, phone); rec.Code != http.StatusFound {
		t.Fatalf("a phone was offered a second admin passkey: %d", rec.Code)
	}
	k := newClient(t, srv.Handler())
	if _, rec := passDoor(t, k, sender, codes, computer); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `data-device="computer"`) {
		t.Fatalf("a computer was not offered its own admin passkey: %d", rec.Code)
	}
}
