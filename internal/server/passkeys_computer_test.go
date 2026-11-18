package server

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	pqtotp "github.com/pquerna/otp/totp"

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/passkey/passkeytest"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

var computer = map[string]string{"User-Agent": desktopUA}

// computerSignIn runs the email-code sign-in from a computer.
func computerSignIn(t *testing.T, c *client, sender *captureSender, email string) *httptest.ResponseRecorder {
	t.Helper()
	sender.reset()
	c.postWith("/request", url.Values{"email": {email}}, computer)
	code := sender.code()
	if code == "" {
		t.Fatalf("no code captured for %s", email)
	}
	return c.postWith("/verify-code", url.Values{"code": {code}}, computer)
}

// registerFrom answers the registration options on page with authenticator
// a, posting what the browser reports about where the passkey was made.
func registerFrom(t *testing.T, c *client, a *passkeytest.Authenticator, page string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	reg := a.Register(pkRPID, pkOrigin, attr(t, page, "challenge"), attr(t, page, "userid"))
	return c.postWith("/passkeys/register", url.Values{
		"id":                {enc(reg.CredentialID)},
		"clientDataJSON":    {enc(reg.ClientDataJSON)},
		"authenticatorData": {enc(reg.AuthenticatorData)},
		"publicKey":         {enc(reg.PublicKey)},
		"publicKeyAlg":      {strconv.Itoa(reg.PublicKeyAlg)},
		"attachment":        {reg.Attachment},
		"transports":        {strings.Join(reg.Transports, ",")},
	}, hdr)
}

// signInFromComputer opens the sign-in page on a computer and answers its
// challenge with a.
func signInFromComputer(t *testing.T, c *client, a *passkeytest.Authenticator) (string, *httptest.ResponseRecorder) {
	t.Helper()
	page := c.get("/login", computer).Body.String()
	as := a.SignIn(pkRPID, pkOrigin, attr(t, page, "challenge"))
	return page, c.postWith("/passkey/login", url.Values{
		"id": {enc(as.CredentialID)}, "clientDataJSON": {enc(as.ClientDataJSON)}, "authenticatorData": {enc(as.AuthenticatorData)},
		"signature": {enc(as.Signature)}, "userHandle": {enc(as.UserHandle)},
	}, computer)
}

// A computer is never offered a passkey unasked: not after an email code, and
// on the passkeys page only once the person chooses to add one, behind the
// warning. A phone's passkeys page is as it was.
func TestComputerPasskeyIsOfferedOnlyOnRequest(t *testing.T) {
	srv, sender := pkServer(t, nil)
	c := newClient(t, srv.Handler())
	if rec := computerSignIn(t, c, sender, "user@example.com"); rec.Code != http.StatusFound {
		t.Fatalf("a computer was offered a passkey after an email code: %d", rec.Code)
	}
	page := c.get("/passkeys", computer).Body.String()
	for _, want := range []string{html.EscapeString(msgPkComputerIntro), `href="/passkeys?add=computer"`, msgPkComputerAdd, msgPkComputerUnavailable, msgPkComputerLost} {
		if !strings.Contains(page, want) {
			t.Errorf("the computer's passkeys page lacks %q", want)
		}
	}
	if strings.Contains(page, "data-challenge") || strings.Contains(page, msgPkComputerWarning) {
		t.Fatal("the computer's passkeys page started a ceremony before the person chose to add a passkey")
	}
	chosen := c.get("/passkeys?add=computer", computer).Body.String()
	for _, want := range []string{msgPkComputerWarning, "data-challenge", `data-device="computer"`, `id="passkey-add"`, "Not now"} {
		if !strings.Contains(chosen, want) {
			t.Errorf("the computer's add page lacks %q", want)
		}
	}
	if strings.Contains(chosen, html.EscapeString(msgPkComputerIntro)) {
		t.Error("the add page repeats the intro")
	}

	// A phone sees the phone's page, whatever the address asks for.
	p := newClient(t, srv.Handler())
	phoneSignIn(t, p, sender, "user@example.com")
	for _, path := range []string{"/passkeys", "/passkeys?add=computer"} {
		page := p.get(path, phone).Body.String()
		if !strings.Contains(page, "Add a passkey on this phone") || strings.Contains(page, msgPkComputerAdd) ||
			strings.Contains(page, `data-device="computer"`) || strings.Contains(page, msgPkComputerWarning) {
			t.Fatalf("%s on a phone shows the computer's offer", path)
		}
	}
}

// A computer adds a passkey held by the computer, signs in with it, and the
// passkeys page names it as this computer's. Only a computer that holds one
// is asked for a passkey at sign-in.
func TestComputerPasskeyRegisterAndSignIn(t *testing.T) {
	srv, sender := pkServer(t, nil)
	c := newClient(t, srv.Handler())
	computerSignIn(t, c, sender, "user@example.com")
	a := passkeytest.NewComputer()
	rec := registerFrom(t, c, a, c.get("/passkeys?add=computer", computer).Body.String(), computer)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), msgPkComputerAdded) || !strings.Contains(rec.Body.String(), msgPkComputerNextTime) {
		t.Fatalf("register on a computer: %d %s", rec.Code, rec.Body.String())
	}
	list, _ := srv.store.ListPasskeys(context.Background(), "user@example.com")
	if len(list) != 1 || list[0].Device != store.DeviceComputer || list[0].Attachment != "platform" || list[0].Transports != "internal" ||
		list[0].Label != "Windows Hello" || list[0].AdminGrade {
		t.Fatalf("stored computer passkey: %+v", list[0])
	}
	if c.cookies[passkeyHereCookie] == nil || c.cookies[passkeyHereCookie].Value != enc(a.ID) {
		t.Fatal("the computer was not marked as holding the passkey")
	}

	// The computer that holds it is asked for it, by its ID; any other
	// computer's sign-in page asks for no passkey.
	if page := c.get("/login", computer).Body.String(); !strings.Contains(page, `data-allow="`+enc(a.ID)+`"`) {
		t.Fatal("the sign-in page on the computer that holds the passkey does not ask for it")
	}
	if page := newClient(t, srv.Handler()).get("/login", computer).Body.String(); strings.Contains(page, "data-allow") {
		t.Fatal("a computer that holds no passkey is asked for one")
	}

	// Signing in on the computer, as the same browser after signing out.
	b := newClient(t, srv.Handler())
	b.cookies[passkeyHereCookie] = c.cookies[passkeyHereCookie]
	if _, rec := signInFromComputer(t, b, a); rec.Code != http.StatusFound {
		t.Fatalf("passkey sign-in on a computer: %d %s", rec.Code, rec.Body.String())
	}
	id := readSession(t, srv, b)
	if id.Email != "user@example.com" || id.PK != list[0].ID {
		t.Fatalf("session after a computer's passkey sign-in: %+v", id)
	}
	if verifyAny(b).Code != http.StatusOK {
		t.Fatal("the computer's passkey session refused at /verify")
	}
	// The passkeys page names the row, with the kind of device.
	page := b.get("/passkeys", computer).Body.String()
	if !strings.Contains(page, msgPkThisComputer) || strings.Contains(page, msgPkAComputer) {
		t.Fatalf("the passkeys page does not name this computer's passkey:\n%s", page)
	}
	// Another computer sees the same passkey as a computer's, not its own.
	o := newClient(t, srv.Handler())
	computerSignIn(t, o, sender, "user@example.com")
	if page := o.get("/passkeys", computer).Body.String(); !strings.Contains(page, msgPkAComputer) || strings.Contains(page, msgPkThisComputer) {
		t.Fatal("another computer names the passkey as its own")
	}
	// The notice names the computer.
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		sender.mu.Lock()
		n := len(sender.notices)
		var text string
		if n > 0 {
			text = sender.notices[0].Text
		}
		sender.mu.Unlock()
		if n > 0 {
			if !strings.Contains(text, ", on "+msgPkNoticeWindows+".") {
				t.Errorf("the notice does not name the computer:\n%s", text)
			}
			break
		}
	}
}

// A computer's registration that the browser says is held elsewhere, such
// as a phone reached over Bluetooth or a QR code, is refused and stores
// nothing. A phone's registration is taken as it comes, as it always was.
func TestComputerRefusesAPasskeyHeldElsewhere(t *testing.T) {
	for name, mut := range map[string]func(a *passkeytest.Authenticator){
		"a phone over a QR code": func(a *passkeytest.Authenticator) { a.Attachment, a.Transports = "cross-platform", []string{"hybrid"} },
		"hybrid and internal, cross": func(a *passkeytest.Authenticator) {
			a.Attachment, a.Transports = "cross-platform", []string{"hybrid", "internal"}
		},
		"hybrid only, platform":     func(a *passkeytest.Authenticator) { a.Transports = []string{"hybrid"} },
		"a security key":            func(a *passkeytest.Authenticator) { a.Attachment, a.Transports = "cross-platform", []string{"usb"} },
		"no transports reported":    func(a *passkeytest.Authenticator) { a.Transports = nil },
		"an unknown transport only": func(a *passkeytest.Authenticator) { a.Transports = []string{"carrier-pigeon"} },
	} {
		t.Run(name, func(t *testing.T) {
			srv, sender := pkServer(t, nil)
			c := newClient(t, srv.Handler())
			computerSignIn(t, c, sender, "user@example.com")
			a := passkeytest.NewComputer()
			mut(a)
			rec := registerFrom(t, c, a, c.get("/passkeys?add=computer", computer).Body.String(), computer)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Your passkey has not been added") ||
				!strings.Contains(rec.Body.String(), msgPkComputerRefused) {
				t.Fatalf("a passkey held elsewhere: %d %s", rec.Code, rec.Body.String())
			}
			if list, _ := srv.store.ListPasskeys(context.Background(), "user@example.com"); len(list) != 0 {
				t.Fatalf("a passkey held elsewhere was stored: %+v", list)
			}
			if c.cookies[passkeyHereCookie] != nil {
				t.Fatal("the computer was marked as holding a refused passkey")
			}
		})
	}
	t.Run("a phone is unchanged", func(t *testing.T) {
		srv, sender := pkServer(t, nil)
		c := newClient(t, srv.Handler())
		a := passkeytest.New()
		a.Attachment, a.Transports = "cross-platform", []string{"hybrid"}
		if rec := registerFrom(t, c, a, phoneSignIn(t, c, sender, "user@example.com").Body.String(), phone); rec.Code != http.StatusOK {
			t.Fatalf("a phone's registration was refused: %d", rec.Code)
		}
		if list, _ := srv.store.ListPasskeys(context.Background(), "user@example.com"); len(list) != 1 || list[0].Device != store.DevicePhone {
			t.Fatalf("the phone's passkey: %+v", list)
		}
	})
	// The challenge decides, not the browser that posts it: a computer's
	// challenge posted with a phone's user agent is still a computer's.
	t.Run("a computer's challenge posted as a phone", func(t *testing.T) {
		srv, sender := pkServer(t, nil)
		c := newClient(t, srv.Handler())
		computerSignIn(t, c, sender, "user@example.com")
		a := passkeytest.NewComputer()
		a.Attachment, a.Transports = "cross-platform", []string{"hybrid"}
		if rec := registerFrom(t, c, a, c.get("/passkeys?add=computer", computer).Body.String(), phone); rec.Code != http.StatusBadRequest {
			t.Fatalf("a computer's challenge posted as a phone: %d", rec.Code)
		}
	})
}

// On a computer, every rule for adding a passkey holds: a recent sign-in,
// and for an administrator the second factor, which makes the passkey admin
// grade. The admin door asks a computer only for the admin passkeys it holds.
func TestComputerPasskeyRulesHold(t *testing.T) {
	t.Run("a sign-in that is not recent", func(t *testing.T) {
		srv, sender := pkServer(t, nil)
		start := time.Now()
		srv.now = func() time.Time { return start }
		c := newClient(t, srv.Handler())
		computerSignIn(t, c, sender, "user@example.com")
		srv.now = func() time.Time { return start.Add(passkeyFreshness + time.Minute) }
		page := c.get("/passkeys?add=computer", computer).Body.String()
		if strings.Contains(page, "data-challenge") || !strings.Contains(page, "You will be asked to confirm your email") ||
			!strings.Contains(page, url.QueryEscape(srv.passkeysURL()+"?add=computer")) {
			t.Fatalf("a stale session on a computer was not sent back through an email code:\n%s", page)
		}
	})
	t.Run("an administrator", func(t *testing.T) {
		srv, sender := pkServer(t, func(c *config.Config) { c.TOTPEnabled = true })
		secret := provisionTOTP(t, srv, "admin@example.com")
		c := newClient(t, srv.Handler())
		computerSignIn(t, c, sender, "admin@example.com")
		page := c.get("/passkeys?add=computer", computer).Body.String()
		if strings.Contains(page, "data-challenge") || !strings.Contains(page, `href="/passkeys/confirm"`) {
			t.Fatal("an administrator without the second step was offered a ceremony on a computer")
		}
		confirm := c.get("/passkeys/confirm", computer).Body.String()
		code, _ := pqtotp.GenerateCode(secret, time.Now())
		ready := c.postWith("/passkeys/confirm", url.Values{"csrf": {extractCSRF(t, confirm)}, "code": {code}}, computer)
		if ready.Code != http.StatusOK || !strings.Contains(ready.Body.String(), `data-device="computer"`) || !strings.Contains(ready.Body.String(), msgPkComputerWarning) {
			t.Fatalf("the code did not lead to the computer's ceremony: %d", ready.Code)
		}
		a := passkeytest.NewComputer()
		if rec := registerFrom(t, c, a, ready.Body.String(), computer); rec.Code != http.StatusOK {
			t.Fatalf("admin register on a computer: %d %s", rec.Code, rec.Body.String())
		}
		list, _ := srv.store.ListPasskeys(context.Background(), "admin@example.com")
		if len(list) != 1 || !list[0].AdminGrade || list[0].Device != store.DeviceComputer {
			t.Fatalf("admin computer passkey: %+v", list)
		}
		// Its sign-in opens the admin pages without the code.
		b := newClient(t, srv.Handler())
		b.cookies[passkeyHereCookie] = c.cookies[passkeyHereCookie]
		if _, rec := signInFromComputer(t, b, a); rec.Code != http.StatusFound {
			t.Fatalf("admin passkey sign-in on a computer: %d", rec.Code)
		}
		if id := readSession(t, srv, b); !id.TOTP || id.PK != list[0].ID {
			t.Fatalf("admin computer passkey session lacks the second factor: %+v", id)
		}
		// The door asks the computer that holds it for that passkey alone, and
		// asks any other computer for none.
		e := newClient(t, srv.Handler())
		computerSignIn(t, e, sender, "admin@example.com")
		if door := e.get("/totp", computer).Body.String(); strings.Contains(door, "Use your passkey") {
			t.Fatal("the door asked a computer that holds no passkey for one")
		}
		e.cookies[passkeyHereCookie] = c.cookies[passkeyHereCookie]
		if door := e.get("/totp", computer).Body.String(); !strings.Contains(door, "Use your passkey") || !strings.Contains(door, `data-allow="`+enc(a.ID)+`"`) {
			t.Fatalf("the door did not ask the computer for its admin passkey:\n%s", door)
		}
	})
	t.Run("a passkey from before the second factor is not admin grade", func(t *testing.T) {
		srv, sender := pkServer(t, nil)
		c := newClient(t, srv.Handler())
		computerSignIn(t, c, sender, "user@example.com")
		a := passkeytest.NewComputer()
		registerFrom(t, c, a, c.get("/passkeys?add=computer", computer).Body.String(), computer)
		srv.cfg.TOTPEnabled = true
		srv.cfg.AdminEmails = []string{"admin@example.com", "user@example.com"}
		srv.policy = newPolicyFor(srv.cfg)
		provisionTOTP(t, srv, "user@example.com")
		b := newClient(t, srv.Handler())
		b.cookies[passkeyHereCookie] = c.cookies[passkeyHereCookie]
		signInFromComputer(t, b, a)
		if rec := b.get("/admin/", nil); !strings.Contains(rec.Header().Get("Location"), "/totp?rd=") {
			t.Fatalf("a computer passkey from before promotion opened the admin pages: %d", rec.Code)
		}
		if door := b.get("/totp", computer).Body.String(); strings.Contains(door, "Use your passkey") {
			t.Fatal("the door asked for a passkey that cannot open the admin pages")
		}
	})
}

// Removing a computer's passkey ends its sessions and drops it from the
// computer's list, and the administrator's view names the kind of device.
// A passkey the gateway no longer holds is dropped from the list at sign-in.
func TestComputerPasskeyRemoval(t *testing.T) {
	srv, sender := pkServer(t, nil)
	c := newClient(t, srv.Handler())
	computerSignIn(t, c, sender, "user@example.com")
	a := passkeytest.NewComputer()
	registerFrom(t, c, a, c.get("/passkeys?add=computer", computer).Body.String(), computer)
	p := passkeytest.New()
	pc := newClient(t, srv.Handler())
	register(t, pc, p, phoneSignIn(t, pc, sender, "user@example.com").Body.String(), nil)

	admin := newClient(t, srv.Handler())
	loginAs(t, admin, sender, "admin@example.com", nil)
	view := admin.get("/admin/access?email=user@example.com", nil).Body.String()
	for _, want := range []string{"<th>" + msgPkDeviceHeading + "</th>", ">" + msgPkDeviceComputer + "</td>", ">" + msgPkDevicePhone + "</td>"} {
		if !strings.Contains(view, want) {
			t.Errorf("the administrator's view lacks %q", want)
		}
	}

	b := newClient(t, srv.Handler())
	b.cookies[passkeyHereCookie] = c.cookies[passkeyHereCookie]
	if _, rec := signInFromComputer(t, b, a); rec.Code != http.StatusFound {
		t.Fatal("passkey sign-in failed")
	}
	list, _ := srv.store.ListPasskeys(context.Background(), "user@example.com")
	var pcID int64
	for _, k := range list {
		if k.Device == store.DeviceComputer {
			pcID = k.ID
		}
	}
	page := b.get("/passkeys", computer).Body.String()
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(page)[1]
	if rec := b.postWith("/passkeys/"+strconv.FormatInt(pcID, 10)+"/remove", url.Values{"csrf": {csrf}}, computer); rec.Code != http.StatusFound {
		t.Fatalf("remove: %d", rec.Code)
	}
	if b.cookies[passkeyHereCookie] != nil {
		t.Error("the removed passkey is still listed as held by the computer")
	}
	if verifyAny(b).Code != http.StatusFound {
		t.Fatal("the removed passkey's session still works")
	}
	// The other browser on the computer still lists it; its sign-in is
	// refused, and the list forgets it.
	_, rec := signInFromComputer(t, c, a)
	if rec.Code != http.StatusUnauthorized || c.cookies[passkeyHereCookie] != nil {
		t.Fatalf("a removed passkey on a computer: %d, cookie %v", rec.Code, c.cookies[passkeyHereCookie])
	}
	if strings.Contains(rec.Body.String(), "data-allow") {
		t.Fatal("the sign-in page still asks for the removed passkey")
	}
}

// The list of passkeys a device holds keeps the newest, and only well-formed
// IDs, within its bounds.
func TestPasskeysHereBounds(t *testing.T) {
	srv, _ := pkServer(t, nil)
	var ck *http.Cookie
	for i := 0; i < passkeyHereMax+3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if ck != nil {
			req.AddCookie(ck)
		}
		rec := httptest.NewRecorder()
		srv.rememberPasskeyHere(rec, req, []byte{byte(i), 1, 2, 3})
		ck = rec.Result().Cookies()[0]
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(ck)
	got := srv.passkeysHere(req)
	if len(got) != passkeyHereMax || got[0] != enc([]byte{byte(passkeyHereMax + 2), 1, 2, 3}) {
		t.Fatalf("passkeys here: %v", got)
	}
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: passkeyHereCookie, Value: "!!.AQID"})
	if got := srv.passkeysHere(req); len(got) != 1 || got[0] != "AQID" {
		t.Fatalf("a malformed entry was kept: %v", got)
	}
}
