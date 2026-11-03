package server

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	pqtotp "github.com/pquerna/otp/totp"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/email"
	"github.com/uppertoe/vps-scaffold-auth/internal/passkey/passkeytest"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
)

const (
	iphoneUA  = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
	desktopUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
	pkRPID    = "auth.example.com"
	pkOrigin  = "https://auth.example.com"
)

var phone = map[string]string{"User-Agent": iphoneUA}

func pkServer(t *testing.T, adjust func(*config.Config)) (*Server, *captureSender) {
	t.Helper()
	return testServerWith(t, func(c *config.Config) {
		c.PasskeysEnabled = true
		if adjust != nil {
			adjust(c)
		}
	})
}

// phoneSignIn runs the email-code sign-in from a phone and returns the
// response to the code, which is the passkey offer when one is due.
func phoneSignIn(t *testing.T, c *client, sender *captureSender, email string) *httptest.ResponseRecorder {
	t.Helper()
	sender.reset()
	c.postWith("/request", url.Values{"email": {email}}, phone)
	code := sender.code()
	if code == "" {
		t.Fatalf("no code captured for %s", email)
	}
	return c.postWith("/verify-code", url.Values{"code": {code}}, phone)
}

func attr(t *testing.T, body, name string) []byte {
	t.Helper()
	m := regexp.MustCompile(`data-` + name + `="([^"]*)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("page has no data-%s", name)
	}
	b, err := base64.RawURLEncoding.DecodeString(m[1])
	if err != nil {
		t.Fatalf("data-%s: %v", name, err)
	}
	return b
}

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// register answers the registration options on page with authenticator a.
func register(t *testing.T, c *client, a *passkeytest.Authenticator, page string, extra url.Values) *httptest.ResponseRecorder {
	t.Helper()
	reg := a.Register(pkRPID, pkOrigin, attr(t, page, "challenge"), attr(t, page, "userid"))
	form := url.Values{
		"id":                {enc(reg.CredentialID)},
		"clientDataJSON":    {enc(reg.ClientDataJSON)},
		"authenticatorData": {enc(reg.AuthenticatorData)},
		"publicKey":         {enc(reg.PublicKey)},
		"publicKeyAlg":      {strconv.Itoa(reg.PublicKeyAlg)},
	}
	for k, v := range extra {
		form[k] = v
	}
	return c.postWith("/passkeys/register", form, phone)
}

// signInWith opens the sign-in page and answers its challenge with a.
func signInWith(t *testing.T, c *client, a *passkeytest.Authenticator) *httptest.ResponseRecorder {
	t.Helper()
	page := c.get("/login", phone).Body.String()
	as := a.SignIn(pkRPID, pkOrigin, attr(t, page, "challenge"))
	return postAssertion(c, as.CredentialID, as.ClientDataJSON, as.AuthenticatorData, as.Signature, as.UserHandle)
}

func postAssertion(c *client, id, cd, ad, sig, handle []byte) *httptest.ResponseRecorder {
	return c.postWith("/passkey/login", url.Values{
		"id": {enc(id)}, "clientDataJSON": {enc(cd)}, "authenticatorData": {enc(ad)},
		"signature": {enc(sig)}, "userHandle": {enc(handle)},
	}, phone)
}

func verifyAny(c *client) *httptest.ResponseRecorder {
	return c.get("/verify", map[string]string{"X-Auth-Policy": "any"})
}

func readSession(t *testing.T, srv *Server, c *client) *session.Identity {
	t.Helper()
	ck := c.cookies[session.SessionCookie]
	if ck == nil {
		t.Fatal("no session cookie")
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(ck)
	id, ok := srv.sessions.ReadSession(req, srv.now())
	if !ok {
		t.Fatal("session cookie does not read")
	}
	return id
}

// The whole staff journey: an email code on a phone, the offer, a passkey,
// then a sign-in with the passkey alone that names it in the session.
func TestPasskeyOfferRegisterAndSignIn(t *testing.T) {
	srv, sender := pkServer(t, nil)
	c := newClient(t, srv.Handler())
	rec := phoneSignIn(t, c, sender, "user@example.com")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Sign in faster on this phone") {
		t.Fatalf("no passkey offer after an email code on a phone: %d", rec.Code)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
		t.Fatalf("offer page CSP does not allow passkey.js: %q", csp)
	}
	if verifyAny(c).Code != http.StatusOK {
		t.Fatal("the session is not issued alongside the offer")
	}
	a := passkeytest.New()
	if rec := register(t, c, a, rec.Body.String(), nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "A passkey has been added to this phone.") {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	list, _ := srv.store.ListPasskeys(context.Background(), "user@example.com")
	if len(list) != 1 || list[0].AdminGrade || list[0].Label != "Passkey on an iPhone" {
		t.Fatalf("stored passkeys: %+v", list)
	}

	// A fresh browser on the same phone signs in with the passkey alone.
	c2 := newClient(t, srv.Handler())
	rec = signInWith(t, c2, a)
	if rec.Code != http.StatusFound {
		t.Fatalf("passkey sign-in: %d %s", rec.Code, rec.Body.String())
	}
	id := readSession(t, srv, c2)
	if id.Email != "user@example.com" || id.PK != list[0].ID || id.TOTP {
		t.Fatalf("session after passkey sign-in: %+v", id)
	}
	if verifyAny(c2).Code != http.StatusOK {
		t.Fatal("passkey session refused at /verify")
	}
}

// The offer is for phones, staff and administrators, after an email code, and
// once per phone.
func TestPasskeyOfferOnlyWhereItHelps(t *testing.T) {
	srv, sender := pkServer(t, func(c *config.Config) { c.OpenRegistrationHosts = []string{"apply.example.com"} })
	c := newClient(t, srv.Handler())
	sender.reset()
	c.postWith("/request", url.Values{"email": {"user@example.com"}}, map[string]string{"User-Agent": desktopUA})
	if rec := c.postWith("/verify-code", url.Values{"code": {sender.code()}}, map[string]string{"User-Agent": desktopUA}); rec.Code != http.StatusFound {
		t.Fatalf("a computer was offered a passkey: %d", rec.Code)
	}
	c = newClient(t, srv.Handler())
	if rec := phoneSignIn(t, c, sender, "user@example.com"); rec.Code != http.StatusOK {
		t.Fatalf("first phone sign-in: %d", rec.Code)
	}
	// Declined once, it is offered again at the next emailed code, so a person
	// who chose "Not now" still has a way to add one later.
	if rec := phoneSignIn(t, c, sender, "user@example.com"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Sign in faster on this phone") {
		t.Fatalf("the offer was not repeated at the next emailed code: %d", rec.Code)
	}
	// A phone holding the old 90-day cookie is offered too, and the cookie is cleared.
	c.cookies[passkeyOfferedCookie] = &http.Cookie{Name: passkeyOfferedCookie, Value: "1"}
	if rec := phoneSignIn(t, c, sender, "user@example.com"); rec.Code != http.StatusOK {
		t.Fatalf("a phone with the old cookie was not offered: %d", rec.Code)
	}
	if c.cookies[passkeyOfferedCookie] != nil {
		t.Error("the old offer cookie was not cleared")
	}
	// A guest is never offered one.
	c = newClient(t, srv.Handler())
	sender.reset()
	c.postWith("/request", url.Values{"email": {"stranger@other.org"}, "rd": {"https://apply.example.com/"}}, phone)
	if rec := c.postWith("/verify-code", url.Values{"code": {sender.code()}, "rd": {"https://apply.example.com/"}}, phone); rec.Code != http.StatusFound {
		t.Fatalf("a guest was offered a passkey: %d", rec.Code)
	}
}

// Off by default: no script, no routes, and the CSP keeps forbidding scripts.
func TestPasskeysOffByDefault(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv.Handler())
	rec := c.get("/login", phone)
	if strings.Contains(rec.Body.String(), "passkey") || strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src") {
		t.Fatal("the sign-in page carries passkeys while they are off")
	}
	for _, p := range []string{"/passkey.js", "/passkeys", "/passkeys/confirm"} {
		if c.get(p, nil).Code != http.StatusNotFound {
			t.Errorf("GET %s answered while passkeys are off", p)
		}
	}
	srv, _ = pkServer(t, nil)
	rec = newClient(t, srv.Handler()).get("/login", phone)
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src 'self'") || !strings.Contains(rec.Body.String(), `src="/passkey.js"`) {
		t.Fatal("the sign-in page does not load passkey.js when passkeys are on")
	}
	// Pages without a ceremony keep the scriptless policy.
	if strings.Contains(newClient(t, srv.Handler()).get("/logout", nil).Header().Get("Content-Security-Policy"), "script-src") {
		t.Fatal("a page with no passkey ceremony allows scripts")
	}
}

// Removing a passkey ends the sessions it started at their next renewal,
// whether the owner or an administrator removes it. Sessions started with an
// email code are not affected.
func TestRemovingAPasskeyEndsItsSessions(t *testing.T) {
	for _, by := range []string{"owner", "administrator"} {
		t.Run(by, func(t *testing.T) {
			srv, sender := pkServer(t, nil)
			start := time.Now()
			srv.now = func() time.Time { return start }
			owner := newClient(t, srv.Handler())
			a := passkeytest.New()
			register(t, owner, a, phoneSignIn(t, owner, sender, "user@example.com").Body.String(), nil)

			viaPasskey := newClient(t, srv.Handler())
			if signInWith(t, viaPasskey, a).Code != http.StatusFound {
				t.Fatal("passkey sign-in failed")
			}
			list, _ := srv.store.ListPasskeys(context.Background(), "user@example.com")
			switch by {
			case "owner":
				page := owner.get("/passkeys", phone).Body.String()
				csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(page)
				if csrf == nil {
					t.Fatal("no CSRF token on the passkeys page")
				}
				if rec := owner.postWith("/passkeys/"+strconv.FormatInt(list[0].ID, 10)+"/remove", url.Values{"csrf": {csrf[1]}}, phone); rec.Code != http.StatusFound {
					t.Fatalf("remove: %d", rec.Code)
				}
			case "administrator":
				admin := newClient(t, srv.Handler())
				loginAs(t, admin, sender, "admin@example.com", nil)
				page := admin.get("/admin/access?email=user@example.com", nil).Body.String()
				if !strings.Contains(page, "This person has 1 passkey.") {
					t.Fatalf("access page does not show the person's passkey")
				}
				csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(page)
				if rec := admin.postForm("/admin/passkeys/remove", url.Values{"csrf": {csrf[1]}, "email": {"user@example.com"}}); rec.Code != http.StatusFound {
					t.Fatalf("admin remove: %d", rec.Code)
				}
			}
			if verifyAny(viaPasskey).Code != http.StatusOK {
				t.Fatal("the session ended before its renewal")
			}
			srv.now = func() time.Time { return start.Add(31 * time.Minute) }
			if rec := verifyAny(viaPasskey); rec.Code != http.StatusFound {
				t.Fatalf("a removed passkey's session renewed: %d", rec.Code)
			}
			if rec := verifyAny(owner); rec.Code != http.StatusOK {
				t.Fatalf("the email-code session ended with the passkey: %d", rec.Code)
			}
			if signInWith(t, newClient(t, srv.Handler()), a).Code != http.StatusUnauthorized {
				t.Fatal("a removed passkey still signs in")
			}
		})
	}
}

// Adding a passkey needs a recent sign-in, so a stolen session cookie cannot
// be turned into a lasting passkey.
func TestAddingAPasskeyNeedsARecentSignIn(t *testing.T) {
	srv, sender := pkServer(t, nil)
	start := time.Now()
	srv.now = func() time.Time { return start }
	c := newClient(t, srv.Handler())
	phoneSignIn(t, c, sender, "user@example.com")
	// Just before the sign-in stops being recent, the passkeys page mints a
	// challenge, which stays valid for passkeyChallengeTTL.
	srv.now = func() time.Time { return start.Add(passkeyFreshness - time.Minute) }
	page := c.get("/passkeys", phone).Body.String()
	if !strings.Contains(page, "data-challenge") {
		t.Fatal("a recent sign-in was not offered a passkey ceremony")
	}
	// Two minutes later the challenge is still valid but the sign-in is not
	// recent: the registration is refused and stores nothing.
	srv.now = func() time.Time { return start.Add(passkeyFreshness + time.Minute) }
	if rec := register(t, c, passkeytest.New(), page, nil); rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/login") {
		t.Fatalf("stale registration: %d, want a redirect to sign in", rec.Code)
	}
	if list, _ := srv.store.ListPasskeys(context.Background(), "user@example.com"); len(list) != 0 {
		t.Fatalf("a stale session added a passkey: %+v", list)
	}
	// The passkeys page now shows the way back through an email code.
	page = c.get("/passkeys", phone).Body.String()
	if strings.Contains(page, "data-challenge") || !strings.Contains(page, "You will be asked to confirm your email") {
		t.Fatal("a stale session was offered a passkey ceremony")
	}
}

// An administrator's passkey: added after the second factor, it is admin
// grade and its sign-in needs no authenticator code. Added when the sign-in is
// no longer recent, it needs the code with the request.
func TestAdminPasskeys(t *testing.T) {
	srv, sender := pkServer(t, func(c *config.Config) { c.TOTPEnabled = true })
	secret := provisionTOTP(t, srv, "admin@example.com")
	start := time.Now()
	srv.now = func() time.Time { return start }
	c := newClient(t, srv.Handler())
	if rec := phoneSignIn(t, c, sender, "admin@example.com"); !strings.Contains(rec.Body.String(), "authenticator") {
		t.Fatal("no TOTP step for the admin")
	}
	code, _ := pqtotp.GenerateCode(secret, start)
	offer := c.postWith("/totp", url.Values{"code": {code}}, phone)
	if !strings.Contains(offer.Body.String(), "Sign in faster on this phone") {
		t.Fatalf("no offer after the admin's second factor: %d", offer.Code)
	}
	a := passkeytest.New()
	if rec := register(t, c, a, offer.Body.String(), nil); rec.Code != http.StatusOK {
		t.Fatalf("admin register: %d", rec.Code)
	}
	list, _ := srv.store.ListPasskeys(context.Background(), "admin@example.com")
	if len(list) != 1 || !list[0].AdminGrade {
		t.Fatalf("admin passkey not admin grade: %+v", list)
	}
	c2 := newClient(t, srv.Handler())
	if rec := signInWith(t, c2, a); rec.Code != http.StatusFound {
		t.Fatalf("admin passkey sign-in: %d", rec.Code)
	}
	if id := readSession(t, srv, c2); !id.TOTP || id.PK != list[0].ID {
		t.Fatalf("admin passkey session lacks the second factor: %+v", id)
	}
	if c2.get("/admin/", nil).Code != http.StatusOK {
		t.Fatal("admin passkey session refused by the admin pages")
	}

	// Later, the sign-in is no longer recent: the passkeys page sends the
	// administrator to the code confirmation, which refuses a wrong code and
	// accepts a right one.
	srv.now = func() time.Time { return start.Add(passkeyFreshness + time.Minute) }
	if page := c2.get("/passkeys", phone).Body.String(); !strings.Contains(page, `href="/passkeys/confirm"`) {
		t.Fatal("stale admin not sent to the code confirmation")
	}
	// The code is checked on its own, before any ceremony: a wrong code shows
	// no challenge, so the phone is never asked to make a passkey.
	confirm := c2.get("/passkeys/confirm", phone).Body.String()
	if strings.Contains(confirm, "data-challenge") || strings.Contains(confirm, "passkey.js") {
		t.Fatal("the confirmation page runs a ceremony before the code is checked")
	}
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(confirm)[1]
	wrong := c2.postWith("/passkeys/confirm", url.Values{"csrf": {csrf}, "code": {"000000"}}, phone)
	if wrong.Code != http.StatusUnauthorized || strings.Contains(wrong.Body.String(), "data-challenge") {
		t.Fatalf("wrong admin code: %d", wrong.Code)
	}
	// totp.Validate reads the real clock, and the first code (at start) was
	// used by the sign-in, so wait for the next step if they would collide.
	code, _ = pqtotp.GenerateCode(secret, time.Now())
	if first, _ := pqtotp.GenerateCode(secret, start); first == code {
		code, _ = pqtotp.GenerateCode(secret, time.Now().Add(30*time.Second))
	}
	ready := c2.postWith("/passkeys/confirm", url.Values{"csrf": {csrf}, "code": {code}}, phone)
	if ready.Code != http.StatusOK || !strings.Contains(ready.Body.String(), "data-challenge") {
		t.Fatalf("right admin code did not lead to the ceremony: %d", ready.Code)
	}
	b := passkeytest.New()
	if rec := register(t, c2, b, ready.Body.String(), nil); rec.Code != http.StatusOK {
		t.Fatalf("register after the code: %d %s", rec.Code, rec.Body.String())
	}
	// Without the code, a stale administrator's ceremony is refused even with
	// a challenge in hand: only a confirmed challenge stands in for a recent
	// sign-in.
	plain := c2.get("/passkeys", phone).Body.String()
	if strings.Contains(plain, "data-challenge") {
		t.Fatal("a stale administrator was offered a ceremony without the code")
	}
	if list, _ := srv.store.ListPasskeys(context.Background(), "admin@example.com"); len(list) != 2 {
		t.Fatalf("admin passkeys: %d, want 2", len(list))
	}
}

// A passkey added before its owner became an administrator does not satisfy
// the second factor: its sign-in continues to the authenticator step.
func TestPasskeyFromBeforePromotionStillNeedsTOTP(t *testing.T) {
	srv, sender := pkServer(t, nil)
	c := newClient(t, srv.Handler())
	a := passkeytest.New()
	register(t, c, a, phoneSignIn(t, c, sender, "user@example.com").Body.String(), nil)
	srv.cfg.TOTPEnabled = true
	srv.cfg.AdminEmails = []string{"admin@example.com", "user@example.com"}
	srv.policy = newPolicyFor(srv.cfg)
	provisionTOTP(t, srv, "user@example.com")
	rec := signInWith(t, newClient(t, srv.Handler()), a)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "authenticator") {
		t.Fatalf("a pre-promotion passkey skipped the second factor: %d", rec.Code)
	}
}

// The checks that hold the ceremony to this host and this moment.
func TestPasskeySignInRefusals(t *testing.T) {
	srv, sender := pkServer(t, nil)
	c := newClient(t, srv.Handler())
	a := passkeytest.New()
	register(t, c, a, phoneSignIn(t, c, sender, "user@example.com").Body.String(), nil)

	t.Run("a challenge is used once", func(t *testing.T) {
		c := newClient(t, srv.Handler())
		page := c.get("/login", phone).Body.String()
		captured := c.cookies[session.PasskeyLoginCookie]
		as := a.SignIn(pkRPID, pkOrigin, attr(t, page, "challenge"))
		if postAssertion(c, as.CredentialID, as.ClientDataJSON, as.AuthenticatorData, as.Signature, as.UserHandle).Code != http.StatusFound {
			t.Fatal("first use refused")
		}
		if c.cookies[session.PasskeyLoginCookie] != nil {
			t.Error("the sign-in challenge cookie outlived its use")
		}
		// Someone holding a copy of the challenge cookie and the signed answer
		// replays both.
		replay := newClient(t, srv.Handler())
		replay.cookies[session.PasskeyLoginCookie] = captured
		if postAssertion(replay, as.CredentialID, as.ClientDataJSON, as.AuthenticatorData, as.Signature, as.UserHandle).Code == http.StatusFound {
			t.Fatal("a replayed sign-in was accepted")
		}
	})
	t.Run("a sibling app's origin", func(t *testing.T) {
		c := newClient(t, srv.Handler())
		page := c.get("/login", phone).Body.String()
		as := a.SignIn(pkRPID, "https://app.example.com", attr(t, page, "challenge"))
		if postAssertion(c, as.CredentialID, as.ClientDataJSON, as.AuthenticatorData, as.Signature, as.UserHandle).Code == http.StatusFound {
			t.Fatal("a ceremony run on a sibling app signed in")
		}
	})
	t.Run("another account's handle", func(t *testing.T) {
		c := newClient(t, srv.Handler())
		page := c.get("/login", phone).Body.String()
		as := a.SignIn(pkRPID, pkOrigin, attr(t, page, "challenge"))
		if postAssertion(c, as.CredentialID, as.ClientDataJSON, as.AuthenticatorData, as.Signature, []byte("someone-else")).Code == http.StatusFound {
			t.Fatal("a mismatched account handle signed in")
		}
	})
	t.Run("an address no longer permitted", func(t *testing.T) {
		srv.cfg.AllowedDomains = []string{"other.org"}
		srv.policy = newPolicyFor(srv.cfg)
		defer func() { srv.cfg.AllowedDomains = []string{"example.com"}; srv.policy = newPolicyFor(srv.cfg) }()
		if signInWith(t, newClient(t, srv.Handler()), a).Code == http.StatusFound {
			t.Fatal("a de-listed address signed in with its passkey")
		}
	})
}

// A registration challenge is bound to the address it was minted for.
func TestRegistrationChallengeIsBoundToItsAccount(t *testing.T) {
	srv, sender := pkServer(t, nil)
	victim := newClient(t, srv.Handler())
	offer := phoneSignIn(t, victim, sender, "user@example.com").Body.String()
	attacker := newClient(t, srv.Handler())
	phoneSignIn(t, attacker, sender, "other@example.com")
	attacker.cookies[session.PasskeyRegCookie] = victim.cookies[session.PasskeyRegCookie]
	register(t, attacker, passkeytest.New(), offer, nil)
	for _, e := range []string{"user@example.com", "other@example.com"} {
		if list, _ := srv.store.ListPasskeys(context.Background(), e); len(list) != 0 {
			t.Fatalf("%s gained a passkey from another account's challenge", e)
		}
	}
}

func newPolicyFor(c *config.Config) *authz.Policy {
	return authz.NewPolicy(c.AllowedDomains, c.AdminEmails)
}

// A session from before the sign-in time was recorded must not look like a
// recent sign-in after it renews, or it could add a passkey.
func TestRenewalKeepsAnOldSessionStale(t *testing.T) {
	srv, _ := pkServer(t, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/verify", nil)
	id := &session.Identity{Email: "user@example.com", Groups: "user", Iat: srv.now().Add(-time.Hour).Unix()}
	if !srv.renewSessionWith(rec, req, id, srv.now(), nil) {
		t.Fatal("renewal refused")
	}
	c := newClient(t, srv.Handler())
	for _, ck := range rec.Result().Cookies() {
		c.cookies[ck.Name] = ck
	}
	renewed := readSession(t, srv, c)
	if srv.freshSignIn(renewed) {
		t.Fatalf("a renewed old session reads as a recent sign-in (auth=%d)", renewed.Auth)
	}
}

// A capital in AUTH_PUBLIC_URL does not break passkeys: browsers write the
// origin in lower case.
func TestPasskeysWithCapitalisedPublicURL(t *testing.T) {
	srv, sender := pkServer(t, func(c *config.Config) { c.PublicURL = "https://Auth.Example.com" })
	c := newClient(t, srv.Handler())
	a := passkeytest.New()
	if rec := register(t, c, a, phoneSignIn(t, c, sender, "user@example.com").Body.String(), nil); rec.Code != http.StatusOK {
		t.Fatalf("register: %d", rec.Code)
	}
	if rec := signInWith(t, newClient(t, srv.Handler()), a); rec.Code != http.StatusFound {
		t.Fatalf("sign-in: %d", rec.Code)
	}
}

// The single-use guard forgets a challenge only after it has expired, and
// refuses new challenges once full rather than growing without bound.
func TestChallengeGuardExpiryAndCap(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	g := newChallengeGuard(func() time.Time { return now })
	if !g.use([]byte("a")) || g.use([]byte("a")) {
		t.Fatal("a challenge was not single-use")
	}
	now = now.Add(passkeyChallengeTTL - time.Second)
	if g.use([]byte("a")) {
		t.Fatal("a challenge was reusable before it expired")
	}
	for i := 0; len(g.seen) < challengeGuardMax; i++ {
		g.seen[[32]byte{byte(i), byte(i >> 8), byte(i >> 16)}] = now.Add(time.Hour)
	}
	if g.use([]byte("b")) {
		t.Fatal("a full guard accepted a new challenge")
	}
}

// Adding a passkey emails the account holder, in the approved wording, with a
// link to their passkeys page.
func TestAddingAPasskeySendsANotice(t *testing.T) {
	srv, sender := pkServer(t, nil)
	srv.loc = time.UTC
	at := time.Date(2026, 11, 2, 15, 14, 0, 0, time.UTC)
	srv.now = func() time.Time { return at }
	c := newClient(t, srv.Handler())
	if rec := register(t, c, passkeytest.New(), phoneSignIn(t, c, sender, "user@example.com").Body.String(), nil); rec.Code != http.StatusOK {
		t.Fatalf("register: %d", rec.Code)
	}
	var notice *email.Message
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline) && notice == nil; time.Sleep(10 * time.Millisecond) {
		sender.mu.Lock()
		if len(sender.notices) > 0 {
			n := sender.notices[0]
			notice = &n
		}
		sender.mu.Unlock()
	}
	if notice == nil {
		t.Fatal("no notice sent when a passkey was added")
	}
	if notice.To != "user@example.com" || notice.Subject != "A passkey has been added to your account" {
		t.Fatalf("notice to %q, subject %q", notice.To, notice.Subject)
	}
	for _, want := range []string{
		"A passkey was added to your account at auth.example.com on 2 November 2026 at 3:14 pm, on an iPhone.",
		"If you added this passkey, there is nothing more to do.",
		"If you did not add it, open Your passkeys, remove it, then contact an administrator for assistance.",
		"https://auth.example.com/passkeys",
	} {
		if !strings.Contains(notice.Text, want) {
			t.Errorf("notice text lacks %q:\n%s", want, notice.Text)
		}
	}
	if !strings.Contains(notice.HTML, `href="https://auth.example.com/passkeys"`) {
		t.Error("notice HTML has no link to the passkeys page")
	}
	// The HTML is the branded layout, not the plain fallback, and carries the
	// same sentences as the text part.
	for _, want := range []string{
		">A passkey has been added to your account</h1>",
		"on 2 November 2026 at 3:14 pm, on an iPhone.",
		">Your passkeys</a>",
	} {
		if !strings.Contains(notice.HTML, want) {
			t.Errorf("notice HTML lacks %q", want)
		}
	}
}

// The notice's HTML template does not escape, so the gateway must: a brand
// name with markup in it is shown as text.
func TestPasskeyNoticeEscapesTheBrandName(t *testing.T) {
	srv, _ := pkServer(t, nil)
	srv.cfg.BrandName = `<b>RCH</b> & co`
	msg := srv.passkeyAddedEmail("user@example.com", "an iPhone", time.Unix(1_700_000_000, 0))
	if strings.Contains(msg.HTML, "<b>RCH</b>") || !strings.Contains(msg.HTML, "&lt;b&gt;RCH&lt;/b&gt; &amp; co") {
		t.Fatalf("brand name not escaped in the notice:\n%s", msg.HTML)
	}
}
