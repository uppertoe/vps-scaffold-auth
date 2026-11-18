package server

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/passkey/passkeytest"
)

// The hospital network, as NETWORK_RANGES names it, and an address in it as
// Caddy forwards it.
const pkNetworks = "RCH=192.168.0.0/16"

var (
	computerOnNet  = map[string]string{"User-Agent": desktopUA, "X-Forwarded-For": "192.168.4.20"}
	phoneOnNet     = map[string]string{"User-Agent": iphoneUA, "X-Forwarded-For": "192.168.4.20"}
	networkRefusal = html.EscapeString(fmt.Sprintf(msgPkComputerOnNetwork, "RCH network"))
)

func pkNetworkServer(t *testing.T, adjust func(*config.Config)) (*Server, *captureSender) {
	t.Helper()
	ranges, err := config.ParseNetworkRanges(pkNetworks)
	if err != nil {
		t.Fatal(err)
	}
	return pkServer(t, func(c *config.Config) {
		c.NetworkRanges = ranges
		c.NetworkNames = config.NetworkNamesAsWritten(pkNetworks)
		if adjust != nil {
			adjust(c)
		}
	})
}

// A computer on a listed network is not offered a passkey, and is told why,
// on the passkeys page and on the add page; no ceremony is started.
func TestComputerOnTheNetworkIsNotOfferedAPasskey(t *testing.T) {
	srv, sender := pkNetworkServer(t, nil)
	c := newClient(t, srv.Handler())
	computerSignIn(t, c, sender, "user@example.com")
	for _, path := range []string{"/passkeys", "/passkeys?add=computer"} {
		page := c.get(path, computerOnNet).Body.String()
		if !strings.Contains(page, networkRefusal) {
			t.Errorf("%s on the network does not say why no passkey is offered:\n%s", path, page)
		}
		for _, not := range []string{"data-challenge", `href="/passkeys?add=computer"`, `id="passkey-add"`, msgPkComputerWarning} {
			if strings.Contains(page, not) {
				t.Errorf("%s on the network offers a passkey (%q)", path, not)
			}
		}
	}
	// Off the network, the same computer is offered one as before.
	if page := c.get("/passkeys?add=computer", computer).Body.String(); !strings.Contains(page, "data-challenge") || strings.Contains(page, networkRefusal) {
		t.Fatal("a computer off the network was not offered a passkey")
	}
}

// The registration is refused on the network whichever side of it the
// challenge was minted on, and minting none there.
func TestComputerRegistrationIsRefusedOnTheNetwork(t *testing.T) {
	t.Run("minted off the network, posted on it", func(t *testing.T) {
		srv, sender := pkNetworkServer(t, nil)
		c := newClient(t, srv.Handler())
		computerSignIn(t, c, sender, "user@example.com")
		page := c.get("/passkeys?add=computer", computer).Body.String()
		rec := registerFrom(t, c, passkeytest.NewComputer(), page, computerOnNet)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), networkRefusal) {
			t.Fatalf("a registration posted on the network: %d %s", rec.Code, rec.Body.String())
		}
		if list, _ := srv.store.ListPasskeys(context.Background(), "user@example.com"); len(list) != 0 {
			t.Fatalf("a passkey was added on the network: %+v", list)
		}
	})
	t.Run("minted on the network", func(t *testing.T) {
		srv, _ := pkNetworkServer(t, nil)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/passkeys?add=computer", nil)
		for k, v := range computerOnNet {
			req.Header.Set(k, v)
		}
		if _, err := srv.passkeyRegisterOptions(w, req, "user@example.com"); err != errPasskeyOnNetwork {
			t.Fatalf("a challenge was minted for a computer on the network: %v", err)
		}
		if len(w.Result().Cookies()) != 0 {
			t.Fatal("a challenge cookie was set on the network")
		}
	})
	t.Run("minted on the network as a phone, posted off it as a computer", func(t *testing.T) {
		// A phone's challenge is a phone's: phones are unchanged.
		srv, sender := pkNetworkServer(t, nil)
		c := newClient(t, srv.Handler())
		offer := phoneSignInWith(t, c, sender, "user@example.com", phoneOnNet)
		if rec := registerFrom(t, c, passkeytest.New(), offer, phoneOnNet); rec.Code != http.StatusOK {
			t.Fatalf("a phone on the network could not add a passkey: %d", rec.Code)
		}
	})
}

// A phone on the network keeps the offer after an email code and its
// passkeys page; a computer on the network signs in with a passkey it
// already holds; and with no ranges set, a computer at the same address is
// offered a passkey as before.
func TestPasskeyNetworkRuleLeavesTheRestAlone(t *testing.T) {
	srv, sender := pkNetworkServer(t, nil)
	p := newClient(t, srv.Handler())
	offer := phoneSignInWith(t, p, sender, "user@example.com", phoneOnNet)
	if !strings.Contains(offer, "Sign in faster on this phone") {
		t.Fatal("a phone on the network was not offered a passkey after an email code")
	}
	if page := p.get("/passkeys", phoneOnNet).Body.String(); !strings.Contains(page, "data-challenge") || strings.Contains(page, networkRefusal) {
		t.Fatal("a phone's passkeys page on the network changed")
	}

	// A passkey added off the network signs in on it.
	c := newClient(t, srv.Handler())
	computerSignIn(t, c, sender, "user@example.com")
	a := passkeytest.NewComputer()
	if rec := registerFrom(t, c, a, c.get("/passkeys?add=computer", computer).Body.String(), computer); rec.Code != http.StatusOK {
		t.Fatalf("register off the network: %d", rec.Code)
	}
	b := newClient(t, srv.Handler())
	b.cookies[passkeyHereCookie] = c.cookies[passkeyHereCookie]
	page := b.get("/login", computerOnNet).Body.String()
	if !strings.Contains(page, `data-allow="`+enc(a.ID)+`"`) {
		t.Fatal("the sign-in page on the network does not ask for the computer's passkey")
	}
	as := a.SignIn(pkRPID, pkOrigin, attr(t, page, "challenge"))
	if rec := b.postWith("/passkey/login", url.Values{
		"id": {enc(as.CredentialID)}, "clientDataJSON": {enc(as.ClientDataJSON)}, "authenticatorData": {enc(as.AuthenticatorData)},
		"signature": {enc(as.Signature)}, "userHandle": {enc(as.UserHandle)},
	}, computerOnNet); rec.Code != http.StatusFound {
		t.Fatalf("passkey sign-in on the network: %d", rec.Code)
	}

	// No ranges set: the same address is nobody's network.
	plain, sender2 := pkServer(t, nil)
	d := newClient(t, plain.Handler())
	computerSignIn(t, d, sender2, "user@example.com")
	if page := d.get("/passkeys?add=computer", computerOnNet).Body.String(); !strings.Contains(page, "data-challenge") {
		t.Fatal("with no ranges set, a computer was refused a passkey")
	}
	if rec := registerFrom(t, d, passkeytest.NewComputer(), d.get("/passkeys?add=computer", computerOnNet).Body.String(), computerOnNet); rec.Code != http.StatusOK {
		t.Fatalf("with no ranges set, a computer's registration: %d", rec.Code)
	}
}

// phoneSignInWith is phoneSignIn with the given headers, returning the page.
func phoneSignInWith(t *testing.T, c *client, sender *captureSender, email string, hdr map[string]string) string {
	t.Helper()
	sender.reset()
	c.postWith("/request", url.Values{"email": {email}}, hdr)
	return c.postWith("/verify-code", url.Values{"code": {sender.code()}}, hdr).Body.String()
}
