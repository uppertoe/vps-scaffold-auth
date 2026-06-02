package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// /verify on a domain-gated app carries the requirement into the login URL so
// the login page can hint and /request can decline early.
func TestVerifyCarriesRequirementIntoLoginURL(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv.Handler())
	rec := c.get("/verify", map[string]string{
		"X-Forwarded-Host": "app.example.com",
		"X-Forwarded-Uri":  "/x",
		"X-Auth-Policy":    "domains=rch.org.au",
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "rqd=rch.org.au") {
		t.Errorf("login redirect missing requirement hint: %q", loc)
	}
}

// The login page shows the expected domain and carries it as a hidden field.
func TestLoginPageShowsDomainHint(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv.Handler())
	body := c.get("/login?rd=&rqd=rch.org.au", nil).Body.String()
	if !strings.Contains(body, "rch.org.au") {
		t.Error("login page does not show the domain hint")
	}
	if !strings.Contains(body, `name="rqd" value="rch.org.au"`) {
		t.Error("login page does not carry rqd as a hidden field")
	}
}

// A pure domain-gated app declines a non-matching address before sending a
// code, with a clear message — and sends one when the domain matches.
func TestRequestEarlyDeniesDomainMismatch(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())

	// Mismatch: example.com user, app wants other.com -> no code, clear message.
	rec := c.postForm("/request", url.Values{"email": {"user@example.com"}, "rqd": {"other.com"}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("mismatch status = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "only available to other.com") {
		t.Errorf("missing early-deny message:\n%s", rec.Body.String())
	}
	if sender.code() != "" {
		t.Error("a code was sent despite a domain mismatch")
	}

	// Match: a code is sent and the code-entry page is shown.
	sender.reset()
	rec = c.postForm("/request", url.Values{"email": {"user@example.com"}, "rqd": {"example.com"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("matching domain status = %d, want 200", rec.Code)
	}
	if sender.code() == "" {
		t.Error("no code sent for a matching domain")
	}
}

// A valid (within-domain) alt-login link is shown on the hinted login page and
// on the early-decline page; an external URL is dropped (anti-phishing).
func TestAltLoginLinkSurfacedAndValidated(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv.Handler())

	// Shown on the hinted login page.
	body := c.get("/login?rd=&rqd=rch.org.au&alt="+
		url.QueryEscape("https://app.example.com/admin")+"&altlabel=Administrators", nil).Body.String()
	if !strings.Contains(body, `href="https://app.example.com/admin"`) || !strings.Contains(body, "Administrators") {
		t.Errorf("alt-login link not shown on login page:\n%s", body)
	}

	// External alt URL must never render on the trusted login page.
	body = c.get("/login?rd=&rqd=rch.org.au&alt="+url.QueryEscape("https://evil.com/x"), nil).Body.String()
	if strings.Contains(body, "evil.com") {
		t.Error("external alt-login URL was rendered (phishing risk)")
	}

	// Carried through to the early-decline page too.
	rec := c.postForm("/request", url.Values{
		"email": {"user@example.com"}, "rqd": {"other.com"},
		"alt": {"https://app.example.com/admin"}, "altlabel": {"Administrators"},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("decline status = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `href="https://app.example.com/admin"`) {
		t.Errorf("alt-login link not shown on decline page:\n%s", rec.Body.String())
	}
}

// /verify carries a within-domain alt-login link into the login URL, and drops
// an external one.
func TestVerifyCarriesAltLogin(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv.Handler())

	rec := c.get("/verify", map[string]string{
		"X-Forwarded-Host": "app.example.com",
		"X-Auth-Policy":    "domains=rch.org.au",
		"X-Auth-Alt-Login": "https://app.example.com/admin",
	})
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "alt=") {
		t.Errorf("alt-login not carried into login URL: %q", loc)
	}

	rec = c.get("/verify", map[string]string{
		"X-Forwarded-Host": "app.example.com",
		"X-Auth-Policy":    "domains=rch.org.au",
		"X-Auth-Alt-Login": "https://evil.com/x",
	})
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "evil.com") {
		t.Errorf("external alt-login was carried into login URL: %q", loc)
	}
}

// A friendly domain label replaces the enumerated list in both the hint and
// the decline message, while the precise domain list still governs the decline.
func TestDomainLabelReplacesEnumeration(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	const label = "an approved Victorian health service"
	rqd := "rch.org.au monashhealth.org svha.org.au alfredhealth.org.au austin.org.au"

	// The visible hint uses the label; it does not enumerate the domains. (The
	// raw list is still present in the hidden rqd carry field — that's fine — so
	// we check for the comma-joined *enumeration* form, which only the hint
	// would produce.)
	const enumerated = "monashhealth.org, svha.org.au"
	body := c.get("/login?rd=&rqd="+url.QueryEscape(rqd)+"&dlabel="+url.QueryEscape(label), nil).Body.String()
	if !strings.Contains(body, "<strong>"+label+"</strong>") {
		t.Errorf("login hint did not use the label:\n%s", body)
	}
	if strings.Contains(body, enumerated) {
		t.Error("login hint enumerated domains despite a label being set")
	}

	// A non-matching address is still declined (label is display-only), and the
	// decline message uses the label.
	rec := c.postForm("/request", url.Values{
		"email": {"user@example.com"}, "rqd": {rqd}, "dlabel": {label},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("decline status = %d, want 403", rec.Code)
	}
	if db := rec.Body.String(); !strings.Contains(db, label) || strings.Contains(db, enumerated) {
		t.Errorf("decline message did not use the label:\n%s", db)
	}
	if sender.code() != "" {
		t.Error("a code was sent despite a domain mismatch")
	}

	// A matching address still gets in (the list, not the label, is authoritative).
	sender.reset()
	if rec := c.postForm("/request", url.Values{
		"email": {"user@monashhealth.org"}, "rqd": {rqd}, "dlabel": {label},
	}); rec.Code != http.StatusOK {
		t.Fatalf("matching domain status = %d, want 200", rec.Code)
	}
}

// An admin door (group-gated) shows no domain hint on the login page.
func TestAdminDoorShowsNoHint(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv.Handler())
	body := c.get("/login?rd=&rqg=admin", nil).Body.String()
	if strings.Contains(body, "This page is for") {
		t.Error("admin (group-gated) login page should not show a domain hint")
	}
}

// The early decline keys off the declared domain alone — a route that also
// names a group still declines a non-matching domain. Group members who don't
// match the domain (admins, collaborators) use a separate group-only route.
func TestEarlyDeclineFiresEvenWithGroupOnRoute(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	rec := c.postForm("/request", url.Values{
		"email": {"user@example.com"}, "rqd": {"other.com"}, "rqg": {"admin"},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (domain decline fires despite a group on the route)", rec.Code)
	}
	if sender.code() != "" {
		t.Error("a code was sent despite a domain mismatch")
	}
}
