package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

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
	if !strings.Contains(rec.Body.String(), "This app admits only other.com email addresses.") {
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
