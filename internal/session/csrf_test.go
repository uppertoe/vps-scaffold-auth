package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// reqWithCookies builds a request carrying every cookie set on the given recorders.
func reqWithCookies(recs ...*httptest.ResponseRecorder) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/admin/x", nil)
	for _, rec := range recs {
		for _, c := range rec.Result().Cookies() {
			req.AddCookie(c)
		}
	}
	return req
}

func TestCSRFBindingAndExpiry(t *testing.T) {
	m := NewManager(testSecret, time.Hour, 30*time.Minute, "", true)
	now := time.Unix(1_700_000_000, 0)
	const ttl = 10 * time.Minute

	// Admin A's session, and a CSRF token minted against it.
	sa := httptest.NewRecorder()
	if err := m.IssueSession(sa, "a@example.com", "admin", now); err != nil {
		t.Fatal(err)
	}
	crec := httptest.NewRecorder()
	tok, err := m.EnsureCSRF(crec, reqWithCookies(sa), ttl, now)
	if err != nil {
		t.Fatal(err)
	}

	// Same session, fresh clock → verifies.
	if !m.VerifyCSRF(reqWithCookies(sa, crec), tok, now) {
		t.Error("valid token should verify for the issuing session")
	}
	// Past expiry → rejected (cookie MaxAge alone would not enforce this).
	if m.VerifyCSRF(reqWithCookies(sa, crec), tok, now.Add(ttl+time.Second)) {
		t.Error("expired CSRF token must be rejected")
	}
	// Bound to A, presented under B's session → rejected.
	sb := httptest.NewRecorder()
	if err := m.IssueSession(sb, "b@example.com", "admin", now); err != nil {
		t.Fatal(err)
	}
	if m.VerifyCSRF(reqWithCookies(sb, crec), tok, now) {
		t.Error("CSRF token bound to A must not verify under B's session")
	}
}
