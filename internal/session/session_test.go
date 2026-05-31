package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef")

func TestSignVerifyRoundTrip(t *testing.T) {
	s := NewSigner(testSecret)
	payload := []byte(`{"hello":"world"}`)
	tok := s.Sign(payload)
	got, err := s.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
}

func TestVerifyRejectsTamper(t *testing.T) {
	s := NewSigner(testSecret)
	tok := s.Sign([]byte("payload"))
	// Flip a character in the payload portion.
	bad := []byte(tok)
	bad[0] ^= 0x01
	if _, err := s.Verify(string(bad)); err == nil {
		t.Error("expected error for tampered payload")
	}
	if _, err := s.Verify("nodot"); err == nil {
		t.Error("expected error for token without separator")
	}
	// Different secret must not verify.
	other := NewSigner([]byte("ffffffffffffffffffffffffffffffff"))
	if _, err := other.Verify(tok); err == nil {
		t.Error("expected error verifying with wrong secret")
	}
}

func roundTripCookie(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			req.AddCookie(c)
		}
	}
	return req
}

func TestSessionIssueAndRead(t *testing.T) {
	m := NewManager(testSecret, time.Hour, 30*time.Minute, ".example.com", true)
	now := time.Unix(1_700_000_000, 0)

	rec := httptest.NewRecorder()
	if err := m.IssueSession(rec, "user@example.com", "user", now); err != nil {
		t.Fatal(err)
	}
	req := roundTripCookie(t, rec, SessionCookie)
	id, ok := m.ReadSession(req, now)
	if !ok {
		t.Fatal("ReadSession returned not-ok")
	}
	if id.Email != "user@example.com" || id.Groups != "user" {
		t.Errorf("identity = %+v", id)
	}
}

func TestSessionExpiry(t *testing.T) {
	m := NewManager(testSecret, time.Minute, time.Second, "", true)
	now := time.Unix(1_700_000_000, 0)
	rec := httptest.NewRecorder()
	_ = m.IssueSession(rec, "a@example.com", "user", now)
	req := roundTripCookie(t, rec, SessionCookie)

	if _, ok := m.ReadSession(req, now.Add(2*time.Minute)); ok {
		t.Error("expected expired session to be rejected")
	}
}

func TestNeedsRenew(t *testing.T) {
	m := NewManager(testSecret, time.Hour, 30*time.Minute, "", true)
	now := time.Unix(1_700_000_000, 0)
	id := &Identity{Email: "a@example.com", Groups: "user", Iat: now.Unix()}
	if m.NeedsRenew(id, now.Add(10*time.Minute)) {
		t.Error("should not need renew before threshold")
	}
	if !m.NeedsRenew(id, now.Add(31*time.Minute)) {
		t.Error("should need renew after threshold")
	}
}

func TestStateAndPendingRoundTrip(t *testing.T) {
	m := NewManager(testSecret, time.Hour, time.Minute, "", true)
	now := time.Unix(1_700_000_000, 0)

	rec := httptest.NewRecorder()
	_ = m.SetState(rec, State{Email: "a@example.com", Redirect: "https://app.example.com/"}, 10*time.Minute, now)
	req := roundTripCookie(t, rec, StateCookie)
	st, ok := m.ReadState(req, now)
	if !ok || st.Email != "a@example.com" || st.Redirect != "https://app.example.com/" {
		t.Errorf("ReadState = %+v ok=%v", st, ok)
	}

	rec2 := httptest.NewRecorder()
	_ = m.SetPending(rec2, Pending{Email: "admin@example.com", Role: "admin", Redirect: "https://app.example.com/"}, 10*time.Minute, now)
	req2 := roundTripCookie(t, rec2, PendingCookie)
	p, ok := m.ReadPending(req2, now)
	if !ok || p.Role != "admin" {
		t.Errorf("ReadPending = %+v ok=%v", p, ok)
	}
}
