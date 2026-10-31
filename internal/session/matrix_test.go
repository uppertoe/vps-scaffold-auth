package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestEveryTokenIsReadOnlyForItsOwnPurpose presents each kind of token this
// package issues under every cookie name, to every reader, and requires that
// exactly one reader accepts it: the reader for its own purpose. Every token
// is signed with the same key, so this is the property that keeps a token
// handed to anyone (the sign-in-progress state) from being replayed as a
// session. It is the October 2026 finding stated as a matrix, so that a new
// token kind or reader cannot be added without being placed in it.
func TestEveryTokenIsReadOnlyForItsOwnPurpose(t *testing.T) {
	m := NewManager([]byte("0123456789abcdef0123456789abcdef"), time.Hour, 30*time.Minute, "", false)
	now := time.Unix(1_700_000_000, 0)

	issue := map[string]func(w http.ResponseWriter) error{
		typSession: func(w http.ResponseWriter) error {
			return m.IssueSession(w, "admin@example.com", "admin", now)
		},
		typState: func(w http.ResponseWriter) error {
			return m.SetState(w, State{Email: "admin@example.com", Redirect: "https://app.example.com/"}, 10*time.Minute, now)
		},
		typPending: func(w http.ResponseWriter) error {
			return m.SetPending(w, Pending{Email: "admin@example.com", Role: "admin"}, 10*time.Minute, now)
		},
		typOffer: func(w http.ResponseWriter) error {
			return m.SetOffer(w, Offer{CodeID: 1, Label: "Lab 1"}, 10*time.Minute, now)
		},
		typCSRF: func(w http.ResponseWriter) error {
			_, err := m.EnsureCSRF(w, httptest.NewRequest(http.MethodGet, "/", nil), time.Hour, now)
			return err
		},
	}

	// Each reader, given a token under its own cookie name.
	read := map[string]func(token string) bool{
		typSession: func(tok string) bool {
			_, ok := m.ReadSession(withCookie(SessionCookie, tok), now)
			return ok
		},
		typState: func(tok string) bool {
			_, ok := m.ReadState(withCookie(StateCookie, tok), now)
			return ok
		},
		typPending: func(tok string) bool {
			_, ok := m.ReadPending(withCookie(PendingCookie, tok), now)
			return ok
		},
		typOffer: func(tok string) bool {
			_, ok := m.ReadOffer(withCookie(OfferCookie, tok), now)
			return ok
		},
		typCSRF: func(tok string) bool {
			// The double-submit check: the cookie and the posted value agree.
			return m.VerifyCSRF(withCookie(CSRFCookie, tok), tok, now)
		},
	}

	kinds := []string{typSession, typState, typPending, typOffer, typCSRF}
	if len(issue) != len(kinds) || len(read) != len(kinds) {
		t.Fatal("a token kind is missing from the matrix")
	}
	for _, minted := range kinds {
		rec := httptest.NewRecorder()
		if err := issue[minted](rec); err != nil {
			t.Fatalf("issue %s: %v", minted, err)
		}
		cookies := rec.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("issue %s set %d cookies, want 1", minted, len(cookies))
		}
		tok := cookies[0].Value
		for _, reader := range kinds {
			got := read[reader](tok)
			if want := reader == minted; got != want {
				t.Errorf("a %s token read by the %s reader: accepted=%v, want %v", minted, reader, got, want)
			}
		}
	}
}

func withCookie(name, value string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: name, Value: value})
	return r
}
