package session

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// IssueSession and ReadSession stand in, for these tests, for the old-format
// session cookie: a signed envelope carrying the whole identity. The gateway
// now reads that format only to convert it (ReadLegacySession), so the tests
// of the envelope (its purpose, signature and expiry) still guard that path.
func (m *Manager) IssueSession(w http.ResponseWriter, email, groups string, now time.Time) error {
	tok, err := m.EncodeLegacySession(Identity{Email: email, Groups: groups, Iat: now.Unix(), Auth: now.Unix(), TTL: int64(m.ttl.Seconds())}, now.Add(m.ttl))
	if err != nil {
		return err
	}
	m.setCookie(w, SessionCookie, tok, m.cookieDomain, m.ttl)
	return nil
}

func (m *Manager) ReadSession(r *http.Request, now time.Time) (*Identity, bool) {
	v, ok := m.SessionToken(r)
	if !ok {
		return nil, false
	}
	id, _, ok := m.ReadLegacySession(v, now)
	return id, ok
}

// A new token is random, has no dot (so it never reads as the old format),
// and is stored only as its hash. The token an old cookie converts to is the
// same every time and depends on the secret.
func TestTokens(t *testing.T) {
	a, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewToken()
	if a == b || len(a) < 43 || IsLegacy(a) {
		t.Fatalf("tokens %q %q", a, b)
	}
	if string(TokenHash(a)) == a || len(TokenHash(a)) != 32 {
		t.Fatal("TokenHash is not a SHA-256")
	}
	m := NewManager(testSecret, time.Hour, 30*time.Minute, "", true)
	other := NewManager([]byte("ffffffffffffffffffffffffffffffff"), time.Hour, 30*time.Minute, "", true)
	old := "payload.mac"
	if !IsLegacy(old) || m.MigratedToken(old) != m.MigratedToken(old) || m.MigratedToken(old) == other.MigratedToken(old) || IsLegacy(m.MigratedToken(old)) {
		t.Fatal("MigratedToken is not stable, keyed and dot-free")
	}
}

// A response carries at most one session cookie, and other cookies are kept.
func TestOneSessionCookiePerResponse(t *testing.T) {
	m := NewManager(testSecret, time.Hour, 30*time.Minute, ".example.com", true)
	now := time.Unix(1_700_000_000, 0)
	rec := httptest.NewRecorder()
	http.SetCookie(rec, &http.Cookie{Name: "other", Value: "1"})
	m.SetSession(rec, "first", now.Add(time.Hour), now)
	m.SetSession(rec, "second", now.Add(time.Hour), now)
	got := rec.Header().Values("Set-Cookie")
	if len(got) != 2 || !strings.HasPrefix(got[0], "other=1") || !strings.HasPrefix(got[1], SessionCookie+"=second;") {
		t.Fatalf("cookies = %v", got)
	}
	m.ClearSession(rec)
	if got := rec.Header().Values("Set-Cookie"); len(got) != 2 || !strings.HasPrefix(got[1], SessionCookie+"=;") || !strings.Contains(got[1], "Max-Age=0") {
		t.Fatalf("after clearing: %v", got)
	}
}
