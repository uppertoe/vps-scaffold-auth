package server

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// A completed login records a login/ok event, and a wrong code records a
// verify/wrong_code attempt — the "attempted and successful logins" trail.
func TestLoginEventsRecorded(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	c.postForm("/request", url.Values{"email": {"user@example.com"}})
	// A wrong attempt first, then the correct code (ConsumeMismatch does not
	// consume, so the real code is still valid).
	c.postForm("/verify-code", url.Values{"code": {"000000"}})
	c.postForm("/verify-code", url.Values{"code": {sender.code()}})

	events, err := srv.store.ListAuthEvents(context.Background(), "user@example.com", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	var sawWrong, sawLogin bool
	for _, e := range events {
		if e.EventType == store.AuthEventVerify && e.Outcome == store.AuthOutcomeWrongCode {
			sawWrong = true
		}
		if e.EventType == store.AuthEventLogin && e.Outcome == store.AuthOutcomeOK {
			sawLogin = true
		}
	}
	if !sawWrong {
		t.Error("wrong-code attempt was not recorded")
	}
	if !sawLogin {
		t.Error("successful login was not recorded")
	}
}

// /verify records app access, deduplicated within the hour: many hits to the same
// app collapse to a single row.
func TestAppAccessRecordedAndDeduped(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	c.postForm("/request", url.Values{"email": {"user@example.com"}})
	c.postForm("/verify-code", url.Values{"code": {sender.code()}})

	for i := 0; i < 3; i++ {
		rec := c.get("/verify", map[string]string{"X-Forwarded-Host": "app.example.com", "X-Auth-Policy": "any"})
		if rec.Code != http.StatusOK {
			t.Fatalf("/verify #%d = %d, want 200", i, rec.Code)
		}
	}
	rows, err := srv.store.ListAppAccess(context.Background(), "user@example.com", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("app_access rows = %d, want 1 (hourly dedup)", len(rows))
	}
	if rows[0].Host != "app.example.com" {
		t.Errorf("host = %q, want app.example.com", rows[0].Host)
	}
}

// The dedup is per-hour: a second access in a later hour bucket adds a new row.
// Retention 0 disables the background prune so the test is deterministic.
func TestAccessAuditHourlyBucket(t *testing.T) {
	srv, _ := testServer(t)
	a := newAccessAudit(srv.store, 0)
	ctx := context.Background()
	t0 := time.Date(2026, 6, 29, 10, 5, 0, 0, time.UTC)

	a.record(ctx, "user@example.com", "app.example.com", "", t0)
	a.record(ctx, "user@example.com", "app.example.com", "", t0.Add(40*time.Minute)) // same hour
	if rows, _ := srv.store.ListAppAccess(ctx, "user@example.com", 100, 0); len(rows) != 1 {
		t.Fatalf("same-hour rows = %d, want 1", len(rows))
	}

	a.record(ctx, "user@example.com", "app.example.com", "", t0.Add(90*time.Minute)) // next hour
	if rows, _ := srv.store.ListAppAccess(ctx, "user@example.com", 100, 0); len(rows) != 2 {
		t.Fatalf("next-hour rows = %d, want 2", len(rows))
	}

	// A blank host (a /verify with no X-Forwarded-Host) is ignored.
	a.record(ctx, "user@example.com", "", "", t0.Add(2*time.Hour))
	if rows, _ := srv.store.ListAppAccess(ctx, "user@example.com", 100, 0); len(rows) != 2 {
		t.Fatalf("after blank-host record rows = %d, want 2 (ignored)", len(rows))
	}
}

// PruneAuditBefore drops rows older than the retention cutoff from both audit
// tables while keeping recent ones.
func TestPruneAuditBefore(t *testing.T) {
	srv, _ := testServer(t)
	ctx := context.Background()
	old := time.Now().Add(-2 * 365 * 24 * time.Hour)
	recent := time.Now()

	for _, ts := range []time.Time{old, recent} {
		if err := srv.store.RecordAuthEvent(ctx, store.AuthEvent{
			Email: "a@example.com", EventType: store.AuthEventLogin, Outcome: store.AuthOutcomeOK, CreatedAt: ts,
		}); err != nil {
			t.Fatal(err)
		}
		if err := srv.store.RecordAppAccess(ctx, store.AppAccess{
			Email: "a@example.com", Host: "app.example.com", Bucket: ts.Unix() / 3600, CreatedAt: ts,
		}); err != nil {
			t.Fatal(err)
		}
	}

	if err := srv.store.PruneAuditBefore(ctx, time.Now().Add(-365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if ev, _ := srv.store.ListAuthEvents(ctx, "", 100, 0); len(ev) != 1 {
		t.Fatalf("auth_events after prune = %d, want 1", len(ev))
	}
	if ac, _ := srv.store.ListAppAccess(ctx, "", 100, 0); len(ac) != 1 {
		t.Fatalf("app_access after prune = %d, want 1", len(ac))
	}
}
