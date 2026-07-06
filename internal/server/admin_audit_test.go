package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// TestAdminActionsAreAudited proves a privileged mutation is recorded with the
// acting admin's identity and surfaced on the audit page — closing the gap
// where break-glass minting (and other admin actions) left no attributable trail.
func TestAdminActionsAreAudited(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)

	tok := extractCSRF(t, c.get("/admin/break", nil).Body.String())
	rec := c.postForm("/admin/break", url.Values{
		"csrf": {tok}, "label": {"Angio 1"}, "group": {"code_stroke_break_glass"},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("create = %d, want 302", rec.Code)
	}

	events, err := srv.store.ListAdminEvents(context.Background(), 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("admin events = %d, want 1", len(events))
	}
	e := events[0]
	if e.Actor != "admin@example.com" {
		t.Errorf("actor = %q, want admin@example.com", e.Actor)
	}
	if e.Action != store.AdminActionBreakCreate {
		t.Errorf("action = %q, want %q", e.Action, store.AdminActionBreakCreate)
	}
	if e.Target != "Angio 1" {
		t.Errorf("target = %q, want %q", e.Target, "Angio 1")
	}

	// The trail is reviewable evidence, not just a row: the audit page renders it.
	body := c.get("/admin/audit", nil).Body.String()
	if !strings.Contains(body, "admin@example.com") || !strings.Contains(body, store.AdminActionBreakCreate) {
		t.Error("audit page did not render the recorded action")
	}
}
