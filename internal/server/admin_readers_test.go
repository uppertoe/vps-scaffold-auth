package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/uppertoe/vps-scaffold-auth/internal/config"
)

// The member readers page has its own menu item, which counts the approvals
// waiting; the Overview lists them as needing attention; and the Access log
// keeps only a link to the page.
func TestReadersPageMenuOverviewAndAccessLink(t *testing.T) {
	srv, sender := fileReadersServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)

	home := c.get("/admin/", nil).Body.String()
	menu := `<a href="/admin/readers" title="Two requests to read group members are waiting for an administrator&#39;s approval.">Member readers<span class="navcount"><span class="vh">: </span>2</span></a>`
	if !strings.Contains(home, menu) {
		t.Error("the menu does not count the waiting approvals")
	}
	if !strings.Contains(home, `<li><a href="/admin/readers">Two requests to read group members</a> are waiting for an administrator&#39;s approval.</li>`) {
		t.Error("the Overview does not list the waiting approvals")
	}

	access := c.get("/admin/access", nil).Body.String()
	if strings.Contains(access, "/admin/member-readers/") || strings.Contains(access, "<h2>Apps that read group members</h2>") ||
		!strings.Contains(access, `<p class="muted">Apps that read group members are listed on the <a href="/admin/readers">Member readers</a> page.</p>`) {
		t.Error("the Access log still holds the approvals, or does not link to them")
	}

	// Once nothing waits, the count and the Overview line go.
	ctx := context.Background()
	for _, g := range []string{"coordinators", "leads"} {
		srv.store.ApproveMemberReader(ctx, "digest", g, "admin@example.com", srv.now())
	}
	home = c.get("/admin/", nil).Body.String()
	if !strings.Contains(home, `<a href="/admin/readers">Member readers</a>`) || strings.Contains(home, `class="navcount"`) || strings.Contains(home, "requests to read group members") {
		t.Error("the menu or the Overview still shows approvals waiting")
	}
	if page := c.get("/admin/readers", nil).Body.String(); !strings.Contains(page, "No requests to read group members are waiting for approval.") {
		t.Error("the page does not say that nothing is waiting")
	}
}

// Without any reader, neither the page nor its menu item nor the link exists.
func TestReadersPageOffWithoutReaders(t *testing.T) {
	srv, sender := testServer(t)
	c := newClient(t, srv.Handler())
	loginAs(t, c, sender, "admin@example.com", nil)
	if rec := c.get("/admin/readers", nil); rec.Code != http.StatusNotFound {
		t.Errorf("the page without readers = %d", rec.Code)
	}
	for _, p := range []string{"/admin/", "/admin/access"} {
		if strings.Contains(c.get(p, nil).Body.String(), "/admin/readers") {
			t.Errorf("%s links to the member readers page without readers", p)
		}
	}
}

// One row per pair, waiting rows first, each with the same four cells; an
// app in MEMBER_READERS is listed as needing no approval; a missing group
// is shown as missing, with nothing to do.
func TestReadersPageRows(t *testing.T) {
	srv, _ := testServerWith(t, func(c *config.Config) {
		c.MemberReaders = []config.MemberReader{
			{App: "alpha", Token: otherToken, Groups: []string{"ghost", "zeds"}, FromFile: true},
			{App: "digest", Token: digestToken, Groups: []string{"coordinators"}},
		}
	})
	ctx := context.Background()
	for _, g := range []string{"coordinators", "zeds"} {
		srv.store.CreateGroup(ctx, g, "")
	}
	srv.store.AddGroupMember(ctx, "zeds", "amy@example.com")
	c := newClient(t, srv.Handler())
	loginAs(t, c, srv.sender.(*captureSender), "admin@example.com", nil)
	page := c.get("/admin/readers", nil).Body.String()

	waiting := strings.Index(page, `<span class="l">Waiting for approval</span>`)
	env := strings.Index(page, `<span class="l">Listed in MEMBER_READERS</span>`)
	missing := strings.Index(page, `<span class="l">Group does not exist yet</span>`)
	if waiting < 0 || env < 0 || missing < 0 || !(waiting < env && env < missing) {
		t.Fatalf("rows out of order: waiting %d, MEMBER_READERS %d, missing %d", waiting, env, missing)
	}
	if strings.Count(page, `<div class="rrow">`) != 3 || strings.Count(page, `<div class="act">`) != 3 {
		t.Error("not one row of four cells per pair")
	}
	if !strings.Contains(page, `<a class="tok" href="/admin/groups/zeds" title="zeds"><svg class="ico" aria-hidden="true"><use href="#k-list"/></svg><span class="l">zeds</span><span class="n">1</span></a>`) {
		t.Error("the group is not drawn as a token with its kind and size")
	}
	if !strings.Contains(page, `<span class="tok static gone" title="This group does not exist yet.">`) {
		t.Error("the missing group is not shown as missing")
	}
	if !strings.Contains(page, `<div class="rstrip waiting" role="status"><i aria-hidden="true"></i><span>One request to read group members is waiting for an administrator&#39;s approval.</span></div>`) {
		t.Error("the strip does not say what is waiting")
	}

	// A confirmation for a pair that cannot be approved draws nothing.
	for _, q := range []string{"confirm=approve&app=alpha&group=ghost", "confirm=approve&app=digest&group=coordinators", "confirm=withdraw&app=alpha&group=zeds", "confirm=approve&app=alpha&group=Bad%20Name"} {
		if page := c.get("/admin/readers?"+q, nil).Body.String(); strings.Contains(page, `action="/admin/member-readers/`) || strings.Contains(page, "rstrip ask") {
			t.Errorf("?%s drew a confirmation", q)
		}
	}
	// The confirmation swaps the row's action cell, and the strip asks.
	page = c.get("/admin/readers?"+url.Values{"confirm": {"approve"}, "app": {"alpha"}, "group": {"zeds"}}.Encode(), nil).Body.String()
	if !strings.Contains(page, `<div class="rrow hit">`) || !strings.Contains(page, `<div class="rstrip ask" role="status"><i aria-hidden="true"></i><span>Approving lets alpha read the email addresses of everyone in zeds.</span></div>`) ||
		!strings.Contains(page, `<a class="btnlink quiet" href="/admin/readers">Cancel</a>`) {
		t.Error("the confirmation is not drawn in place")
	}
}
