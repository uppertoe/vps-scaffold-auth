package server

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pqtotp "github.com/pquerna/otp/totp"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/config"
	"github.com/uppertoe/vps-scaffold-auth/internal/passkey/passkeytest"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// The guests release: a role held by guests opens guest sign-in on its app's
// hosts, ALLOWED_EMAIL_DOMAINS and OPEN_REGISTRATION_HOSTS are retired, and
// staff sessions from before the release carry over as guests' instead of
// ending.

// requestCodeAt asks for a code for addr with rd as the destination and
// reports whether one was mailed.
func requestCodeAt(t *testing.T, srv *Server, sender *captureSender, c *client, addr, rd string) bool {
	t.Helper()
	sender.reset()
	form := url.Values{"email": {addr}}
	if rd != "" {
		form.Set("rd", rd)
	}
	if rec := c.postForm("/request", form); rec.Code != http.StatusOK {
		t.Fatalf("request for %s at %q = %d", addr, rd, rec.Code)
	}
	return !noEmailSent(sender)
}

// Item 1. A stranger who confirms an address on the host of an app whose
// User role is held by guests signs in as a guest; on any other host,
// including the auth host and a host whose app gives guests nothing, the
// stranger is sent a decoy and no session. A direct visit is decided by
// DEFAULT_REDIRECT.
func TestGuestsOpenSignInOnTheirAppsHosts(t *testing.T) {
	srv, sender := guestServer(t)
	testGuardApp(t, srv, "closed")
	mustAssign(t, srv, store.RoleAssignment{App: "closed", Role: "user", Kind: store.AssignPerson, Ref: "p@elsewhere.org", How: store.AssignedByAdmin})
	ctx := context.Background()
	for rd, open := range map[string]bool{
		openHostRD:                         true,
		"https://apply.example.com/x?y=1":  true,
		"https://closed.example.com/":      false,
		closedHostRD:                       false, // DEFAULT_REDIRECT, no app gives guests a role there
		"https://auth.example.com/":        false,
		"https://auth.example.com/welcome": false,
		"https://apply.example.com.evil/":  false,
		"http://apply.example.com/":        false,
		"":                                 false, // DEFAULT_REDIRECT is closed
	} {
		if got := srv.isOpenHost(ctx, rd); got != open {
			t.Errorf("isOpenHost(%q) = %v, want %v", rd, got, open)
		}
		if got := requestCodeAt(t, srv, sender, newClient(t, srv.Handler()), strangerAddr, rd); got != open {
			t.Errorf("a code was sent to a stranger at %q: %v, want %v", rd, got, open)
		}
	}
	// The guest session is a guest's, holds only the guests' role, and
	// never the closed app's.
	g := newClient(t, srv.Handler())
	loginGuest(t, g, sender, strangerAddr)
	if id := sessionOf(t, srv, g); id.Kind != session.KindGuest || id.Groups != authz.RoleGuest {
		t.Fatalf("guest session = kind %q groups %q", id.Kind, id.Groups)
	}
	if rec := g.get("/verify", guardFor("apply")); rec.Code != http.StatusOK || rec.Header().Get("Remote-Roles") != "user" {
		t.Errorf("guest at the open app = %d, roles %q", rec.Code, rec.Header().Get("Remote-Roles"))
	}
	wantDenied(t, "a guest at the closed app", g.get("/verify", guardFor("closed")))

	// Staff, an administrator and a member keep their kind on the open host:
	// nobody who may sign in otherwise is made a guest.
	for addr, want := range map[string]string{"amy@example.com": "", "admin@example.com": "", "p@elsewhere.org": session.KindMember} {
		c := newClient(t, srv.Handler())
		sender.reset()
		c.postForm("/request", url.Values{"email": {addr}, "rd": {openHostRD}})
		c.postForm("/verify-code", url.Values{"code": {sender.code()}, "rd": {openHostRD}})
		if id := sessionOf(t, srv, c); id.Kind != want {
			t.Errorf("%s on the open host signed in as kind %q, want %q", addr, id.Kind, want)
		}
	}

	// With DEFAULT_REDIRECT on the open host, a direct visit to the sign-in
	// page signs a stranger up, as on p.stonn.
	srv.cfg.DefaultRedirect = openHostRD
	if !requestCodeAt(t, srv, sender, newClient(t, srv.Handler()), "new@gmail.com", "") {
		t.Error("a direct visit with DEFAULT_REDIRECT on the open host sent no code")
	}
}

// A role held by guests opens only that app's hosts. On a host two apps
// share, a guest may start there, but the app that gives guests nothing
// still refuses the guest; and guests given a role other than User hold
// nothing through it.
func TestGuestReachWhereHostsAreShared(t *testing.T) {
	srv, sender := testServerWith(t, nil)
	testGuardApp(t, srv, "open")
	testGuardApp(t, srv, "closed")
	srv.appRoles.Apps["closed"].Hosts = []string{"open.example.com"}
	mustAssign(t, srv, store.RoleAssignment{App: "open", Role: "user", Kind: store.AssignGuests})
	if !srv.isOpenHost(context.Background(), "https://open.example.com/") {
		t.Fatal("the shared host is not open")
	}
	g := newClient(t, srv.Handler())
	sender.reset()
	g.postForm("/request", url.Values{"email": {strangerAddr}, "rd": {"https://open.example.com/"}})
	g.postForm("/verify-code", url.Values{"code": {sender.code()}, "rd": {"https://open.example.com/"}})
	if rec := g.get("/verify", guardFor("open")); rec.Code != http.StatusOK {
		t.Fatalf("guest at the open app = %d", rec.Code)
	}
	closed := guardFor("closed")
	closed["X-Forwarded-Host"] = "open.example.com"
	wantDenied(t, "a guest at the closed app on the shared host", g.get("/verify", closed))
	closed["X-Auth-Role"] = "admin"
	wantDenied(t, "a guest at the closed app's Administrator", g.get("/verify", closed))
	adminGuard := guardFor("open")
	adminGuard["X-Auth-Role"] = "admin"
	wantDenied(t, "a guest at the open app's Administrator", g.get("/verify", adminGuard))
	if err := srv.store.AddRoleAssignment(context.Background(), store.RoleAssignment{App: "open", Role: "admin", Kind: store.AssignGuests}); err == nil {
		t.Error("the store gave guests a role other than User")
	}
	// The auth host is never a destination open to guests, even if a
	// manifest entry tried to name it (refused at start; see
	// TestManifestNamingTheAuthHostIsRefused).
	if srv.isOpenHost(context.Background(), "https://auth.example.com/admin/") {
		t.Error("the auth host is open to guests")
	}
}

// Item 5. A manifest that gives an app the auth host stops start-up.
func TestManifestNamingTheAuthHostIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app-roles.tsv")
	if err := os.WriteFile(path, []byte("sneaky\tuser\tUser\tauth.{$DOMAIN},sneaky.{$DOMAIN}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := &config.Config{PublicURL: "https://Auth.example.com", Domain: "example.com", AdminEmails: []string{"admin@example.com"},
		SessionSecret: []byte("0123456789abcdef0123456789abcdef"), AppRolesFile: path, SessionTTL: time.Hour}
	if _, err := New(cfg, st, newCaptureSender()); err == nil || !strings.Contains(err.Error(), "auth host") {
		t.Fatalf("New with an app on the auth host = %v, want a refusal", err)
	}
	if err := os.WriteFile(path, []byte("fine\tuser\tUser\tfine.{$DOMAIN}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg, st, newCaptureSender()); err != nil {
		t.Fatalf("New with an ordinary manifest: %v", err)
	}
}

// Item 3. A retired setting is reported once at start and otherwise
// ignored: ALLOWED_EMAIL_DOMAINS=* makes no stranger staff, and
// OPEN_REGISTRATION_HOSTS opens no host.
func TestRetiredSettingsAreReportedAndIgnored(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	srv, sender := testServerWith(t, func(c *config.Config) {
		c.RetiredSet = []string{"ALLOWED_EMAIL_DOMAINS", "OPEN_REGISTRATION_HOSTS"}
	})
	log.SetOutput(os.Stderr)
	for _, k := range config.RetiredSettings {
		if !strings.Contains(buf.String(), msgRetired[k]) {
			t.Errorf("no start-up warning for %s in %q", k, buf.String())
		}
	}
	if got := srv.knownRole(context.Background(), strangerAddr); got != authz.RoleDeny {
		t.Errorf("a stranger is %q, want deny", got)
	}
	if requestCodeAt(t, srv, sender, newClient(t, srv.Handler()), strangerAddr, "https://apply.example.com/") {
		t.Error("a code was sent to a stranger on a host no app gives guests")
	}
}

// The release is recorded once: a later start keeps the first time.
func TestReleaseIsRecordedOnce(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	first, err := st.FirstRun(ctx, guestsFromRolesRelease, time.Unix(1_000, 0))
	if err != nil || first.Unix() != 1_000 {
		t.Fatalf("first run = %v, %v", first, err)
	}
	if again, err := st.FirstRun(ctx, guestsFromRolesRelease, time.Unix(9_000, 0)); err != nil || again.Unix() != 1_000 {
		t.Errorf("a later start = %v, %v; want the first time kept", again, err)
	}
	cfg := &config.Config{PublicURL: "https://auth.example.com", Domain: "example.com", AdminEmails: []string{"admin@example.com"},
		SessionSecret: []byte("0123456789abcdef0123456789abcdef"), SessionTTL: time.Hour}
	srv, err := New(cfg, st, newCaptureSender())
	if err != nil {
		t.Fatal(err)
	}
	if srv.guestsReleasedAt.Unix() != 1_000 {
		t.Errorf("guestsReleasedAt = %v, want the first run", srv.guestsReleasedAt)
	}
}

// pstonnServer is shaped like markbot: no domain groups, one app, p, whose
// User role guests hold and whose Administrator role the owner holds by
// name. ADMIN_EMAILS names the gateway's administrator, admin@example.com;
// the owner, owner@pstonn.org, is not in it. The release is taken to have
// first run at released.
func pstonnServer(t *testing.T, released time.Time) (*Server, *captureSender) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app-roles.tsv")
	if err := os.WriteFile(path, []byte("p\tuser\tUser\tp.{$DOMAIN}\np\tadmin\tAdministrator\tp.{$DOMAIN}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, sender := testServerNoStaff(t, func(c *config.Config) {
		c.AppRolesFile = path
		c.DefaultRedirect = "https://p.example.com/"
		c.SessionTTL = 30 * 24 * time.Hour
		c.SessionRememberTTL = 30 * 24 * time.Hour
		c.SessionMaxAge = 90 * 24 * time.Hour
	})
	mustAssign(t, srv, store.RoleAssignment{App: "p", Role: "user", Kind: store.AssignGuests})
	mustAssign(t, srv, store.RoleAssignment{App: "p", Role: "admin", Kind: store.AssignPerson, Ref: "owner@pstonn.org", How: store.AssignedByAdmin})
	srv.guestsReleasedAt = released
	return srv, sender
}

// Item 2. Upgrading a p.stonn-shaped server signs nobody out. Every session
// was made under ALLOWED_EMAIL_DOMAINS=*, so each is a staff session. At its
// next request a member of the public becomes a guest with the same
// Remote-Roles, the owner (Administrator by name) becomes a member and keeps
// Administrator, the gateway's administrator stays one, and an old signed
// cookie converts and carries over as well. A remembered session gives up the
// remember-me lifetime.
func TestUpgradeSignsNobodyOutOnAPstonnShapedServer(t *testing.T) {
	now := time.Now()
	released := now.Add(-time.Minute)
	srv, _ := pstonnServer(t, released)
	srv.now = func() time.Time { return now }
	before := released.Add(-10 * 24 * time.Hour).Unix()
	guard := guardFor("p")
	mint := func(email string, ttl time.Duration) *client {
		return mintSession(t, srv, session.Identity{Email: email, Groups: authz.RoleUser, Auth: before}, ttl)
	}
	public := mint("reader@gmail.com", 30*24*time.Hour)
	remembered := mint("keeper@bigpond.com", 60*24*time.Hour)
	owner := mint("owner@pstonn.org", 30*24*time.Hour)
	admin := mintSession(t, srv, session.Identity{Email: "admin@example.com", Groups: authz.RoleAdmin, Auth: before}, 30*24*time.Hour)
	old := clientWith(t, srv, legacyCookie(t, srv, session.Identity{Email: "old@outlook.com", Groups: authz.RoleUser, Iat: before, Auth: before, TTL: int64((30 * 24 * time.Hour).Seconds())}, now.Add(20*24*time.Hour)))

	for name, c := range map[string]*client{"public": public, "remembered": remembered, "owner": owner, "admin": admin, "old cookie": old} {
		rec := c.get("/verify", guard)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s was not admitted after the upgrade: %d to %q", name, rec.Code, rec.Header().Get("Location"))
		}
	}
	check := func(name string, c *client, kind, roles string) {
		t.Helper()
		rec := c.get("/verify", guard)
		id := sessionOf(t, srv, c)
		if rec.Code != http.StatusOK || id.Kind != kind || rec.Header().Get("Remote-Roles") != roles {
			t.Errorf("%s: %d, kind %q, roles %q; want 200, kind %q, roles %q", name, rec.Code, id.Kind, rec.Header().Get("Remote-Roles"), kind, roles)
		}
	}
	check("public", public, session.KindGuest, "user")
	check("remembered", remembered, session.KindGuest, "user")
	check("old cookie", old, session.KindGuest, "user")
	check("owner", owner, session.KindMember, "admin,user")
	check("admin", admin, "", "user")
	if id := sessionOf(t, srv, remembered); id.TTL != int64(srv.cfg.SessionTTL.Seconds()) {
		t.Errorf("the carried-over session kept a lifetime of %ds", id.TTL)
	}
	if id := sessionOf(t, srv, public); !strings.HasPrefix(id.Groups, authz.RoleGuest) || id.Auth != before {
		t.Errorf("carried-over session: groups %q, sign-in %d (want guest, %d)", id.Groups, id.Auth, before)
	}
	if !isAdminSession(sessionOf(t, srv, admin)) {
		t.Error("the gateway's administrator lost the admin tier")
	}
	for _, e := range []string{"reader@gmail.com", "keeper@bigpond.com", "owner@pstonn.org", "admin@example.com", "old@outlook.com"} {
		if liveCount(srv, e) != 1 {
			t.Errorf("%s has %d sessions, want 1", e, liveCount(srv, e))
		}
	}
	// The carried-over guest has Your sessions and the guests' passkey rules.
	if rec := public.get("/sessions", nil); rec.Code != http.StatusOK {
		t.Errorf("the carried-over guest's Your sessions = %d", rec.Code)
	}

	// A new member of the public signs up on p and, by a direct visit, on
	// the auth host, whose DEFAULT_REDIRECT is p.
	_, sender := srv, srv.sender.(*captureSender)
	for _, rd := range []string{"https://p.example.com/schedule", ""} {
		c := newClient(t, srv.Handler())
		sender.reset()
		c.postForm("/request", url.Values{"email": {"newcomer@gmail.com"}, "rd": {rd}})
		code := sender.code()
		if code == "" {
			t.Fatalf("no code for a newcomer at %q", rd)
		}
		c.postForm("/verify-code", url.Values{"code": {code}, "rd": {rd}})
		if id := sessionOf(t, srv, c); id.Kind != session.KindGuest {
			t.Errorf("newcomer at %q = kind %q, want guest", rd, id.Kind)
		}
	}
}

// The carry-over is only for sessions from before the release, only for a
// staff session, and only while some app's role is held by guests.
func TestCarryOverIsOnlyForOldStaffSessions(t *testing.T) {
	now := time.Now()
	released := now.Add(-time.Hour)
	guard := guardFor("p")
	signedOut := func(t *testing.T, srv *Server, c *client, what string) {
		t.Helper()
		rec := c.get("/verify", guard)
		if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/login") {
			t.Errorf("%s: %d to %q, want sign-in", what, rec.Code, rec.Header().Get("Location"))
		}
	}
	t.Run("a session the release started", func(t *testing.T) {
		srv, _ := pstonnServer(t, released)
		srv.now = func() time.Time { return now }
		c := mintSession(t, srv, session.Identity{Email: "late@gmail.com", Groups: authz.RoleUser, Auth: released.Add(time.Second).Unix()}, time.Hour)
		signedOut(t, srv, c, "a staff session begun after the release")
	})
	t.Run("a member's session", func(t *testing.T) {
		srv, _ := pstonnServer(t, released)
		srv.now = func() time.Time { return now }
		c := mintSession(t, srv, session.Identity{Email: "ex-member@gmail.com", Groups: authz.RoleGuest, Kind: session.KindMember, Auth: released.Add(-time.Hour).Unix()}, time.Hour)
		signedOut(t, srv, c, "a member who no longer holds a role")
	})
	t.Run("no app gives guests a role", func(t *testing.T) {
		srv, _ := pstonnServer(t, released)
		srv.now = func() time.Time { return now }
		noGuestsAnywhere(t, srv)
		mustAssign(t, srv, store.RoleAssignment{App: "p", Role: "user", Kind: store.AssignPerson, Ref: "other@gmail.com", How: store.AssignedByAdmin})
		c := mintSession(t, srv, session.Identity{Email: "reader@gmail.com", Groups: authz.RoleUser, Auth: released.Add(-time.Hour).Unix()}, time.Hour)
		signedOut(t, srv, c, "an old staff session with guests holding nothing")
	})
	t.Run("the rule is off", func(t *testing.T) {
		srv, _ := pstonnServer(t, time.Time{})
		c := mintSession(t, srv, session.Identity{Email: "reader@gmail.com", Groups: authz.RoleUser, Auth: released.Add(-time.Hour).Unix()}, time.Hour)
		signedOut(t, srv, c, "with no release recorded")
	})
	t.Run("staff whose domain group loses its role after the release", func(t *testing.T) {
		srv, sender := pstonnServer(t, released)
		seedStaff(t, srv, "example.com")
		c := newClient(t, srv.Handler())
		loginAs(t, c, sender, "amy@example.com", nil)
		unseedStaff(t, srv)
		signedOut(t, srv, c, "staff who signed in after the release")
	})
}

// Item 7. A guest may add a passkey on a phone, and on a computer under the
// computer's rules (asked for, held by the computer, never on a listed
// network). It is never admin grade. Signing in with it gives a guest
// session where an emailed code would, and nothing anywhere else.
func TestGuestPasskeys(t *testing.T) {
	srv, sender := pkNetworkServer(t, func(c *config.Config) { c.DefaultRedirect = openHostRD })
	openToGuestsForTest(t, srv, "apply")
	g := newClient(t, srv.Handler())
	offer := phoneSignIn(t, g, sender, strangerAddr)
	if id := sessionOf(t, srv, g); id.Kind != session.KindGuest {
		t.Fatalf("stranger signed in as kind %q, want guest", id.Kind)
	}
	if offer.Code != http.StatusOK || !strings.Contains(offer.Body.String(), "data-challenge") {
		t.Fatalf("a guest on a phone was not offered a passkey: %d", offer.Code)
	}
	a := passkeytest.New()
	if rec := register(t, g, a, offer.Body.String(), nil); rec.Code != http.StatusOK {
		t.Fatalf("guest passkey registration = %d %s", rec.Code, rec.Body.String())
	}
	keys, _ := srv.store.ListPasskeys(context.Background(), strangerAddr)
	if len(keys) != 1 || keys[0].AdminGrade {
		t.Fatalf("guest passkeys = %+v, want one, not admin grade", keys)
	}
	if rec := g.get("/passkeys", phone); rec.Code != http.StatusOK {
		t.Errorf("a guest's passkeys page = %d", rec.Code)
	}

	// Signing in with it, where an emailed code would make a guest.
	p := newClient(t, srv.Handler())
	if rec := signInWith(t, p, a); rec.Code != http.StatusFound {
		t.Fatalf("guest passkey sign-in = %d %s", rec.Code, rec.Body.String())
	}
	if id := sessionOf(t, srv, p); id.Kind != session.KindGuest || id.PK == 0 {
		t.Errorf("passkey sign-in = kind %q pk %d, want a guest's passkey session", id.Kind, id.PK)
	}
	// Towards a host where guests hold nothing, it is refused, exactly as an
	// emailed code would be.
	q := newClient(t, srv.Handler())
	page := q.get("/login?rd="+url.QueryEscape(closedHostRD), phone).Body.String()
	as := a.SignIn(pkRPID, pkOrigin, attr(t, page, "challenge"))
	rec := q.postWith("/passkey/login", url.Values{
		"id": {enc(as.CredentialID)}, "clientDataJSON": {enc(as.ClientDataJSON)}, "authenticatorData": {enc(as.AuthenticatorData)},
		"signature": {enc(as.Signature)}, "userHandle": {enc(as.UserHandle)}, "rd": {closedHostRD},
	}, phone)
	if rec.Code == http.StatusFound || q.cookies[session.SessionCookie] != nil {
		t.Errorf("a guest's passkey signed in towards a host where guests hold nothing: %d", rec.Code)
	}
	// Once no app gives guests a role, the passkey signs in nowhere.
	noGuestsAnywhere(t, srv)
	if rec := signInWith(t, newClient(t, srv.Handler()), a); rec.Code == http.StatusFound {
		t.Error("a guest's passkey signed in with guests holding nothing")
	}
	openToGuestsForTest(t, srv, "apply")

	// A guest's computer: the passkey is offered only when asked for, and a
	// registration on a listed network is refused.
	c := newClient(t, srv.Handler())
	if rec := computerSignIn(t, c, sender, "desk@gmail.com"); rec.Code != http.StatusFound {
		t.Fatalf("a guest's computer was offered a passkey unasked: %d", rec.Code)
	}
	page = c.get("/passkeys?add=computer", computer).Body.String()
	if rec := registerFrom(t, c, passkeytest.NewComputer(), page, computerOnNet); rec.Code != http.StatusForbidden {
		t.Errorf("a guest's computer registration on the network = %d, want 403", rec.Code)
	}
	if keys, _ := srv.store.ListPasskeys(context.Background(), "desk@gmail.com"); len(keys) != 0 {
		t.Errorf("a guest's computer passkey was added on the network: %+v", keys)
	}
	if rec := c.get("/passkeys", computerOnNet); !strings.Contains(rec.Body.String(), networkRefusal) {
		t.Error("the passkeys page does not tell a guest on the network why it cannot add one")
	}
}

// Must-fix 1. A manifest that cannot be read (a directory, as Docker makes
// for a missing bind-mount source, or a missing file) or declares no app
// stops start-up, rather than starting with nobody staff and every session
// ending at its next request.
func TestManifestUnreadableOrEmptyRefusesStart(t *testing.T) {
	dir := t.TempDir()
	asDir := filepath.Join(dir, "as-dir.tsv")
	if err := os.Mkdir(asDir, 0o700); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty.tsv")
	if err := os.WriteFile(empty, []byte("# no apps\n\nbroken line\n@label\tx\tX\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"a directory": asDir, "a missing file": filepath.Join(dir, "missing.tsv"), "no app": empty} {
		st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "auth.db"))
		if err != nil {
			t.Fatal(err)
		}
		cfg := &config.Config{PublicURL: "https://auth.example.com", Domain: "example.com", AdminEmails: []string{"admin@example.com"},
			SessionSecret: []byte("0123456789abcdef0123456789abcdef"), AppRolesFile: path, SessionTTL: time.Hour}
		if _, err := New(cfg, st, newCaptureSender()); err == nil || !strings.Contains(err.Error(), "APP_ROLES_FILE") {
			t.Errorf("%s: New = %v, want a refusal naming APP_ROLES_FILE", name, err)
		}
		st.Close()
	}
}

// Must-fix 1. A restart whose manifest has lost the app guests hold a role
// in is a configuration fault: guest sessions, and staff sessions that would
// carry over as guests', are kept and answered 503, not ended. Declaring
// the app again brings them back; taking guests off the app on purpose ends
// them as before.
func TestGuestsStrandedByTheManifestAreKept(t *testing.T) {
	now := time.Now()
	released := now.Add(-time.Hour)
	srv, sender := pstonnServer(t, released)
	srv.now = func() time.Time { return now }
	old := mintSession(t, srv, session.Identity{Email: "reader@gmail.com", Groups: authz.RoleUser, Auth: released.Add(-time.Hour).Unix()}, time.Hour)
	g := newClient(t, srv.Handler())
	sender.reset()
	g.postForm("/request", url.Values{"email": {"guest@gmail.com"}, "rd": {"https://p.example.com/"}})
	g.postForm("/verify-code", url.Values{"code": {sender.code()}, "rd": {"https://p.example.com/"}})
	if id := sessionOf(t, srv, g); id.Kind != session.KindGuest {
		t.Fatalf("guest kind %q", id.Kind)
	}

	restart := func(manifest string) *Server {
		t.Helper()
		path := filepath.Join(t.TempDir(), "app-roles.tsv")
		if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := *srv.cfg
		cfg.AppRolesFile = path
		next, err := New(&cfg, srv.store, newCaptureSender())
		if err != nil {
			t.Fatal(err)
		}
		next.now = srv.now
		next.guestsReleasedAt = released
		return next
	}
	other := restart("other\tuser\tUser\tother.{$DOMAIN}\n")
	if !other.guestsStranded(context.Background()) {
		t.Fatal("the lost app's guests assignment is not seen as stranded")
	}
	for name, c := range map[string]*client{"guest": g, "carried over": old} {
		c2 := clientWith(t, other, c.cookies[session.SessionCookie])
		if rec := c2.get("/verify", guardFor("other")); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s with the app gone from the manifest = %d, want 503", name, rec.Code)
		}
	}
	if liveCount(other, "guest@gmail.com") != 1 || liveCount(other, "reader@gmail.com") != 1 {
		t.Fatal("a session was ended while the manifest had lost the guests' app")
	}

	back := restart("p\tuser\tUser\tp.{$DOMAIN}\n")
	for name, c := range map[string]*client{"guest": g, "carried over": old} {
		c2 := clientWith(t, back, c.cookies[session.SessionCookie])
		if rec := c2.get("/verify", guardFor("p")); rec.Code != http.StatusOK {
			t.Errorf("%s once the app is declared again = %d, want 200", name, rec.Code)
		}
	}
	// Taking guests off the app is a decision: the guest session ends.
	noGuestsAnywhere(t, back)
	c2 := clientWith(t, back, g.cookies[session.SessionCookie])
	if rec := c2.get("/verify", guardFor("p")); rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/login") {
		t.Errorf("guest once guests were taken off p = %d to %q, want sign-in", rec.Code, rec.Header().Get("Location"))
	}
}

// Must-fix 2. A sign-in towards one of the gateway's own pages (Your
// sessions, Your passkeys, the links in its emails) is decided as one to
// DEFAULT_REDIRECT, so a signed-out guest can sign in again there when a
// direct visit could; the person lands back on the page. Where
// DEFAULT_REDIRECT is closed to guests, so is the auth host.
func TestGuestSignsInTowardsTheGatewaysOwnPages(t *testing.T) {
	srv, sender := pstonnServer(t, time.Now().Add(-time.Hour))
	// A signed-out visit to Your sessions is sent to sign in with the page
	// as its destination.
	if rec := newClient(t, srv.Handler()).get("/sessions", nil); !strings.Contains(rec.Header().Get("Location"), url.QueryEscape("https://auth.example.com/sessions")) {
		t.Fatalf("signed-out /sessions = %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	for _, rd := range []string{"https://auth.example.com/sessions", "https://auth.example.com/passkeys"} {
		c := newClient(t, srv.Handler())
		if !requestCodeAt(t, srv, sender, c, "reader@gmail.com", rd) {
			t.Fatalf("no code for a guest signing in towards %s", rd)
		}
		rec := c.postForm("/verify-code", url.Values{"code": {sender.code()}, "rd": {rd}})
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != rd {
			t.Errorf("guest sign-in towards %s = %d to %q", rd, rec.Code, rec.Header().Get("Location"))
		}
		if id := sessionOf(t, srv, c); id.Kind != session.KindGuest {
			t.Errorf("towards %s: kind %q, want guest", rd, id.Kind)
		}
	}
	// The admin pages still refuse the guest.
	c := newClient(t, srv.Handler())
	requestCodeAt(t, srv, sender, c, "nosy@gmail.com", "https://auth.example.com/admin/")
	c.postForm("/verify-code", url.Values{"code": {sender.code()}, "rd": {"https://auth.example.com/admin/"}})
	if rec := c.get("/admin/", nil); rec.Code == http.StatusOK {
		t.Error("a guest reached the admin pages")
	}

	rch, rsender := rchShapedServer(t, time.Now().Add(-time.Hour))
	if requestCodeAt(t, rch, rsender, newClient(t, rch.Handler()), "reader@gmail.com", "https://auth.example.com/sessions") {
		t.Error("a stranger was sent a code towards the auth host where DEFAULT_REDIRECT is closed to guests")
	}
}

// rchShapedServer is shaped like RCH: staff at example.com through a domain
// group that holds home's User role, guests holding enquiries' User role,
// and DEFAULT_REDIRECT the apex, which no app gives guests.
func rchShapedServer(t *testing.T, released time.Time) (*Server, *captureSender) {
	t.Helper()
	srv, sender := testServerWith(t, func(c *config.Config) {
		c.DefaultRedirect = "https://example.com/"
		c.SessionTTL = 24 * time.Hour
		c.SessionRememberTTL = 30 * 24 * time.Hour
		c.SessionMaxAge = 30 * 24 * time.Hour
	})
	openToGuestsForTest(t, srv, "enquiries")
	testGuardApp(t, srv, "home")
	mustAssign(t, srv, store.RoleAssignment{App: "home", Role: "user", Kind: store.AssignDomainGroup, Ref: staffHarnessGroup})
	srv.guestsReleasedAt = released
	srv.forgetRoles()
	return srv, sender
}

// On an RCH-shaped server the upgrade changes nothing: staff stay staff with
// their remembered lifetime, a guest stays a guest at enquiries only, and the
// administrator keeps the admin tier.
func TestRCHShapedUpgradeChangesNothing(t *testing.T) {
	now := time.Now()
	released := now.Add(-time.Minute)
	srv, _ := rchShapedServer(t, released)
	srv.now = func() time.Time { return now }
	before := released.Add(-5 * 24 * time.Hour).Unix()
	staff := mintSession(t, srv, session.Identity{Email: "amy@example.com", Groups: authz.RoleUser, Auth: before}, 30*24*time.Hour)
	guest := mintSession(t, srv, session.Identity{Email: "applicant@gmail.com", Groups: authz.RoleGuest, Kind: session.KindGuest, Auth: before}, 24*time.Hour)
	admin := mintSession(t, srv, session.Identity{Email: "admin@example.com", Groups: authz.RoleAdmin, Auth: before}, 30*24*time.Hour)
	for _, tc := range []struct {
		name, guard, kind string
		c                 *client
		code              int
	}{
		{"staff at home", "home", "", staff, http.StatusOK},
		{"staff at enquiries", "enquiries", "", staff, http.StatusOK},
		{"guest at enquiries", "enquiries", session.KindGuest, guest, http.StatusOK},
		{"guest at home", "home", session.KindGuest, guest, http.StatusFound},
		{"admin at home", "home", "", admin, http.StatusOK},
	} {
		rec := tc.c.get("/verify", guardFor(tc.guard))
		if id := sessionOf(t, srv, tc.c); rec.Code != tc.code || id.Kind != tc.kind {
			t.Errorf("%s: %d kind %q, want %d kind %q", tc.name, rec.Code, id.Kind, tc.code, tc.kind)
		}
	}
	if id := sessionOf(t, srv, staff); id.TTL != int64((30 * 24 * time.Hour).Seconds()) {
		t.Errorf("staff remembered lifetime changed: %d", id.TTL)
	}
	if !isAdminSession(sessionOf(t, srv, admin)) {
		t.Error("the administrator lost the admin tier")
	}
	for _, e := range []string{"amy@example.com", "applicant@gmail.com", "admin@example.com"} {
		if liveCount(srv, e) != 1 {
			t.Errorf("%s has %d sessions, want 1", e, liveCount(srv, e))
		}
	}
}

// Only the open app's own hosts are open: not a subdomain of one, not a
// look-alike, not another scheme, and not a host whose app gives guests
// nothing. Case and a port do not matter, as a browser reads them.
func TestOpenHostVariants(t *testing.T) {
	srv, sender := rchShapedServer(t, time.Now().Add(-time.Hour))
	i := 0
	for rd, want := range map[string]bool{
		"https://enquiries.example.com/x":           true,
		"https://ENQUIRIES.example.com/":            true,
		"https://enquiries.example.com:8443/":       true,
		"https://enquiries.example.com./":           false,
		"https://a.enquiries.example.com/":          false,
		"https://auth.example.com/":                 false,
		"https://example.com/":                      false,
		"":                                          false,
		"http://enquiries.example.com/":             false,
		"https://enquiries.example.com.evil.org/":   false,
		"https://evil.org/?x=enquiries.example.com": false,
		"//enquiries.example.com/":                  false,
		"https://home.example.com/":                 false,
	} {
		i++
		if got := requestCodeAt(t, srv, sender, newClient(t, srv.Handler()), fmt.Sprintf("nobody%d@gmail.com", i), rd); got != want {
			t.Errorf("rd %q: code sent %v, want %v", rd, got, want)
		}
	}
}

// A code asked for on the way to the open host, entered with a closed host
// as the destination, makes no session: the verify step decides afresh.
func TestRequestOpenVerifyClosedMakesNoSession(t *testing.T) {
	srv, sender := rchShapedServer(t, time.Now().Add(-time.Hour))
	c := newClient(t, srv.Handler())
	if !requestCodeAt(t, srv, sender, c, "nobody@gmail.com", "https://enquiries.example.com/") {
		t.Fatal("no code on the open host")
	}
	rec := c.postForm("/verify-code", url.Values{"code": {sender.code()}, "rd": {"https://home.example.com/"}})
	if c.cookies[session.SessionCookie] != nil {
		t.Errorf("a session was made towards a closed host: %d", rec.Code)
	}
}

// A guest's passkey is never admin grade: the role is checked on its own,
// before the second factor and the admin step, so neither a confirmed
// challenge nor a fresh step makes a non-administrator's passkey admin grade.
func TestOnlyAnAdministratorsPasskeyIsAdminGrade(t *testing.T) {
	for _, role := range []string{authz.RoleGuest, authz.RoleMember, authz.RoleUser, authz.RoleDeny} {
		if adminGradeFor(role, true, true, true) {
			t.Errorf("a %q passkey is admin grade", role)
		}
	}
	if !adminGradeFor(authz.RoleAdmin, true, true, false) || !adminGradeFor(authz.RoleAdmin, true, false, true) {
		t.Error("an administrator's passkey after the second step is not admin grade")
	}
	if adminGradeFor(authz.RoleAdmin, false, true, true) || adminGradeFor(authz.RoleAdmin, true, false, false) {
		t.Error("an administrator's passkey is admin grade without TOTP or the second step")
	}
}

// A passkey sign-in gives the second step only to a current administrator:
// an admin-grade passkey whose person has left ADMIN_EMAILS signs in as
// staff, with no second step recorded.
func TestAdminGradePasskeyOfAFormerAdministratorGivesNoSecondStep(t *testing.T) {
	srv, sender := pkServer(t, func(c *config.Config) { c.TOTPEnabled = true })
	secret := provisionTOTP(t, srv, "admin@example.com")
	start := time.Now()
	srv.now = func() time.Time { return start }
	c := newClient(t, srv.Handler())
	phoneSignIn(t, c, sender, "admin@example.com")
	door := c.get("/totp", phone).Body.String()
	code, _ := pqtotp.GenerateCode(secret, start)
	offer := c.postWith("/totp", url.Values{"code": {code}, "csrf": {extractCSRF(t, door)}}, phone)
	a := passkeytest.New()
	if rec := register(t, c, a, offer.Body.String(), nil); rec.Code != http.StatusOK {
		t.Fatalf("admin register: %d", rec.Code)
	}
	if list, _ := srv.store.ListPasskeys(context.Background(), "admin@example.com"); len(list) != 1 || !list[0].AdminGrade {
		t.Fatalf("passkey = %+v, want one admin grade", list)
	}
	srv.policy = authz.NewPolicy(nil) // no longer an administrator; still staff
	p := newClient(t, srv.Handler())
	if rec := signInWith(t, p, a); rec.Code != http.StatusFound {
		t.Fatalf("former administrator's passkey sign-in = %d", rec.Code)
	}
	if id := readSession(t, srv, p); id.TOTP || id.Kind != "" || strings.Contains(id.Groups, authz.RoleAdmin) {
		t.Errorf("former administrator's passkey session = %+v, want staff with no second step", id)
	}
}

// A guests assignment left behind for an app that was already gone at the
// previous start does not keep guest sessions: once an administrator takes
// guests off the last declared app, a guest is signed out, not answered 503.
func TestRecheckStrandedWithOrphanAfterAdminRemoval(t *testing.T) {
	now := time.Now()
	srv, _ := rchShapedServer(t, now.Add(-time.Hour))
	srv.now = func() time.Time { return now }
	mustAssign(t, srv, store.RoleAssignment{App: "old-app", Role: "user", Kind: store.AssignGuests})
	g := mintSession(t, srv, session.Identity{Email: "applicant@gmail.com", Groups: authz.RoleGuest, Kind: session.KindGuest, Auth: now.Add(-time.Minute).Unix()}, 24*time.Hour)
	if rec := g.get("/verify", guardFor("enquiries")); rec.Code != http.StatusOK {
		t.Fatalf("guest before = %d", rec.Code)
	}
	if err := srv.store.RemoveRoleAssignment(context.Background(), "enquiries", "user", store.AssignGuests, ""); err != nil {
		t.Fatal(err)
	}
	srv.forgetRoles()
	if srv.guestsStranded(context.Background()) {
		t.Error("an assignment for an app gone before the previous start counts as stranded")
	}
	rec := g.get("/verify", guardFor("enquiries"))
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/login") || liveCount(srv, "applicant@gmail.com") != 0 {
		t.Errorf("guest after guests were taken off enquiries = %d to %q, %d live; want signed out", rec.Code, rec.Header().Get("Location"), liveCount(srv, "applicant@gmail.com"))
	}
}

// Each start records the apps its manifest declares and reports those the
// previous start declared that it does not.
func TestDeclaredAppsAreRecordedAtEachStart(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	start := func(manifest string) *Server {
		t.Helper()
		path := filepath.Join(t.TempDir(), "app-roles.tsv")
		if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
			t.Fatal(err)
		}
		srv, err := New(&config.Config{PublicURL: "https://auth.example.com", Domain: "example.com", AdminEmails: []string{"admin@example.com"},
			SessionSecret: []byte("0123456789abcdef0123456789abcdef"), AppRolesFile: path, SessionTTL: time.Hour}, st, newCaptureSender())
		if err != nil {
			t.Fatal(err)
		}
		return srv
	}
	if s := start("a\tuser\tUser\ta.{$DOMAIN}\nb\tuser\tUser\tb.{$DOMAIN}\n"); len(s.lostApps) != 0 {
		t.Errorf("first start lost %v", s.lostApps)
	}
	if s := start("a\tuser\tUser\ta.{$DOMAIN}\n"); len(s.lostApps) != 1 || !s.lostApps["b"] {
		t.Errorf("second start lost %v, want b", s.lostApps)
	}
	if s := start("a\tuser\tUser\ta.{$DOMAIN}\n"); len(s.lostApps) != 0 {
		t.Errorf("third start lost %v, want nothing", s.lostApps)
	}
}
