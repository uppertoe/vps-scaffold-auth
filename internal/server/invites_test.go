package server

import (
	"context"
	"errors"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/email"
	"github.com/uppertoe/vps-scaffold-auth/internal/otp"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// mailLog records every message the server sends, and passes code emails on
// to the captureSender so the sign-in helpers still work. fail refuses the
// messages to one address.
type mailLog struct {
	mu   sync.Mutex
	all  []email.Message
	next email.Sender
	fail string
}

func (m *mailLog) Send(ctx context.Context, msg email.Message) error {
	m.mu.Lock()
	m.all = append(m.all, msg)
	fail := m.fail
	m.mu.Unlock()
	if fail != "" && msg.To == fail {
		return errors.New("mailbox unavailable")
	}
	if msg.OTPCode != "" {
		return m.next.Send(ctx, msg)
	}
	return nil
}

// waitFor returns the messages matching keep once there are want of them,
// waiting up to a second, then a moment longer for any extra.
func (m *mailLog) waitFor(want int, keep func(email.Message) bool) []email.Message {
	get := func() []email.Message {
		m.mu.Lock()
		defer m.mu.Unlock()
		var out []email.Message
		for _, msg := range m.all {
			if keep(msg) {
				out = append(out, msg)
			}
		}
		return out
	}
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if len(get()) >= want && want > 0 {
			break
		}
	}
	time.Sleep(50 * time.Millisecond)
	return get()
}

func invitationsTo(addr string) func(email.Message) bool {
	return func(m email.Message) bool { return m.To == addr && strings.HasPrefix(m.Subject, "An invitation to ") }
}

var reInviteLink = regexp.MustCompile(`https://auth\.example\.com(/invite/[A-Za-z0-9_-]+)`)

func inviteLinkIn(t *testing.T, m email.Message) string {
	t.Helper()
	got := reInviteLink.FindStringSubmatch(m.Text)
	if got == nil {
		t.Fatalf("no invitation link in %q", m.Text)
	}
	return got[1]
}

// inviteAdmin is appsAdmin with every message recorded.
func inviteAdmin(t *testing.T) (*Server, *captureSender, *mailLog, *client) {
	t.Helper()
	srv, sender, c := appsAdmin(t)
	ml := &mailLog{next: sender}
	srv.sender = ml
	return srv, sender, ml, c
}

// invite fills the form, checks it and sends it, returning the check page.
func invite(t *testing.T, c *client, form url.Values) string {
	t.Helper()
	form.Set("csrf", csrfOf(t, c, "/admin/invitations/new"))
	rec := c.postForm("/admin/invitations/check", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("check = %d: %s", rec.Code, rec.Body.String())
	}
	check := html.UnescapeString(rec.Body.String())
	if rec := c.postForm("/admin/invitations", form); rec.Code != http.StatusFound {
		t.Fatalf("send = %d: %s", rec.Code, html.UnescapeString(rec.Body.String()))
	}
	return check
}

func adminInviteForm(addrs string) url.Values {
	return url.Values{"addresses": {addrs}, "role": {"enquiries:admin"}, "access": {"until"}, "until": {"2099-01-31"}, "message": {"Hi Kim, this is for the 2027 fellowship round."}}
}

func TestInvitationAcceptedByLinkAndCode(t *testing.T) {
	srv, sender, ml, c := inviteAdmin(t)
	invite(t, c, adminInviteForm("k.lee@monash.org"))

	mail := ml.waitFor(1, invitationsTo("k.lee@monash.org"))
	if len(mail) != 1 {
		t.Fatalf("invitation emails = %d, want 1", len(mail))
	}
	m := mail[0]
	for _, want := range []string{
		"admin@example.com has invited you to use Fellowship enquiries as an administrator. Your access lasts until 31 January 2099.",
		"Hi Kim, this is for the 2027 fellowship round.",
		"To accept, open the link below. We will then send a code to this address to confirm it.",
		"The link works only for k.lee@monash.org and expires on ",
	} {
		if !strings.Contains(m.Text, want) {
			t.Errorf("invitation email lacks %q:\n%s", want, m.Text)
		}
	}
	if m.Subject != "An invitation to Fellowship enquiries" || !strings.Contains(m.HTML, "Accept the invitation") {
		t.Errorf("subject %q or button missing", m.Subject)
	}
	link := inviteLinkIn(t, m)
	token := strings.TrimPrefix(link, "/invite/")

	// Only a hash of the token is stored.
	invs, _ := srv.store.ListInvitations(context.Background())
	if len(invs) != 1 || invs[0].TokenHash != otp.Hash(token) || strings.Contains(invs[0].TokenHash, token) {
		t.Fatalf("stored invitation = %+v", invs)
	}
	// The other administrator is emailed once, about the batch.
	others := ml.waitFor(1, func(m email.Message) bool { return m.To == "boss@example.com" })
	if len(others) != 1 || !strings.Contains(others[0].Text, "Administrator · Invite · k.lee@monash.org, until 31 January 2099") {
		t.Errorf("admin emails = %+v", others)
	}
	// The app page lists the invitation, without the role.
	page := html.UnescapeString(c.get("/admin/apps/enquiries", nil).Body.String())
	if !strings.Contains(page, "Invited ") || !strings.Contains(page, ", not yet accepted") || !strings.Contains(page, "31 January 2099") {
		t.Error("the app page does not list the invitation")
	}
	if as, _ := srv.store.ListRoleAssignments(context.Background(), "enquiries"); len(as) != 0 {
		t.Fatalf("an unaccepted invitation gave the role: %+v", as)
	}

	// The invited person opens the link, sends the code and enters it.
	p := newClient(t, srv.Handler())
	body := html.UnescapeString(p.get(link, nil).Body.String())
	for _, want := range []string{"Accept your invitation", "Fellowship enquiries", "As an administrator, until 31 January 2099", "We will send a code to k.lee@monash.org to confirm the address.", "Send the code"} {
		if !strings.Contains(body, want) {
			t.Errorf("link page lacks %q", want)
		}
	}
	sender.reset()
	if rec := p.postForm("/invite/send", url.Values{"token": {token}}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Check your email") {
		t.Fatalf("send the code = %d", rec.Code)
	}
	code := sender.code()
	if code == "" {
		t.Fatal("no code was sent to the invited address")
	}
	rec := p.postForm("/verify-code", url.Values{"code": {code}})
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/invite/done?i=") {
		t.Fatalf("verify-code = %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	if p.cookies[session.SessionCookie] == nil {
		t.Fatal("no session after accepting")
	}
	done := html.UnescapeString(p.get(rec.Header().Get("Location"), nil).Body.String())
	if !strings.Contains(done, "Your invitation has been accepted") || !strings.Contains(done, "Open Fellowship enquiries") {
		t.Errorf("done page:\n%s", done)
	}
	as, _ := srv.store.ListRoleAssignments(context.Background(), "enquiries")
	if len(as) != 1 || as[0].Ref != "k.lee@monash.org" || as[0].Role != "admin" || as[0].How != store.AssignedByInvite || as[0].CreatedBy != "admin@example.com" {
		t.Fatalf("assignment = %+v", as)
	}
	// The new session reaches the administrator role.
	if rec := p.get("/verify", withHost(roleGuard("enquiries", "admin"), "enquiries.example.com")); rec.Code != http.StatusOK {
		t.Errorf("verify as the invited administrator = %d", rec.Code)
	}
	page = html.UnescapeString(c.get("/admin/apps/enquiries", nil).Body.String())
	if !strings.Contains(page, "Accepted an invitation, ") {
		t.Error("the app page does not say the role came from an invitation")
	}
	if list := html.UnescapeString(c.get("/admin/invitations", nil).Body.String()); !strings.Contains(list, ">Accepted ") {
		t.Error("the Invitations page does not show the acceptance")
	}
	// The link now says it has been accepted, to someone else too.
	if again := html.UnescapeString(newClient(t, srv.Handler()).get(link, nil).Body.String()); !strings.Contains(again, msgInviteUsedTitle) {
		t.Errorf("an accepted link shows:\n%s", again)
	}
	events, _ := srv.store.ListAdminEvents(context.Background(), 20, 0)
	seen := map[string]bool{}
	for _, e := range events {
		seen[e.Action] = true
	}
	if !seen[store.AdminActionInviteCreate] || !seen[store.AdminActionInviteAccept] {
		t.Errorf("admin log = %+v", events)
	}
}

func withHost(h map[string]string, host string) map[string]string {
	h["X-Forwarded-Host"] = host
	return h
}

func TestOpenInvitationMaySignInWithoutAccepting(t *testing.T) {
	srv, sender, _, c := inviteAdmin(t)
	// Before the invitation, the address is not sent a code.
	sender.reset()
	newClient(t, srv.Handler()).postForm("/request", url.Values{"email": {"k.lee@monash.org"}})
	if code := sender.code(); code != "" {
		t.Fatal("an address with no role was sent a code")
	}
	invite(t, c, adminInviteForm("k.lee@monash.org"))
	p := newClient(t, srv.Handler())
	loginAs(t, p, sender, "k.lee@monash.org", nil)
	if as, _ := srv.store.ListRoleAssignments(context.Background(), "enquiries"); len(as) != 0 {
		t.Fatalf("signing in accepted the invitation: %+v", as)
	}
	if rec := p.get("/verify", withHost(roleGuard("enquiries", "admin"), "enquiries.example.com")); rec.Code == http.StatusOK {
		t.Error("an unaccepted invitation admitted the person")
	}
}

func TestInvitationLinkWrongAddress(t *testing.T) {
	srv, sender, ml, c := inviteAdmin(t)
	invite(t, c, adminInviteForm("k.lee@monash.org"))
	link := inviteLinkIn(t, ml.waitFor(1, invitationsTo("k.lee@monash.org"))[0])
	other := newClient(t, srv.Handler())
	loginAs(t, other, sender, "user@example.com", nil)
	body := html.UnescapeString(other.get(link, nil).Body.String())
	if !strings.Contains(body, "This invitation is for k.lee@monash.org, and you are signed in as user@example.com.") || strings.Contains(body, "Send the code") {
		t.Errorf("wrong-address page:\n%s", body)
	}
	// A code step started as another address cannot accept it either.
	if _, err := srv.store.AcceptInvitation(context.Background(), 1, "user@example.com", srv.now(), store.AdminEvent{CreatedAt: srv.now()}); !errors.Is(err, store.ErrInvitationClosed) {
		t.Errorf("accept as another address: %v", err)
	}
}

func TestResendAndWithdrawEndTheOldLink(t *testing.T) {
	srv, _, ml, c := inviteAdmin(t)
	invite(t, c, adminInviteForm("k.lee@monash.org"))
	old := inviteLinkIn(t, ml.waitFor(1, invitationsTo("k.lee@monash.org"))[0])

	rec := c.postForm("/admin/invitations/1/resend", url.Values{"csrf": {csrfOf(t, c, "/admin/invitations/new")}})
	if rec.Code != http.StatusFound {
		t.Fatalf("resend = %d", rec.Code)
	}
	mail := ml.waitFor(2, invitationsTo("k.lee@monash.org"))
	if len(mail) != 2 {
		t.Fatalf("emails after resend = %d", len(mail))
	}
	fresh := inviteLinkIn(t, mail[1])
	p := newClient(t, srv.Handler())
	if body := html.UnescapeString(p.get(old, nil).Body.String()); !strings.Contains(body, msgInviteBadTitle) {
		t.Error("the old link still works after a resend")
	}
	if rec := p.postForm("/invite/send", url.Values{"token": {strings.TrimPrefix(old, "/invite/")}}); strings.Contains(rec.Body.String(), "Check your email") {
		t.Error("the old link still sends a code")
	}
	if body := p.get(fresh, nil).Body.String(); !strings.Contains(body, "Send the code") {
		t.Error("the new link does not work")
	}

	rec = c.postForm("/admin/invitations/1/withdraw", url.Values{"csrf": {csrfOf(t, c, "/admin/invitations/new")}})
	if rec.Code != http.StatusFound {
		t.Fatalf("withdraw = %d", rec.Code)
	}
	if body := html.UnescapeString(p.get(fresh, nil).Body.String()); !strings.Contains(body, "This invitation has been withdrawn") {
		t.Errorf("withdrawn link shows:\n%s", body)
	}
	if rec := p.postForm("/invite/send", url.Values{"token": {strings.TrimPrefix(fresh, "/invite/")}}); strings.Contains(rec.Body.String(), "Check your email") {
		t.Error("a withdrawn invitation still sends a code")
	}
	if list := c.get("/admin/invitations", nil).Body.String(); !strings.Contains(list, ">Withdrawn<") {
		t.Error("the list does not show the withdrawal")
	}
	// Withdrawing again changes nothing.
	c.postForm("/admin/invitations/1/withdraw", url.Values{"csrf": {csrfOf(t, c, "/admin/invitations/new")}})
	if body := html.UnescapeString(c.get("/admin/invitations", nil).Body.String()); !strings.Contains(body, adminWarnings["invite-closed"]) {
		t.Error("a second withdrawal was not refused")
	}
	// Signing in is no longer allowed once the invitation is withdrawn.
	if srv.mayHoldRoleNow(context.Background(), "k.lee@monash.org") {
		t.Error("a withdrawn invitation still lets the address sign in")
	}
}

func TestExpiredInvitation(t *testing.T) {
	srv, _, ml, c := inviteAdmin(t)
	invite(t, c, adminInviteForm("k.lee@monash.org"))
	link := inviteLinkIn(t, ml.waitFor(1, invitationsTo("k.lee@monash.org"))[0])
	start := time.Now()
	srv.now = func() time.Time { return start.Add(15 * 24 * time.Hour) }
	srv.forgetRoles()
	body := html.UnescapeString(newClient(t, srv.Handler()).get(link, nil).Body.String())
	if !strings.Contains(body, "This invitation has expired") || !strings.Contains(body, "If you still need access, you can ask admin@example.com to send a new invitation.") {
		t.Errorf("expired page:\n%s", body)
	}
	if srv.mayHoldRoleNow(context.Background(), "k.lee@monash.org") {
		t.Error("an expired invitation still lets the address sign in")
	}
	srv.now = time.Now
	inv, _, _ := srv.store.GetInvitation(context.Background(), 1)
	w := &rolesWorld{now: start.Add(15 * 24 * time.Hour)}
	if state, _ := srv.inviteState(w, inv); state != inviteExpired {
		t.Errorf("state = %q", state)
	}
}

func TestInvitationCheckStep(t *testing.T) {
	srv, _, ml, c := inviteAdmin(t)
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "admin", Kind: store.AssignPerson, Ref: "has@monash.org", How: store.AssignedByAdmin})
	mustDomainGroup(t, srv, "staff", "example.com")
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "admin", Kind: store.AssignDomainGroup, Ref: "staff"})
	invite(t, c, adminInviteForm("waiting@monash.org"))
	ml.waitFor(1, invitationsTo("waiting@monash.org"))

	form := adminInviteForm("new@monash.org, someone@gmail.com\nnot-an-address; has@monash.org staff@example.com waiting@monash.org new@monash.org")
	form.Set("csrf", csrfOf(t, c, "/admin/invitations/new"))
	page := html.UnescapeString(c.postForm("/admin/invitations/check", form).Body.String())
	for _, want := range []string{
		"Check the invitations", "Nothing has been sent yet.", "Two people will be invited", "until 31 January 2099",
		msgCheckSend, msgCheckWebmail, msgCheckInvalid, msgCheckHoldsDirect,
		"Left out, because the address already holds this role through staff.", msgCheckWaiting,
		"Send two invitations", "Change the list",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("check step lacks %q", want)
		}
	}
	if n := strings.Count(page, ">new@monash.org<"); n != 1 {
		t.Errorf("a repeated address is listed %d times", n)
	}
	if rec := c.postForm("/admin/invitations", form); rec.Code != http.StatusFound {
		t.Fatalf("send = %d", rec.Code)
	}
	invs, _ := srv.store.ListInvitations(context.Background())
	got := map[string]bool{}
	for _, v := range invs {
		got[v.Email] = true
	}
	if len(invs) != 3 || !got["new@monash.org"] || !got["someone@gmail.com"] {
		t.Errorf("invitations = %v", got)
	}
	// A form with a past date or no role is refused before any check.
	bad := adminInviteForm("x@monash.org")
	bad.Set("until", "2001-01-01")
	bad.Set("csrf", csrfOf(t, c, "/admin/invitations/new"))
	if body := html.UnescapeString(c.postForm("/admin/invitations/check", bad).Body.String()); !strings.Contains(body, msgInviteDatePassed) {
		t.Error("a past end date was not refused")
	}
	bad.Set("role", "enquiries:owner")
	if body := html.UnescapeString(c.postForm("/admin/invitations/check", bad).Body.String()); !strings.Contains(body, msgInviteNoRole) {
		t.Error("an undeclared role was not refused")
	}
}

func TestUndeliveredInvitation(t *testing.T) {
	_, _, ml, c := inviteAdmin(t)
	ml.fail = "bounce@monash.org"
	invite(t, c, adminInviteForm("bounce@monash.org"))
	ml.waitFor(1, invitationsTo("bounce@monash.org"))
	time.Sleep(50 * time.Millisecond)
	body := html.UnescapeString(c.get("/admin/invitations", nil).Body.String())
	if !strings.Contains(body, ">Not delivered<") || !strings.Contains(body, "The invitation to bounce@monash.org could not be delivered. Check the address, then withdraw it and invite again.") {
		t.Errorf("Invitations page:\n%s", body)
	}
	if strings.Contains(body, ">Resend<") {
		t.Error("an undelivered invitation offers Resend")
	}
}

func TestInvitationWaitingAWeek(t *testing.T) {
	srv, _, _, c := inviteAdmin(t)
	sent := time.Now().Add(-8 * 24 * time.Hour)
	if _, err := srv.store.CreateInvitations(context.Background(), []store.Invitation{{
		Email: "k.lee@monash.org", App: "enquiries", Role: "admin", TokenHash: "h", CreatedBy: "admin@example.com",
		CreatedAt: sent, SentAt: sent, ExpiresAt: sent.Add(inviteTTL),
	}}, nil); err != nil {
		t.Fatal(err)
	}
	srv.forgetRoles()
	body := html.UnescapeString(c.get("/admin/apps", nil).Body.String())
	if !strings.Contains(body, "The invitation to k.lee@monash.org for Fellowship enquiries has not been accepted after a week.") {
		t.Error("the overview does not name the invitation waiting a week")
	}
	if !strings.Contains(html.UnescapeString(c.get("/admin/apps?address=k.lee%40monash.org", nil).Body.String()),
		"k.lee@monash.org holds no role yet. An invitation to Fellowship enquiries: Administrator has not been accepted.") {
		t.Error("the address check does not mention the invitation")
	}
}

func TestRemindersSentOnce(t *testing.T) {
	srv, _, ml, _ := inviteAdmin(t)
	now := time.Now()
	srv.now = func() time.Time { return now }
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "admin", Kind: store.AssignPerson, Ref: "p@monash.org", How: store.AssignedByAdmin, CreatedBy: "boss@example.com", Until: now.Add(5 * 24 * time.Hour)})
	mustAssign(t, srv, store.RoleAssignment{App: "enquiries", Role: "user", Kind: store.AssignPerson, Ref: "later@monash.org", How: store.AssignedByAdmin, CreatedBy: "boss@example.com", Until: now.Add(30 * 24 * time.Hour)})
	srv.sendReminders(context.Background())
	srv.sendReminders(context.Background())
	mail := ml.waitFor(2, func(m email.Message) bool { return strings.Contains(m.Subject, " ends on ") })
	if len(mail) != 2 {
		t.Fatalf("reminders = %d, want 2: %+v", len(mail), mail)
	}
	ends := srv.longDate(now.Add(5*24*time.Hour - time.Second))
	for _, m := range mail {
		switch m.To {
		case "p@monash.org":
			if m.Subject != "Your access to Fellowship enquiries ends on "+ends+"." || !strings.Contains(m.Text, "you can ask boss@example.com to extend it") {
				t.Errorf("person's reminder = %+v", m)
			}
		case "boss@example.com":
			if m.Subject != "Access for p@monash.org ends on "+ends+"." || !strings.Contains(m.Text, "p@monash.org holds Administrator in Fellowship enquiries until "+ends+".") {
				t.Errorf("admin's reminder = %+v", m)
			}
		default:
			t.Errorf("reminder to %s", m.To)
		}
	}
}
