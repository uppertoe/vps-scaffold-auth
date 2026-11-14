package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/breakglass"
	"github.com/uppertoe/vps-scaffold-auth/internal/email"
	"github.com/uppertoe/vps-scaffold-auth/internal/otp"
	"github.com/uppertoe/vps-scaffold-auth/internal/roles"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// The Invitations pages: every invitation and its state
// (GET /admin/invitations), and the form that invites people
// (GET /admin/invitations/new), which checks the addresses before anything
// is sent. Each address receives its own invitation and its own email, with a
// link that works only for that address and expires inviteTTL after it is
// sent. Accepting one is in invite_public.go.

// inviteTTL is how long an invitation's link works after it is sent.
const inviteTTL = 14 * 24 * time.Hour

// inviteWaitNote is how long an invitation may wait before the Apps overview
// says it has not been accepted.
const inviteWaitNote = 7 * 24 * time.Hour

// maxInviteBatch bounds the addresses one form may invite, and
// maxInviteMessage the message added to each email.
const (
	maxInviteBatch   = 100
	maxInviteMessage = 500
)

// The strings of the Invitations pages, approved on 13 November 2026.
const (
	msgInviteWaiting = "The invitation to %s for %s has not been accepted after a week."
	// The check step.
	msgCheckSend        = "A personal link, sent by email"
	msgCheckWebmail     = "A personal link, sent by email. A webmail address can be invited."
	msgCheckInvalid     = "Left out, because it is not an email address."
	msgCheckWaiting     = "Left out, because an invitation to this role is already waiting for a reply."
	msgCheckHoldsDirect = "Left out, because the address already holds this role directly."
	msgCheckHoldsVia    = "Left out, because the address already holds this role through %s."
	msgCheckNobody      = "Nobody will be invited, because every address has been left out."
	// The form's refusals.
	msgInviteNoAddress   = "Nothing has been checked, because no address has been entered."
	msgInviteTooMany     = "Nothing has been checked, because more than 100 addresses have been entered. Invite them in smaller batches."
	msgInviteNoRole      = "Nothing has been checked, because no role has been chosen."
	msgInviteNoDate      = "Nothing has been checked, because the end date is missing. Enter the end date as a day, month and year."
	msgInviteDatePassed  = "Nothing has been checked, because the end date has passed."
	msgInviteLongMessage = "Nothing has been checked, because the message is longer than 500 characters."
	msgInvitesNone       = "No invitations have been sent."
)

func init() {
	// The notices for the invitation actions.
	adminNotices["invite-sent"] = "The invitation has been sent."
	adminNotices["invites-sent"] = "The invitations have been sent."
	adminNotices["invite-resent"] = "The invitation has been sent again with a new link. The earlier link no longer works."
	adminNotices["invite-withdrawn"] = "The invitation has been withdrawn. Its link no longer works."
	adminWarnings["invite-closed"] = "Nothing has been changed, because the invitation has already been accepted or withdrawn."
}

// Invitation states, as the Invitations page shows them.
const (
	inviteWaiting     = "Waiting for a reply"
	inviteUndelivered = "Not delivered"
	inviteAccepted    = "Accepted"
	inviteExpired     = "Link expired"
	inviteEnded       = "Access ended"
	inviteWithdrawn   = "Withdrawn"
)

type invitesView struct {
	Attention []attentionLine
	Rows      []inviteRow
	Empty     string
	// Confirm is the row whose Resend or Withdraw is being confirmed
	// (?resend=id or ?withdraw=id), with the confirmation's wording.
	Confirm                          int64
	ConfirmAction                    string // "resend" or "withdraw"
	ConfirmText, ConfirmButton, Keep string
}

type inviteRow struct {
	ID              int64
	Email           string
	Token           tokenView
	Access          string
	Sent, SentTitle string
	State, Tone     string
	Resend          bool
	Withdraw        bool
	SendAgain       bool
}

// inviteState is an invitation's state, with the pill's tone.
func (s *Server) inviteState(w *rolesWorld, v store.Invitation) (state, tone string) {
	now := w.now
	switch {
	case !v.WithdrawnAt.IsZero():
		return inviteWithdrawn, "tag"
	case !v.AcceptedAt.IsZero():
		if !holdsDirectly(w, v.App, v.Role, v.Email) {
			return inviteEnded, "tag"
		}
		return inviteAccepted + " " + v.AcceptedAt.In(s.tzloc()).Format("2 Jan"), "ok"
	case v.Undelivered:
		return inviteUndelivered, "off"
	case !now.Before(v.ExpiresAt):
		return inviteExpired, "tag"
	}
	return inviteWaiting, "warn"
}

// holdsDirectly reports whether a current person assignment gives email the
// role.
func holdsDirectly(w *rolesWorld, app, role, email string) bool {
	for _, a := range w.as {
		if a.App == app && a.Role == role && a.Kind == store.AssignPerson && a.Ref == email {
			return a.Until.IsZero() || w.now.Before(a.Until)
		}
	}
	return false
}

// appRoleToken is the token that names an app role: "Fellowship enquiries:
// Administrator".
func (s *Server) appRoleToken(app, role string) tokenView {
	label := app + ": " + role
	if a, ok := s.appRoles.Apps[app]; ok {
		label = a.Label + ": " + roleLabel(a, role)
	}
	return tokenView{Icon: iconApp, Label: label, Title: label}
}

// accessUntil is "Until 31 Jan 2027" or "Permanent". until is the moment the
// role ends, so the last day is the day before.
func (s *Server) accessUntil(until time.Time) string {
	if until.IsZero() {
		return "Permanent"
	}
	return "Until " + until.Add(-time.Second).In(s.tzloc()).Format("2 Jan 2006")
}

func (s *Server) handleAdminInvites(w http.ResponseWriter, r *http.Request) {
	if !s.rolesOn() {
		http.Redirect(w, r, "/admin/", http.StatusFound)
		return
	}
	world, err := s.loadRolesWorld(r.Context())
	if err != nil {
		s.adminError(w, r)
		return
	}
	v := &invitesView{Empty: msgInvitesNone, Attention: s.invitationLines(world)}
	q := r.URL.Query()
	for _, inv := range world.invites {
		state, tone := s.inviteState(world, inv)
		row := inviteRow{
			ID: inv.ID, Email: inv.Email, Token: s.appRoleToken(inv.App, inv.Role), Access: s.accessUntil(inv.Until),
			Sent: inv.SentAt.In(s.tzloc()).Format("2 Jan"), SentTitle: "Sent by " + inv.CreatedBy + ", " + s.longDate(inv.SentAt),
			State: state, Tone: tone,
		}
		switch state {
		case inviteWaiting:
			row.Resend, row.Withdraw = true, true
		case inviteUndelivered:
			row.SendAgain, row.Withdraw = true, true
		case inviteExpired:
			row.SendAgain = true
		}
		id := strconv.FormatInt(inv.ID, 10)
		switch {
		case row.Resend && q.Get("resend") == id:
			v.Confirm, v.ConfirmAction = inv.ID, "resend"
			v.ConfirmText, v.ConfirmButton, v.Keep = fmt.Sprintf(msgResendConfirm, inv.Email), msgResendButton, "Cancel"
		case row.Withdraw && q.Get("withdraw") == id:
			v.Confirm, v.ConfirmAction = inv.ID, "withdraw"
			v.ConfirmText, v.ConfirmButton, v.Keep = fmt.Sprintf(msgWithdrawConfirm, inv.Email), msgWithdrawButton, msgWithdrawKeep
		}
		v.Rows = append(v.Rows, row)
	}
	s.renderAdmin(w, r, http.StatusOK, "admin_invites", adminData{Title: "Invitations", Invites: v})
}

// openInvites are the invitations that can still be accepted.
func (w *rolesWorld) openInvites() []store.Invitation {
	var out []store.Invitation
	for _, v := range w.invites {
		if v.Open(w.now) {
			out = append(out, v)
		}
	}
	return out
}

// invitationLines are the attention lines about invitations, which the
// Apps, Invitations and Overview pages all show: each invitation that could
// not be delivered, then each that has waited a week.
func (s *Server) invitationLines(w *rolesWorld) []attentionLine {
	var out []attentionLine
	for _, v := range w.invites {
		if state, _ := s.inviteState(w, v); state == inviteUndelivered {
			out = append(out, attentionLine{Bad: true, Before: fmt.Sprintf(msgInviteUndelivered, v.Email)})
		}
	}
	return append(out, s.inviteAttention(w)...)
}

// inviteAttention is the line for each invitation that has waited a week.
func (s *Server) inviteAttention(w *rolesWorld) []attentionLine {
	var out []attentionLine
	for _, v := range w.openInvites() {
		if v.Undelivered || w.now.Sub(v.SentAt) < inviteWaitNote {
			continue
		}
		app := v.App
		if a, ok := w.m.Apps[v.App]; ok {
			app = a.Label
		}
		out = append(out, attentionLine{Before: fmt.Sprintf(msgInviteWaiting, v.Email, app)})
	}
	return out
}

// --- The form ---

// inviteForm is what the form holds, as entered.
type inviteForm struct {
	Addresses string
	Role      string // "app:role"
	Access    string // "until" or "perm"
	Until     string // yyyy-mm-dd
	Message   string
}

type newInviteView struct {
	Form    inviteForm
	Choices []inviteChoice
	Check   *inviteCheck
	Today   string
}

type inviteChoice struct {
	Value   string
	Token   tokenView
	Says    string
	Reach   reachView
	Checked bool
}

// inviteCheck is the check step.
type inviteCheck struct {
	Heading string
	Token   tokenView
	For     string // "until 31 January 2027" or "permanently"
	Rows    []checkRow
	Send    int
	Button  string
	Nobody  string
}

type checkRow struct {
	Email   string
	Says    string
	LeftOut bool
}

func (s *Server) handleAdminNewInvite(w http.ResponseWriter, r *http.Request) {
	if !s.rolesOn() {
		http.Redirect(w, r, "/admin/", http.StatusFound)
		return
	}
	f := inviteForm{Access: "until", Role: r.URL.Query().Get("role")}
	if _, _, ok := s.inviteRole(f.Role); !ok {
		f.Role = ""
	}
	s.renderInviteForm(w, r, http.StatusOK, f, nil, "")
}

// handleAdminInviteEdit is "Change the list": the form again, as it was.
func (s *Server) handleAdminInviteEdit(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	if !s.rolesOn() {
		http.Redirect(w, r, "/admin/", http.StatusFound)
		return
	}
	s.renderInviteForm(w, r, http.StatusOK, inviteFormOf(r), nil, "")
}

func inviteFormOf(r *http.Request) inviteForm {
	return inviteForm{
		Addresses: r.PostFormValue("addresses"),
		Role:      r.PostFormValue("role"),
		Access:    r.PostFormValue("access"),
		Until:     strings.TrimSpace(r.PostFormValue("until")),
		Message:   strings.TrimSpace(r.PostFormValue("message")),
	}
}

func (s *Server) renderInviteForm(w http.ResponseWriter, r *http.Request, status int, f inviteForm, check *inviteCheck, warning string) {
	world, err := s.loadRolesWorld(r.Context())
	if err != nil {
		s.adminError(w, r)
		return
	}
	v := &newInviteView{Form: f, Check: check, Today: s.now().In(s.tzloc()).Format("2006-01-02")}
	for _, a := range world.m.Sorted() {
		for _, role := range a.RoleOrder {
			val := a.Name + ":" + role
			says := "Can use the app"
			if role != roles.UserRole {
				says = "Can use the app's " + strings.ToLower(a.Roles[role]) + " pages"
			}
			v.Choices = append(v.Choices, inviteChoice{
				Value: val, Token: s.appRoleToken(a.Name, role), Says: says,
				Reach: s.roleRow(world, a, role, false, nil, nil).Reach, Checked: val == f.Role,
			})
		}
	}
	s.renderAdmin(w, r, status, "admin_invite_new", adminData{Title: "Invite people", NewInvite: v, Warning: warning})
}

// inviteRole parses "app:role" against the manifest.
func (s *Server) inviteRole(v string) (*roles.App, string, bool) {
	app, role, ok := strings.Cut(v, ":")
	if !ok || !s.appRoles.Has(app, role) {
		return nil, "", false
	}
	return s.appRoles.Apps[app], role, true
}

// splitAddresses splits pasted addresses on commas, semicolons and white
// space, lowercased, without repeats, in the order given.
func splitAddresses(raw string) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' || r == '\t'
	}) {
		e := normalizeEmail(strings.Trim(f, "<>\"'"))
		if e == "" || seen[e] {
			continue
		}
		seen[e] = true
		out = append(out, e)
	}
	return out
}

// invitePlan is a checked form: the role, the end, and each address with
// what will happen to it.
type invitePlan struct {
	app   *roles.App
	role  string
	until time.Time
	msg   string
	rows  []checkRow
	send  []string
}

// planInvites checks the form. It returns a warning, and no plan, for a form
// that cannot be checked at all.
func (s *Server) planInvites(world *rolesWorld, f inviteForm) (*invitePlan, string) {
	addrs := splitAddresses(f.Addresses)
	switch {
	case len(addrs) == 0:
		return nil, msgInviteNoAddress
	case len(addrs) > maxInviteBatch:
		return nil, msgInviteTooMany
	}
	a, role, ok := s.inviteRole(f.Role)
	if !ok {
		return nil, msgInviteNoRole
	}
	if len([]rune(f.Message)) > maxInviteMessage {
		return nil, msgInviteLongMessage
	}
	p := &invitePlan{app: a, role: role, msg: f.Message}
	if f.Access != "perm" {
		day, err := time.ParseInLocation("2006-01-02", f.Until, s.tzloc())
		if err != nil {
			return nil, msgInviteNoDate
		}
		p.until = day.AddDate(0, 0, 1)
		if !p.until.After(s.now()) {
			return nil, msgInviteDatePassed
		}
	}
	waiting := map[string]bool{}
	for _, v := range world.openInvites() {
		if v.App == a.Name && v.Role == role {
			waiting[v.Email] = true
		}
	}
	for _, e := range addrs {
		row := checkRow{Email: e, Says: msgCheckSend}
		switch {
		case !plainAddress(e):
			row.Says, row.LeftOut = msgCheckInvalid, true
		case waiting[e]:
			row.Says, row.LeftOut = msgCheckWaiting, true
		default:
			if via, holds := s.holdsRole(world, a, role, e); holds {
				row.LeftOut = true
				row.Says = msgCheckHoldsDirect
				if via != "" {
					row.Says = fmt.Sprintf(msgCheckHoldsVia, via)
				}
			} else if store.IsWebmailDomain(e[strings.LastIndexByte(e, '@')+1:]) {
				row.Says = msgCheckWebmail
			}
		}
		if !row.LeftOut {
			p.send = append(p.send, e)
		}
		p.rows = append(p.rows, row)
	}
	return p, ""
}

// holdsRole reports whether email already holds the role, and through which
// group ("" for a direct assignment). Networks and guests are left out: they
// do not name the person.
func (s *Server) holdsRole(w *rolesWorld, a *roles.App, role, email string) (via string, holds bool) {
	lists := map[string]bool{}
	if gs, err := s.store.GroupsForEmail(context.Background(), email); err == nil {
		for _, g := range gs {
			lists[g] = true
		}
	}
	sub := roles.Subject{Session: true, Email: email, Lists: lists}
	env := roles.Env{Domains: w.domains, Now: w.now}
	for _, as := range w.assigned(a.Name, role) {
		if as.Kind == store.AssignNetwork || as.Kind == store.AssignGuests {
			continue
		}
		if len(roles.Held(a.Name, sub, []store.RoleAssignment{as}, env)) == 0 {
			continue
		}
		if as.Kind == store.AssignPerson {
			return "", true
		}
		return w.groupLabel(as.Ref), true
	}
	return "", false
}

// handleAdminInviteCheck is "Check the addresses": the check step, which
// sends nothing.
func (s *Server) handleAdminInviteCheck(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	if !s.rolesOn() {
		http.Redirect(w, r, "/admin/", http.StatusFound)
		return
	}
	world, err := s.loadRolesWorld(r.Context())
	if err != nil {
		s.adminError(w, r)
		return
	}
	f := inviteFormOf(r)
	p, warning := s.planInvites(world, f)
	if warning != "" {
		s.renderInviteForm(w, r, http.StatusBadRequest, f, nil, warning)
		return
	}
	c := &inviteCheck{
		Heading: capFirst(countWords(len(p.send), "person", "people")) + " will be invited",
		Token:   s.appRoleToken(p.app.Name, p.role), For: "permanently", Rows: p.rows, Send: len(p.send),
		Button: "Send " + countWords(len(p.send), "invitation", "invitations"),
	}
	if !p.until.IsZero() {
		c.For = "until " + s.longDate(p.until.Add(-time.Second))
	}
	if len(p.send) == 0 {
		c.Nobody = msgCheckNobody
	}
	s.renderInviteForm(w, r, http.StatusOK, f, c, "")
}

// handleAdminInviteSend checks the form again and sends one invitation to
// each address the check would send to. The invitations and their records
// are saved in one transaction; the emails are then sent one after another
// on one goroutine, and an email the mailer refuses marks its invitation as
// not delivered. The other administrators are emailed once.
func (s *Server) handleAdminInviteSend(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	if !s.rolesOn() {
		http.Redirect(w, r, "/admin/", http.StatusFound)
		return
	}
	world, err := s.loadRolesWorld(r.Context())
	if err != nil {
		s.adminError(w, r)
		return
	}
	f := inviteFormOf(r)
	p, warning := s.planInvites(world, f)
	if warning != "" {
		s.renderInviteForm(w, r, http.StatusBadRequest, f, nil, warning)
		return
	}
	if len(p.send) == 0 {
		s.renderInviteForm(w, r, http.StatusOK, f, nil, msgCheckNobody)
		return
	}
	actor := s.actor(r)
	now := s.now()
	var invs []store.Invitation
	var events []store.AdminEvent
	var tokens []string
	var lines []string
	for _, e := range p.send {
		token, err := breakglass.GenerateToken()
		if err != nil {
			s.adminError(w, r)
			return
		}
		tokens = append(tokens, token)
		invs = append(invs, store.Invitation{
			Email: e, App: p.app.Name, Role: p.role, Until: p.until, Message: p.msg, TokenHash: otp.Hash(token),
			CreatedBy: actor, CreatedAt: now, SentAt: now, ExpiresAt: now.Add(inviteTTL),
		})
		detail := e
		holder := e
		if !p.until.IsZero() {
			detail += " until " + s.longDate(p.until.Add(-time.Second))
			holder += ", until " + s.longDate(p.until.Add(-time.Second))
		}
		events = append(events, s.adminEvent(r, actor, store.AdminActionInviteCreate, p.app.Name+":"+p.role, detail))
		lines = append(lines, roleLabel(p.app, p.role)+" · Invite · "+holder)
	}
	ids, err := s.store.CreateInvitations(r.Context(), invs, events)
	if err != nil {
		s.adminError(w, r)
		return
	}
	for i := range invs {
		invs[i].ID = ids[i]
	}
	s.forgetRoles()
	s.sendInvitations(invs, tokens)
	s.emailOtherAdmins(actor, fmt.Sprintf(msgChangeSubject, p.app.Label), lines)
	done := "invites-sent"
	if len(invs) == 1 {
		done = "invite-sent"
	}
	s.redirectDone(w, r, "/admin/invitations", done, "")
}

// actor is the signed-in administrator's address.
func (s *Server) actor(r *http.Request) string {
	if id, ok := s.sessions.ReadSession(r, s.now()); ok {
		return id.Email
	}
	return ""
}

func (s *Server) adminEvent(r *http.Request, actor, action, target, detail string) store.AdminEvent {
	return store.AdminEvent{
		Actor: actor, Action: action, Target: target, Detail: detail,
		ClientIP: clientIP(r), UserAgent: clampUserAgent(r.UserAgent()), CreatedAt: s.now(),
	}
}

// sendInvitations emails each invitation its link, one after another on one
// goroutine, through the notice slots. An email the mailer refuses marks its
// invitation as not delivered, which closes it; one it accepts reopens an
// invitation sent again after a failure. The log names the address and never
// the link.
func (s *Server) sendInvitations(invs []store.Invitation, tokens []string) {
	msgs := make([]inviteMail, len(invs))
	for i, v := range invs {
		msgs[i] = inviteMail{inv: v, msg: s.invitationEmail(v, tokens[i])}
	}
	s.sendNotice(fmt.Sprintf("%d invitations", len(msgs)), func(ctx context.Context) error {
		failed := 0
		for _, m := range msgs {
			if err := s.sender.Send(ctx, m.msg); err != nil {
				failed++
				log.Printf("send invitation to %s: %v", m.inv.Email, err)
				if err := s.store.MarkInvitationUndelivered(context.Background(), m.inv.ID, m.inv.TokenHash); err != nil {
					log.Printf("record undelivered invitation to %s: %v", m.inv.Email, err)
				}
				continue
			}
			if err := s.store.MarkInvitationDelivered(context.Background(), m.inv.ID, m.inv.TokenHash); err != nil {
				log.Printf("record delivered invitation to %s: %v", m.inv.Email, err)
			}
		}
		// A delivery closes or reopens an invitation, which decides whether
		// its address may sign in.
		s.forgetRoles()
		if failed > 0 {
			return fmt.Errorf("%d of %d not delivered", failed, len(msgs))
		}
		return nil
	})
}

type inviteMail struct {
	inv store.Invitation
	msg email.Message
}

// --- Resend and withdraw ---

// inviteFromPath reads the invitation the path names.
func (s *Server) inviteFromPath(w http.ResponseWriter, r *http.Request) (store.Invitation, bool) {
	if !s.checkCSRF(w, r) {
		return store.Invitation{}, false
	}
	if !s.rolesOn() {
		http.Redirect(w, r, "/admin/", http.StatusFound)
		return store.Invitation{}, false
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Redirect(w, r, "/admin/invitations", http.StatusFound)
		return store.Invitation{}, false
	}
	v, ok, err := s.store.GetInvitation(r.Context(), id)
	if err != nil {
		s.adminError(w, r)
		return store.Invitation{}, false
	}
	if !ok {
		http.Redirect(w, r, "/admin/invitations", http.StatusFound)
		return store.Invitation{}, false
	}
	return v, true
}

// back returns to the page the form came from: an app's page, or the
// Invitations page.
func inviteBack(r *http.Request) string {
	if app := r.PostFormValue("from_app"); app != "" && authzSafeName(app) {
		return "/admin/apps/" + url.PathEscape(app)
	}
	return "/admin/invitations"
}

// authzSafeName accepts an app name as the manifest writes it.
func authzSafeName(s string) bool {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return s != ""
}

// handleAdminInviteResend is Resend and Send again: a new link and a new
// fortnight. The old link stops working at once.
func (s *Server) handleAdminInviteResend(w http.ResponseWriter, r *http.Request) {
	v, ok := s.inviteFromPath(w, r)
	if !ok {
		return
	}
	token, err := breakglass.GenerateToken()
	if err != nil {
		s.adminError(w, r)
		return
	}
	now := s.now()
	actor := s.actor(r)
	ev := s.adminEvent(r, actor, store.AdminActionInviteResend, v.App+":"+v.Role, v.Email)
	if err := s.store.ResendInvitation(r.Context(), v.ID, otp.Hash(token), now, now.Add(inviteTTL), ev); err != nil {
		if errors.Is(err, store.ErrInvitationClosed) {
			s.redirectDone(w, r, inviteBack(r), "invite-closed", "")
			return
		}
		s.adminError(w, r)
		return
	}
	v.TokenHash, v.SentAt, v.ExpiresAt = otp.Hash(token), now, now.Add(inviteTTL)
	s.forgetRoles()
	s.sendInvitations([]store.Invitation{v}, []string{token})
	s.redirectDone(w, r, inviteBack(r), "invite-resent", "")
}

func (s *Server) handleAdminInviteWithdraw(w http.ResponseWriter, r *http.Request) {
	v, ok := s.inviteFromPath(w, r)
	if !ok {
		return
	}
	ev := s.adminEvent(r, s.actor(r), store.AdminActionInviteWithdraw, v.App+":"+v.Role, v.Email)
	if err := s.store.WithdrawInvitation(r.Context(), v.ID, s.now(), ev); err != nil {
		if errors.Is(err, store.ErrInvitationClosed) {
			s.redirectDone(w, r, inviteBack(r), "invite-closed", "")
			return
		}
		s.adminError(w, r)
		return
	}
	s.forgetRoles()
	s.redirectDone(w, r, inviteBack(r), "invite-withdrawn", "")
}

// invitedRows are an app's open invitations as rows of its people table.
func (s *Server) invitedRows(w *rolesWorld, a *roles.App) []personRow {
	var out []personRow
	for _, v := range w.openInvites() {
		if v.App != a.Name {
			continue
		}
		p := personRow{Email: v.Email, Role: v.Role, RoleLabel: roleLabel(a, v.Role), Until: "No end date", NoEnd: v.Until.IsZero(), InviteID: v.ID,
			How: "Invited " + s.longDate(v.SentAt) + ", not yet accepted"}
		if !v.Until.IsZero() {
			p.Until = s.longDate(v.Until.Add(-time.Second))
		}
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out
}
