// Planning, checking and sending invitations, and resending or withdrawing one.

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
	actor := s.adminActor(r)
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
	actor := s.adminActor(r)
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
	ev := s.adminEvent(r, s.adminActor(r), store.AdminActionInviteWithdraw, v.App+":"+v.Role, v.Email)
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
