package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

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
