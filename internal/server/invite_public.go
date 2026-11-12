package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/email"
	"github.com/uppertoe/vps-scaffold-auth/internal/otp"
	"github.com/uppertoe/vps-scaffold-auth/internal/roles"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// The invitation's own pages, on the auth host. The link in the email opens
// GET /invite/{token}, which grants nothing: like a card's scan page, it is
// safe for a mail scanner to fetch. Its button posts the token to
// /invite/send, which sends a sign-in code to the invited address through the
// same limits as /request and starts the code step with the invitation named
// in the signed state cookie, on the invitation's own code page. Its "Send a
// new code" posts the token to /invite/send again. /verify-code then accepts
// the invitation and signs the person in, and /invite/done shows the result.

// The strings of the invitation's pages and email. Those marked DRAFT are not
// yet approved.
const (
	msgInviteSubject    = "An invitation to %s"
	msgInviteBody       = "%s has invited you %s."
	msgInviteLasts      = "Your access lasts until %s."
	msgInviteHow        = "To accept, open the link below. We will then send a code to this address to confirm it."
	msgInviteButton     = "Accept the invitation"
	msgInviteFooter     = "The link works only for %s and expires on %s."
	msgInviteOpenTitle  = "Accept your invitation"
	msgInviteOpenBody   = "We will send a code to %s to confirm the address."
	msgInviteSendCode   = "Send the code"
	msgInviteDoneTitle  = "Your invitation has been accepted"
	msgInviteOpenApp    = "Open %s"
	msgInviteExpTitle   = "This invitation has expired"
	msgInviteExpBody    = "The invitation for %s expired on %s."
	msgInviteAskAgain   = "If you still need access, you can ask %s to send a new invitation."
	msgInviteUsedTitle  = "This invitation has already been accepted"                                                  // DRAFT
	msgInviteUsedBody   = "The invitation for %s was accepted on %s."                                                  // DRAFT
	msgInviteUsedNext   = "If this is your invitation, you can open %s and sign in with %s."                           // DRAFT
	msgInviteGoneTitle  = "This invitation has been withdrawn"                                                         // DRAFT
	msgInviteGoneBody   = "The invitation for %s was withdrawn on %s."                                                 // DRAFT
	msgInviteOtherTitle = "You are signed in with a different address"                                                 // DRAFT
	msgInviteOtherBody  = "This invitation is for %s, and you are signed in as %s."                                    // DRAFT
	msgInviteOtherNext  = "To accept the invitation, sign out, then open the link in the email again."                 // DRAFT
	msgInviteSignOut    = "Sign out"                                                                                   // DRAFT
	msgInviteBadTitle   = "We do not recognise this invitation link"                                                   // DRAFT
	msgInviteBadBody    = "If the invitation was sent again, only the link in the newest email works."                 // DRAFT
	msgInviteBadNext    = "If you still need access, you can ask the person who invited you to send a new invitation." // DRAFT
)

// inviteDonePath is where the code step of an invitation lands.
const inviteDonePath = "/invite/done?i="

// invitePage is the view of an invitation's page.
type invitePage struct {
	Heading  string
	App      string // the box's first line; empty for no box
	Access   string // the box's second line
	Lines    []string
	Token    string // set on the page that sends the code
	Button   string
	Href     string // a link button, such as Open {app}
	SignOut  bool
	SendCode string
	// The code page: the form that posts the code to /verify-code (CodeForm,
	// left out once the code step has ended), and the line and button that
	// send a new code (when Token is set).
	Code       bool
	CodeForm   bool
	CodeButton string
	Redirect   string
	Error      string
	Late       string
	NewCode    string
}

// inviteRoleWords is how the invitation says what it gives: "to use
// Fellowship enquiries as an administrator", or "to use Narrator" for the
// user role.
func inviteRoleWords(a *roles.App, role string) string {
	if role == roles.UserRole {
		return "to use " + a.Label
	}
	return "to use " + a.Label + " " + roleAs(roleLabel(a, role))
}

// roleAs is "as an administrator".
func roleAs(label string) string {
	l := strings.ToLower(label)
	art := "a "
	if l != "" && strings.ContainsRune("aeiou", rune(l[0])) {
		art = "an "
	}
	return "as " + art + l
}

// inviteBoxLine is the box's second line: "As an administrator, until 31
// January 2027", "To use Narrator", and so on.
func (s *Server) inviteBoxLine(a *roles.App, v store.Invitation) string {
	line := roleAs(roleLabel(a, v.Role))
	if v.Role == roles.UserRole {
		line = "to use " + a.Label
	}
	if !v.Until.IsZero() {
		line += ", until " + s.longDate(v.Until.Add(-time.Second))
	}
	return capFirst(line)
}

// appURL is the address an app is opened at.
func appURL(a *roles.App) string {
	if len(a.Hosts) == 0 {
		return ""
	}
	return "https://" + a.Hosts[0] + "/"
}

// inviteMailTmpl is the invitation email's HTML. html/template escapes every
// value, the inviter's message included.
var inviteMailTmpl = template.Must(template.New("invite").Parse(`<!DOCTYPE html><html><body style="margin:0;padding:24px;background:#f4f5f7;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1b1f24">
<div style="max-width:480px;margin:0 auto;background:#fff;border:1px solid #e2e5e9;border-radius:12px;padding:24px">
<p style="margin:0 0 14px;font-size:15px;line-height:1.5">{{.Body}}</p>
{{if .Message}}<p style="margin:0 0 14px;padding:10px 12px;border-left:3px solid {{.Accent}};background:#f9fafb;font-size:15px;line-height:1.5;white-space:pre-wrap">{{.Message}}</p>{{end}}
<p style="margin:0 0 18px;font-size:15px;line-height:1.5">{{.How}}</p>
<p style="margin:0 0 18px"><a href="{{.Link}}" style="display:inline-block;background:{{.Accent}};color:#fff;text-decoration:none;font-weight:600;padding:12px 18px;border-radius:10px">{{.Button}}</a></p>
<p style="margin:0;font-size:13px;line-height:1.5;color:#5f6670">{{.Footer}}</p>
</div></body></html>`))

// invitationEmail builds one invitation's email. The link carries the token,
// which is never stored or logged.
func (s *Server) invitationEmail(v store.Invitation, token string) email.Message {
	a, ok := s.appRoles.Apps[v.App]
	if !ok {
		a = &roles.App{Name: v.App, Label: v.App, Roles: map[string]string{}}
	}
	body := fmt.Sprintf(msgInviteBody, v.CreatedBy, inviteRoleWords(a, v.Role))
	if !v.Until.IsZero() {
		body += " " + fmt.Sprintf(msgInviteLasts, s.longDate(v.Until.Add(-time.Second)))
	}
	link := s.cfg.PublicURL + "/invite/" + token
	footer := fmt.Sprintf(msgInviteFooter, v.Email, s.longDate(v.ExpiresAt))
	accent := "#2563eb"
	if b, err := s.publicBranding(context.Background()); err == nil {
		accent = hexOrDefault(b.accentColor, accent)
	}
	var buf bytes.Buffer
	if err := inviteMailTmpl.Execute(&buf, map[string]string{
		"Body": body, "Message": v.Message, "How": msgInviteHow, "Link": link,
		"Button": msgInviteButton, "Footer": footer, "Accent": accent,
	}); err != nil {
		log.Printf("render invitation email: %v", err)
	}
	var text strings.Builder
	text.WriteString(body + "\n\n")
	if v.Message != "" {
		text.WriteString(v.Message + "\n\n")
	}
	text.WriteString(msgInviteHow + "\n\n" + link + "\n\n" + footer + "\n")
	return email.Message{To: v.Email, Subject: fmt.Sprintf(msgInviteSubject, a.Label), Text: text.String(), HTML: buf.String()}
}

// inviteByToken finds the invitation a link names.
func (s *Server) inviteByToken(ctx context.Context, token string) (store.Invitation, bool, error) {
	if token == "" || len(token) > 64 {
		return store.Invitation{}, false, nil
	}
	return s.store.InvitationByTokenHash(ctx, otp.Hash(token))
}

func (s *Server) renderInvite(w http.ResponseWriter, status int, p *invitePage) {
	s.render(w, status, "invite", pageData{Title: p.Heading, Invite: p})
}

// handleInviteLink is the page the email's link opens. It shows the
// invitation's state and, while it is open, a button that sends the code.
func (s *Server) handleInviteLink(w http.ResponseWriter, r *http.Request) {
	if !s.inviteLimiter.Allow(clientIP(r)) {
		s.render(w, http.StatusTooManyRequests, "message", pageData{Title: "Too many requests", Message: "Please wait a little while and try again."})
		return
	}
	token := r.PathValue("token")
	v, ok, err := s.inviteByToken(r.Context(), token)
	if err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong"})
		return
	}
	a, known := s.appRoles.Apps[v.App]
	if !ok || !known {
		s.renderInvite(w, http.StatusNotFound, badInvitePage())
		return
	}
	now := s.now()
	if v.Open(now) {
		if id, signed := s.readSession(r, now); signed && id.Kind != session.KindBreakGlass && id.Email != v.Email {
			s.renderInvite(w, http.StatusOK, &invitePage{
				Heading: msgInviteOtherTitle,
				Lines:   []string{fmt.Sprintf(msgInviteOtherBody, v.Email, id.Email), msgInviteOtherNext},
				SignOut: true, Button: msgInviteSignOut,
			})
			return
		}
		s.renderInvite(w, http.StatusOK, &invitePage{
			Heading: msgInviteOpenTitle, App: a.Label, Access: s.inviteBoxLine(a, v),
			Lines: []string{fmt.Sprintf(msgInviteOpenBody, v.Email)}, Token: token, SendCode: msgInviteSendCode,
		})
		return
	}
	s.renderInvite(w, http.StatusOK, s.closedInvitePage(r, a, v))
}

// closedInvitePage is the page of an invitation that can no longer be
// accepted: accepted, withdrawn, not delivered or expired. A link whose email
// was not delivered shows the page of a link that is not recognised.
func (s *Server) closedInvitePage(r *http.Request, a *roles.App, v store.Invitation) *invitePage {
	switch {
	case !v.AcceptedAt.IsZero():
		if id, ok := s.readSession(r, s.now()); ok && id.Email == v.Email && id.Kind == "" {
			return &invitePage{Heading: msgInviteDoneTitle, App: a.Label, Access: s.inviteBoxLine(a, v),
				Href: appURL(a), Button: fmt.Sprintf(msgInviteOpenApp, a.Label)}
		}
		return &invitePage{Heading: msgInviteUsedTitle, Lines: []string{
			fmt.Sprintf(msgInviteUsedBody, v.Email, s.longDate(v.AcceptedAt)),
			fmt.Sprintf(msgInviteUsedNext, a.Label, v.Email),
		}, Href: appURL(a), Button: fmt.Sprintf(msgInviteOpenApp, a.Label)}
	case !v.WithdrawnAt.IsZero():
		return &invitePage{Heading: msgInviteGoneTitle, Lines: []string{
			fmt.Sprintf(msgInviteGoneBody, v.Email, s.longDate(v.WithdrawnAt)),
			fmt.Sprintf(msgInviteAskAgain, v.CreatedBy),
		}}
	case v.Undelivered:
		return badInvitePage()
	}
	return &invitePage{Heading: msgInviteExpTitle, Lines: []string{
		fmt.Sprintf(msgInviteExpBody, v.Email, s.longDate(v.ExpiresAt)),
		fmt.Sprintf(msgInviteAskAgain, v.CreatedBy),
	}}
}

// badInvitePage is the page of a link that is not recognised.
func badInvitePage() *invitePage {
	return &invitePage{Heading: msgInviteBadTitle, Lines: []string{msgInviteBadBody, msgInviteBadNext}}
}

// handleInviteSend is "Send the code". It is a sign-in form like /request:
// same-origin only, limited per client IP, and the code goes through the
// same cooldown and send limits. The state cookie names the invitation, so
// the code step accepts it.
func (s *Server) handleInviteSend(w http.ResponseWriter, r *http.Request) {
	if !s.requireSameOrigin(w, r) {
		return
	}
	now := s.now()
	if !s.ipLimiter.Allow(clientIP(r)) {
		s.render(w, http.StatusTooManyRequests, "message", pageData{Title: "Too many requests", Message: "Please wait a little while and try again."})
		return
	}
	v, ok, err := s.inviteByToken(r.Context(), r.PostFormValue("token"))
	if err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong"})
		return
	}
	a, known := s.appRoles.Apps[v.App]
	if !ok || !known {
		s.renderInvite(w, http.StatusNotFound, badInvitePage())
		return
	}
	if !v.Open(now) {
		s.renderInvite(w, http.StatusOK, s.closedInvitePage(r, a, v))
		return
	}
	if err := s.store.DeleteExpiredCodes(r.Context(), now); err != nil {
		log.Printf("prune expired codes: %v", err)
	}
	// The address is permitted while the invitation is open (see
	// mayHoldRoleNow), so this sends a real code under the usual limits.
	s.issueCode(r, v.Email, true, now)
	rd := s.cfg.PublicURL + inviteDonePath + strconv.FormatInt(v.ID, 10)
	if err := s.sessions.SetState(w, session.State{Email: v.Email, Redirect: rd, Invite: v.ID}, s.cfg.OTPTTL, now); err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong"})
		return
	}
	s.renderInvite(w, http.StatusOK, s.inviteCodePage(a, v, r.PostFormValue("token"), rd))
}

// inviteCodePage is the invitation's code page: the box naming the app and
// role, the code form, and the button that sends a new code with the token.
func (s *Server) inviteCodePage(a *roles.App, v store.Invitation, token, rd string) *invitePage {
	return &invitePage{
		Heading: msgInviteCodeTitle, App: a.Label, Access: s.inviteBoxLine(a, v),
		Lines: []string{fmt.Sprintf(msgInviteCodeBody, v.Email, a.Label)},
		Code:  true, CodeForm: true, CodeButton: msgInviteCodeButton, Redirect: rd,
		Token: token, Late: msgInviteCodeLate, NewCode: msgInviteNewCode,
	}
}

// renderInviteCodeError shows the invitation's code page again after a code
// was refused, in place of the sign-in code page. The token comes back with
// the code form, and is kept for "Send a new code" only when it still names
// the invitation the code step is for. ended drops the code form, after the
// code step has ended. It reports false, having drawn nothing, when the
// invitation cannot be found, so the caller shows its usual page.
func (s *Server) renderInviteCodeError(w http.ResponseWriter, r *http.Request, status int, st *session.State, rd, msg string, ended bool) bool {
	v, ok, err := s.store.GetInvitation(r.Context(), st.Invite)
	if err != nil || !ok {
		return false
	}
	a, known := s.appRoles.Apps[v.App]
	if !known {
		return false
	}
	token := r.PostFormValue("token")
	if t, found, err := s.inviteByToken(r.Context(), token); err != nil || !found || t.ID != v.ID {
		token = ""
	}
	p := s.inviteCodePage(a, v, token, rd)
	p.Error, p.CodeForm = msg, !ended
	s.renderInvite(w, status, p)
	return true
}

// acceptInvite accepts the invitation the code step names, after a correct
// code for email. A failure is logged and leaves the sign-in to go ahead as
// any other would; the done page then shows the invitation's state.
func (s *Server) acceptInvite(r *http.Request, id int64, emailAddr string, now time.Time) {
	v, ok, err := s.store.GetInvitation(r.Context(), id)
	if err != nil || !ok {
		log.Printf("accept invitation %d for %s: not found (%v)", id, emailAddr, err)
		return
	}
	ev := store.AdminEvent{
		Actor: emailAddr, Action: store.AdminActionInviteAccept, Target: v.App + ":" + v.Role, Detail: emailAddr,
		ClientIP: clientIP(r), UserAgent: clampUserAgent(r.UserAgent()), CreatedAt: now,
	}
	if _, err := s.store.AcceptInvitation(r.Context(), id, emailAddr, now, ev); err != nil {
		if !errors.Is(err, store.ErrInvitationClosed) {
			log.Printf("accept invitation %d for %s: %v", id, emailAddr, err)
		}
		return
	}
	s.forgetRoles()
}

// handleInviteDone is where the code step lands: the accepted page for the
// person signed in as the invited address, or the invitation's state if it
// could not be accepted.
func (s *Server) handleInviteDone(w http.ResponseWriter, r *http.Request) {
	id, ok := s.readSession(r, s.now())
	if !ok {
		http.Redirect(w, r, s.cfg.PublicURL+"/login", http.StatusFound)
		return
	}
	n, err := strconv.ParseInt(r.URL.Query().Get("i"), 10, 64)
	if err != nil {
		http.Redirect(w, r, s.cfg.PublicURL+"/welcome", http.StatusFound)
		return
	}
	v, found, err := s.store.GetInvitation(r.Context(), n)
	a, known := s.appRoles.Apps[v.App]
	if err != nil || !found || !known || v.Email != id.Email || v.Open(s.now()) {
		http.Redirect(w, r, s.cfg.PublicURL+"/welcome", http.StatusFound)
		return
	}
	s.renderInvite(w, http.StatusOK, s.closedInvitePage(r, a, v))
}
