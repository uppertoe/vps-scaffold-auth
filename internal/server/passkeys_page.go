// Your passkeys page: listing and removing passkeys, and the emails sent when a passkey is added or removed.

package server

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/breakglass"
	"github.com/uppertoe/vps-scaffold-auth/internal/email"
	"github.com/uppertoe/vps-scaffold-auth/internal/passkey"
	"github.com/uppertoe/vps-scaffold-auth/internal/session"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
)

// handlePasskeyScript serves the one script the sign-in pages use.
func (s *Server) handlePasskeyScript(w http.ResponseWriter, r *http.Request) {
	if s.passkeysOff(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Write(passkeyScript)
}

// handlePasskeys is the person's own passkeys page.
func (s *Server) handlePasskeys(w http.ResponseWriter, r *http.Request) {
	if s.passkeysOff(w, r) {
		return
	}
	id, role, ok := s.passkeySession(r)
	if !ok {
		http.Redirect(w, r, s.loginURL(s.passkeysURL()), http.StatusFound)
		return
	}
	s.renderPasskeys(w, r, id, role, false)
}

// renderPasskeys draws the passkeys page. confirmed is set straight after an
// administrator's authenticator code, which lets the page add a passkey
// although the sign-in is not recent.
func (s *Server) renderPasskeys(w http.ResponseWriter, r *http.Request, id *session.Identity, role string, confirmed bool) {
	list, err := s.store.ListPasskeys(r.Context(), id.Email)
	if err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong"})
		return
	}
	csrf, err := s.sessions.EnsureCSRF(w, r, csrfTTL, s.now())
	if err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong"})
		return
	}
	phone := isPhone(r)
	// On a computer, a passkey is added only once the person has chosen to;
	// confirmed follows that choice, through the code confirmation.
	addComputer := !phone && (confirmed || r.URL.Query().Get("add") == "computer")
	pp := &passkeyPage{Phone: phone, Computer: !phone, Text: pkText}
	if !phone {
		if msg, blocked := s.passkeyBlockedNetwork(r); blocked {
			pp.OnNetwork, addComputer = msg, false
		}
	}
	if phone || addComputer {
		switch {
		case confirmed || s.mayAddPasskeyNow(id, role):
			reg, err := s.passkeyRegisterOptionsFor(w, r, id.Email, confirmed)
			if err != nil {
				s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong"})
				return
			}
			pp = reg
			pp.CanAdd = true
		case role == authz.RoleAdmin && s.cfg.TOTPEnabled:
			pp.NeedCode = true
		default:
			pp.NeedEmail = true
			back := s.passkeysURL()
			if addComputer {
				back += "?add=computer"
			}
			pp.ReauthURL = s.loginURL(back)
		}
	}
	pp.AddComputer = addComputer
	pp.Rows = s.ownPasskeyRows(r, id, list)
	for _, row := range pp.Rows {
		pp.HeldHere = pp.HeldHere || row.Kind == msgPkThisComputer
	}
	pp.Removed = r.URL.Query().Get("removed") == "1"
	pp.Next = s.passkeysURL()
	pp.RPID = s.relyingParty().ID
	s.prunePasskeysHere(w, r, "")
	pp.Gone = s.takePasskeyForget(w, r)
	s.render(w, http.StatusOK, "passkeys", pageData{Passkey: pp, CSRF: csrf, Identity: id.Email})
}

// handlePasskeyRemove removes one of the signed-in person's passkeys.
func (s *Server) handlePasskeyRemove(w http.ResponseWriter, r *http.Request) {
	if s.passkeysOff(w, r) || !s.requireSameOrigin(w, r) {
		return
	}
	id, _, ok := s.passkeySession(r)
	if !ok {
		http.Redirect(w, r, s.loginURL(s.passkeysURL()), http.StatusFound)
		return
	}
	if !s.sessions.VerifyCSRF(r, r.PostFormValue("csrf"), s.now()) {
		s.render(w, http.StatusForbidden, "message", pageData{
			Title: "Please try again", Message: "This page had expired, so the passkey has not been removed. Open Your passkeys and try again.",
		})
		return
	}
	pid, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	held, found, err := s.store.GetPasskey(r.Context(), pid)
	if err != nil {
		s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Something went wrong"})
		return
	}
	removed := false
	if found && held.Email == id.Email {
		// The sessions the passkey started end first; the passkey is removed
		// only once they have, so a failure leaves it listed to try again.
		err = s.revokeAnd(r.Context(), []string{passkeyKey(pid)}, func(x *store.Session) bool { return x.Passkey == pid }, s.now(), func() error {
			var err error
			removed, err = s.store.DeletePasskey(r.Context(), id.Email, pid)
			return err
		})
		if err != nil {
			log.Printf("remove passkey %d: %v", pid, err)
			s.render(w, http.StatusInternalServerError, "message", pageData{Title: "Please try again", Message: msgPkRemoveFailed})
			return
		}
	}
	if removed {
		// The person removed it on this device: the page this redirects to
		// asks the browser to forget it.
		s.forgetPasskeyHere(w, r, held.CredentialID)
		s.setPasskeyForget(w, held.CredentialID)
		s.recordAuth(r, id.Email, store.AuthEventPasskeyRemove, store.AuthOutcomeOK)
		s.notifyPasskeyRemoved(r, id.Email, s.now())
	}
	http.Redirect(w, r, s.passkeysURL()+"?removed=1", http.StatusFound)
}

// handleAdminRemovePasskeys removes every passkey of one person.
func (s *Server) handleAdminRemovePasskeys(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	emailAddr := normalizeEmail(r.PostFormValue("email"))
	keys, err := s.store.ListPasskeys(r.Context(), emailAddr)
	if err != nil {
		s.adminError(w, r)
		return
	}
	// The sessions the passkeys started end first, those of a passkey added
	// since the list included; the passkeys are removed only once they have.
	cut := make([]string, 0, len(keys))
	for _, k := range keys {
		cut = append(cut, passkeyKey(k.ID))
	}
	var n int
	if err := s.revokeAnd(r.Context(), cut, func(x *store.Session) bool { return x.Email == emailAddr && x.Passkey != 0 }, s.now(), func() error {
		var err error
		n, err = s.store.DeletePasskeys(r.Context(), emailAddr)
		return err
	}); err != nil {
		s.adminError(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionPasskeysRemove, emailAddr, strconv.Itoa(n))
	http.Redirect(w, r, "/admin/access?email="+url.QueryEscape(emailAddr)+"&passkeys_removed=1", http.StatusFound)
}

// passkeyRows lists passkeys for the administrator's page, and is the base of
// the person's own (ownPasskeyRows).
func (s *Server) passkeyRows(list []store.Passkey) []passkeyRow {
	today := s.now().In(s.loc).Format("2006-01-02")
	out := make([]passkeyRow, 0, len(list))
	for _, p := range list {
		row := passkeyRow{ID: p.ID, Name: p.Label, Added: p.CreatedAt.In(s.loc).Format("2 January 2006")}
		row.Computer = p.Device == store.DeviceComputer
		if row.Computer {
			row.Device, row.Kind = msgPkDeviceComputer, msgPkAComputer
		} else {
			row.Device, row.Kind = msgPkDevicePhone, msgPkAPhone
		}
		switch {
		case p.LastUsedAt.IsZero():
			row.Used = "Not used yet"
		case p.LastUsedAt.In(s.loc).Format("2006-01-02") == today:
			row.Used = "Last used today"
		default:
			row.Used = "Last used " + p.LastUsedAt.In(s.loc).Format("2 January 2006")
		}
		if row.Name == "" {
			row.Name = "Passkey"
		}
		out = append(out, row)
	}
	return out
}

// ownPasskeyRows lists a person's passkeys for their own page, naming the
// one this device holds, as far as the gateway can tell: the passkey that
// started this session, or one that passkeyHereCookie names.
func (s *Server) ownPasskeyRows(r *http.Request, id *session.Identity, list []store.Passkey) []passkeyRow {
	here := map[string]bool{}
	for _, c := range s.passkeysHere(r) {
		here[c] = true
	}
	rows := s.passkeyRows(list)
	for i, p := range list {
		if p.ID != id.PK && !here[b64(p.CredentialID)] {
			continue
		}
		if rows[i].Computer {
			rows[i].Kind = msgPkThisComputer
		} else {
			rows[i].Kind = msgPkThisPhone
		}
	}
	return rows
}

// passkeyProviders names the common passkey providers by the identifier
// (AAGUID) they report. A name is only a label for the person's own list; an
// unknown or withheld identifier falls back to the kind of phone.
var passkeyProviders = map[string]string{
	"ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "Google Password Manager",
	"fbfc3007-154e-4ecc-8c0b-6e020557d7bd": "iCloud Keychain",
	"dd4ec289-e01d-41c9-bb89-70fa845d4bf2": "iCloud Keychain",
	"bada5566-a7aa-401f-bd96-45619a55120d": "1Password",
	"d548826e-79b4-db40-a3d8-11116f7e8349": "Bitwarden",
	"53414d53-554e-4700-0000-000000000000": "Samsung Pass",
	"08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
	"9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello",
	"6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello",
	"adce0002-35bc-c60a-648b-0b25f1f05503": "Chrome on Mac",
}

func passkeyLabel(aaguid [16]byte, r *http.Request) string {
	if name, ok := passkeyProviders[passkey.AAGUIDString(aaguid)]; ok {
		return name
	}
	ua := r.UserAgent()
	switch {
	case strings.Contains(ua, "iPhone"):
		return "Passkey on an iPhone"
	case strings.Contains(ua, "Android"):
		return "Passkey on an Android phone"
	case strings.Contains(ua, "Macintosh"):
		return msgPkLabelMac
	case strings.Contains(ua, "Windows"):
		return msgPkLabelWindows
	case !isPhoneUA(ua):
		return msgPkLabelComputer
	}
	return "Passkey"
}

// notifyPasskeyAdded emails the account holder whenever a passkey is added.
// A passkey needs no proof of the device that made it, so a session cookie
// stolen soon after a sign-in could register a key of the thief's; this email
// is how the person learns of it. It is sent on a detached goroutine, like the
// sign-in code, so mail delivery never delays the page.
func (s *Server) notifyPasskeyAdded(r *http.Request, to string, now time.Time) {
	msg := s.passkeyAddedEmail(to, passkeyDevice(r.UserAgent()), now)
	s.sendNotice("passkey notice to "+to, func(ctx context.Context) error { return s.sender.Send(ctx, msg) })
}

// notifyPasskeyRemoved emails the account holder when they remove one of
// their passkeys. A session started with one passkey can remove the others,
// so a stolen, unlocked phone could strip the owner's other passkeys; this
// email is how the owner learns of it.
func (s *Server) notifyPasskeyRemoved(r *http.Request, to string, now time.Time) {
	msg := s.passkeyRemovedEmail(to, passkeyDevice(r.UserAgent()), now)
	s.sendNotice("passkey notice to "+to, func(ctx context.Context) error { return s.sender.Send(ctx, msg) })
}

// passkeyNoticeData is the view model for a passkey notice. The template
// renders with text/template, which does not escape, so every string is
// HTML-escaped by renderPasskeyNoticeHTML; the colours are validated "#rrggbb".
type passkeyNoticeData struct {
	BrandName, Heading, First, OK, NotYou, Link, LinkLabel string
	HeaderColor, HeaderText                                string
	AccentColor, AccentText                                string
}

// renderPasskeyNoticeHTML lays a notice out like the sign-in code email, in
// the admin branding's colours, falling back to plain paragraphs if the
// template ever fails so that the notice is still sent.
func (s *Server) renderPasskeyNoticeHTML(heading, first, ok, notYou, linkLabel, link string, now time.Time) string {
	header := breakglass.DefaultPalette.Header
	accent := breakglass.DefaultPalette.Accent
	if b, err := s.publicBrandingAt(context.Background(), now); err == nil {
		header = hexOrDefault(b.headerColor, header)
		accent = hexOrDefault(b.accentColor, accent)
	}
	esc := html.EscapeString
	var buf bytes.Buffer
	err := s.emailTmpl.ExecuteTemplate(&buf, "email_passkey_notice", passkeyNoticeData{
		BrandName: esc(s.cfg.BrandName), Heading: esc(heading), First: esc(first), OK: esc(ok), NotYou: esc(notYou), Link: esc(link), LinkLabel: esc(linkLabel),
		HeaderColor: header, HeaderText: emailTextOn(header),
		AccentColor: accent, AccentText: emailTextOn(accent),
	})
	if err == nil {
		return buf.String()
	}
	log.Printf("render passkey notice: %v", err)
	return `<p>` + esc(first) + `</p><p>` + esc(ok) + `</p><p>` + esc(notYou) + `</p><p><a href="` + esc(link) + `">` + esc(linkLabel) + `</a></p>`
}

// passkeyDevice names the kind of phone or computer for the notice, or "" if
// unknown.
func passkeyDevice(ua string) string {
	switch {
	case strings.Contains(ua, "iPhone"):
		return "an iPhone"
	case strings.Contains(ua, "Android"):
		return "an Android phone"
	case strings.Contains(ua, "Macintosh"):
		return msgPkNoticeMac
	case strings.Contains(ua, "Windows"):
		return msgPkNoticeWindows
	case ua != "" && !isPhoneUA(ua):
		return msgPkNoticeOther
	}
	return ""
}

// passkeyNotice builds a notice whose first line reads "A passkey was <done>
// your account at <host> on <date> at <time>[, on <device>]."
func (s *Server) passkeyNotice(to, subject, done, device, ok, notYou string, now time.Time) email.Message {
	first := fmt.Sprintf("A passkey was %s your account at %s on %s", done, s.relyingParty().ID, s.noticeStamp(now))
	if device != "" {
		first += ", on " + device
	}
	first += "."
	return s.personalNotice(to, subject, first, ok, notYou, "Your passkeys", s.passkeysURL(), now)
}

// noticeStamp is "2 January 2006 at 3:04 pm", for a personal notice.
func (s *Server) noticeStamp(now time.Time) string {
	when := now.In(s.loc)
	return when.Format("2 January 2006") + " at " + strings.ToLower(when.Format("3:04 pm"))
}

// personalNotice is an email to the account holder about a change to their
// account (a passkey added or removed, sessions signed out): a heading, three
// sentences and a button to the page where they can check it.
func (s *Server) personalNotice(to, subject, first, ok, notYou, linkLabel, link string, now time.Time) email.Message {
	text := first + "\n\n" + ok + "\n\n" + notYou + "\n\n" + linkLabel + ": " + link + "\n"
	htmlBody := s.renderPasskeyNoticeHTML(subject, first, ok, notYou, linkLabel, link, now)
	return email.Message{To: to, Subject: subject, Text: text, HTML: htmlBody}
}

func (s *Server) passkeyAddedEmail(to, device string, now time.Time) email.Message {
	return s.passkeyNotice(to, "A passkey has been added to your account", "added to", device,
		"If you added this passkey, there is nothing more to do.",
		"If you did not add it, open Your passkeys, remove it, then contact an administrator for assistance.", now)
}

func (s *Server) passkeyRemovedEmail(to, device string, now time.Time) email.Message {
	return s.passkeyNotice(to, "A passkey has been removed from your account", "removed from", device,
		"If you removed this passkey, there is nothing more to do.",
		"If you did not remove it, sign in, check Your passkeys, then contact an administrator for assistance.", now)
}
