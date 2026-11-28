package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
	"github.com/uppertoe/vps-scaffold-auth/internal/breakglass"
	"github.com/uppertoe/vps-scaffold-auth/internal/otp"
	"github.com/uppertoe/vps-scaffold-auth/internal/store"
	"github.com/uppertoe/vps-scaffold-auth/internal/totp"
)

// adminRoutes registers the admin subtree on its own mux. The whole tree is
// wrapped by requireAdmin in routes(); handlers here can assume an admin caller.
func (s *Server) adminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/{$}", s.handleAdminHome)
	mux.HandleFunc("GET /admin/apps", s.handleAdminApps)
	mux.HandleFunc("GET /admin/apps/{app}", s.handleAdminApp)
	mux.HandleFunc("POST /admin/apps/{app}/review", s.handleAdminAppReview)
	mux.HandleFunc("POST /admin/apps/{app}/edit", s.handleAdminAppEdit)
	mux.HandleFunc("POST /admin/apps/{app}/save", s.handleAdminAppSave)
	mux.HandleFunc("GET /admin/invitations", s.handleAdminInvites)
	mux.HandleFunc("GET /admin/invitations/new", s.handleAdminNewInvite)
	mux.HandleFunc("POST /admin/invitations/check", s.handleAdminInviteCheck)
	mux.HandleFunc("POST /admin/invitations/edit", s.handleAdminInviteEdit)
	mux.HandleFunc("POST /admin/invitations", s.handleAdminInviteSend)
	mux.HandleFunc("POST /admin/invitations/{id}/resend", s.handleAdminInviteResend)
	mux.HandleFunc("POST /admin/invitations/{id}/withdraw", s.handleAdminInviteWithdraw)
	mux.HandleFunc("GET /admin/groups", s.handleAdminGroups)
	mux.HandleFunc("GET /admin/groups/new", s.handleAdminNewGroup)
	mux.HandleFunc("POST /admin/groups/{name}/domains", s.handleAdminAddDomain)
	mux.HandleFunc("POST /admin/groups/{name}/domains/delete", s.handleAdminRemoveDomain)
	mux.HandleFunc("POST /admin/groups", s.handleAdminCreateGroup)
	mux.HandleFunc("GET /admin/groups/{name}", s.handleAdminGroup)
	mux.HandleFunc("POST /admin/groups/{name}/delete", s.handleAdminDeleteGroup)
	mux.HandleFunc("POST /admin/groups/{name}/label", s.handleAdminGroupLabel)
	mux.HandleFunc("POST /admin/groups/{name}/org", s.handleAdminGroupOrg)
	mux.HandleFunc("POST /admin/groups/{name}/members", s.handleAdminAddMember)
	mux.HandleFunc("POST /admin/groups/{name}/members/confirm", s.handleAdminConfirmMembers)
	mux.HandleFunc("POST /admin/groups/{name}/includes", s.handleAdminAddInclude)
	mux.HandleFunc("POST /admin/groups/{name}/sync", s.handleAdminSyncGroup)
	mux.HandleFunc("POST /admin/groups/{name}/keep", s.handleAdminKeepMembers)
	mux.HandleFunc("POST /admin/groups/{name}/includes/delete", s.handleAdminRemoveInclude)
	mux.HandleFunc("POST /admin/groups/{name}/members/delete", s.handleAdminRemoveMember)
	mux.HandleFunc("GET /admin/access", s.handleAdminAccess)
	mux.HandleFunc("GET /admin/app-feeds", s.handleAdminReaders)
	mux.HandleFunc("POST /admin/member-readers/approve", s.handleAdminApproveReader)
	mux.HandleFunc("POST /admin/member-readers/withdraw", s.handleAdminWithdrawReader)
	mux.HandleFunc("GET /admin/audit", s.handleAdminAudit)
	mux.HandleFunc("GET /admin/break", s.handleAdminBreakList)
	mux.HandleFunc("POST /admin/break", s.handleAdminBreakCreate)
	mux.HandleFunc("GET /admin/break/new", s.handleAdminBreakNew)
	mux.HandleFunc("GET /admin/break/preview.svg", s.handleAdminBreakPreview)
	mux.HandleFunc("GET /admin/break/{id}", s.handleAdminBreakDetail)
	mux.HandleFunc("POST /admin/break/{id}/revoke", s.handleAdminBreakRevoke)
	mux.HandleFunc("POST /admin/break/{id}/remint", s.handleAdminBreakRemint)
	mux.HandleFunc("POST /admin/break/{id}/design", s.handleAdminBreakDesign)
	// pdf, qr.png and card.svg (see handleAdminBreakFile).
	mux.HandleFunc("GET /admin/break/{id}/{file}", s.handleAdminBreakFile)
	mux.HandleFunc("GET /admin/break/designs", s.handleAdminDesigns)
	mux.HandleFunc("POST /admin/break/designs", s.handleAdminDesignCreate)
	mux.HandleFunc("GET /admin/break/designs/new", s.handleAdminDesignNew)
	mux.HandleFunc("GET /admin/break/designs/preview.svg", s.handleAdminDesignPreview)
	mux.HandleFunc("GET /admin/break/designs/{id}", s.handleAdminDesign)
	mux.HandleFunc("GET /admin/break/designs/{id}/card.svg", s.handleAdminDesignSVG)
	mux.HandleFunc("POST /admin/break/designs/{id}/save", s.handleAdminDesignSave)
	mux.HandleFunc("POST /admin/break/designs/{id}/delete", s.handleAdminDesignDelete)
	mux.HandleFunc("GET /admin/branding", s.handleAdminBranding)
	mux.HandleFunc("POST /admin/branding", s.handleAdminSaveBranding)
	mux.HandleFunc("GET /admin/branding/{which}/img", s.handleAdminBrandingImage)
	mux.HandleFunc("GET /admin/settings", s.handleAdminSettings)
	mux.HandleFunc("POST /admin/settings", s.handleAdminSaveSettings)
	mux.HandleFunc("GET /admin/totp", s.handleAdminTOTP)
	mux.HandleFunc("POST /admin/totp/generate", s.handleAdminTOTPGenerate)
	mux.HandleFunc("POST /admin/totp/remove", s.handleAdminTOTPRemove)
	mux.HandleFunc("POST /admin/passkeys/remove", s.handleAdminRemovePasskeys)
	mux.HandleFunc("GET /admin/sessions", s.handleAdminSessions)
	mux.HandleFunc("POST /admin/sessions/end", s.handleAdminEndSessions)
	mux.HandleFunc("POST /admin/sessions/end-one", s.handleAdminEndSession)
	mux.HandleFunc("POST /admin/sessions/end-all", s.handleAdminEndAllSessions)
}

// --- Admin two-factor provisioning ---
//
// TOTP secrets are provisioned out-of-band, never self-enrolled at login (that
// would let an inbox-only attacker bootstrap the second factor). An already
// authenticated admin mints a secret here and conveys it to the target admin
// over a trusted channel; the first admin is bootstrapped with the -totp-enroll
// CLI. See startTOTP.

// handleAdminTOTP lists the configured admins and their enrolment status.
func (s *Server) handleAdminTOTP(w http.ResponseWriter, r *http.Request) {
	s.renderAdmin(w, r, http.StatusOK, "admin_totp", adminData{
		Title:       "Admin two-factor",
		TOTPEnabled: s.cfg.TOTPEnabled,
		TOTPAdmins:  s.totpAdminViews(r.Context()),
	})
}

// handleAdminTOTPGenerate mints (or resets) a TOTP secret for a configured admin
// and shows it exactly once on the returned page.
func (s *Server) handleAdminTOTPGenerate(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	emailAddr := normalizeEmail(r.PostFormValue("email"))
	if !s.isAdminEmail(emailAddr) {
		s.renderAdmin(w, r, http.StatusBadRequest, "admin_message", adminData{
			Title:   "Unknown admin",
			Message: "That address is not in the configured admin list (ADMIN_EMAILS), so a secret was not created.",
		})
		return
	}
	en, err := totp.Enroll(s.totpIssuer(), emailAddr)
	if err != nil {
		s.adminError(w, r)
		return
	}
	_, replacing, err := s.store.GetTOTPSecret(r.Context(), emailAddr)
	if err != nil {
		s.adminError(w, r)
		return
	}
	// A secret is replaced when the old authenticator is lost or may be in
	// someone else's hands: every session it passed ends first, and the
	// secret is replaced only once they have (revokeAnd).
	set := func() error { return s.setTOTPSecret(r.Context(), emailAddr, en.Secret) }
	var err2 error
	if replacing {
		err2 = s.revokeAnd(r.Context(), []string{emailAddr}, sessionsForKey(emailAddr), s.now(), set)
	} else {
		err2 = set()
	}
	if err2 != nil {
		s.adminError(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionTOTPGenerate, emailAddr, "")
	// Render (not redirect) so the secret appears once and lands in no URL or
	// history; refreshing the page drops it.
	s.renderAdmin(w, r, http.StatusOK, "admin_totp", adminData{
		Title:       "Admin two-factor",
		TOTPEnabled: s.cfg.TOTPEnabled,
		TOTPAdmins:  s.totpAdminViews(r.Context()),
		NewTOTP:     &newTOTPView{Email: emailAddr, URL: en.URL, Key: en.Secret},
	})
}

// handleAdminTOTPRemove deletes an admin's TOTP secret. With TOTP enabled, that
// admin then cannot sign in until re-provisioned.
func (s *Server) handleAdminTOTPRemove(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	emailAddr := normalizeEmail(r.PostFormValue("email"))
	// The authenticator may be lost or in someone else's hands: every
	// session it passed ends first, and the secret is removed only once
	// they have (revokeAnd).
	if err := s.revokeAnd(r.Context(), []string{emailAddr}, sessionsForKey(emailAddr), s.now(), func() error {
		return s.store.DeleteTOTPSecret(r.Context(), emailAddr)
	}); err != nil {
		s.adminError(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionTOTPRemove, emailAddr, "")
	http.Redirect(w, r, "/admin/totp", http.StatusFound)
}

// handleAdminEndSessions signs a person out on every device: every session
// they have, wherever it is, ends at once. From the Sessions page it returns
// there; otherwise to the person's access log.
func (s *Server) handleAdminEndSessions(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	emailAddr := normalizeEmail(r.PostFormValue("email"))
	if !plainAddress(emailAddr) {
		http.Redirect(w, r, "/admin/access", http.StatusFound)
		return
	}
	if err := s.endSessions(r.Context(), emailAddr, s.now()); err != nil {
		s.adminError(w, r)
		return
	}
	s.auditAdmin(r, store.AdminActionSessionsEnd, emailAddr, "")
	s.emailOtherAdmins(s.adminActor(r), fmt.Sprintf(msgSessSubjectPerson, emailAddr), []string{fmt.Sprintf(msgSessLinePerson, emailAddr)})
	if r.PostFormValue("back") == "sessions" {
		s.redirectDone(w, r, sessionsHref(emailAddr, nil), "sessions-ended", "")
		return
	}
	http.Redirect(w, r, "/admin/access?email="+url.QueryEscape(emailAddr)+"&sessions_ended=1", http.StatusFound)
}

// totpAdminViews reports each configured admin and whether a secret is stored.
func (s *Server) totpAdminViews(ctx context.Context) []totpAdminView {
	out := make([]totpAdminView, 0, len(s.cfg.AdminEmails))
	for _, e := range s.cfg.AdminEmails {
		_, ok, err := s.store.GetTOTPSecret(ctx, e)
		if err != nil {
			log.Printf("totp status for %s: %v", e, err)
		}
		out = append(out, totpAdminView{Email: e, Enrolled: ok})
	}
	return out
}

// isAdminEmail reports whether email is in the configured admin list. AdminEmails
// is already normalised (lowercased/trimmed) at config load.
func (s *Server) isAdminEmail(email string) bool {
	for _, e := range s.cfg.AdminEmails {
		if e == email {
			return true
		}
	}
	return false
}

// totpIssuer is the issuer label shown in authenticator apps.
func (s *Server) totpIssuer() string {
	if s.cfg.TOTPIssuer != "" {
		return s.cfg.TOTPIssuer
	}
	return s.cfg.Domain
}

func orFallback(v, def string) string {
	if trimField(v) == "" {
		return def
	}
	return v
}

// splitEmails parses a comma/space/newline-separated email list, normalised.
func splitEmails(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == ';'
	}) {
		if e := normalizeEmail(f); e != "" {
			out = append(out, e)
		}
	}
	return out
}

// requireAdmin gates the admin subtree: a normal session of a current
// administrator that holds the admin tier, which with TOTP enabled means a
// second step within adminStepMaxAge. Non-admins are sent to the login flow;
// an administrator without a recent second step is sent to the admin door.
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.readSession(r, s.now())
		// A break-glass or guest session must never reach the admin UI, even if
		// its groups somehow include "admin": the admin tier requires a real
		// login (and TOTP when enabled), not a bearer QR scan or a stranger's
		// sign-in. isAdminSession admits only the normal session kind.
		// The cookie's groups were true when it was minted; the admin UI never
		// passes through /verify, where renewal re-checks policy, so an admin
		// removed from ADMIN_EMAILS would otherwise keep this door until the
		// cookie expired. Re-check the current policy on every admin request.
		admin := ok && id.Kind == "" && s.policy.Role(id.Email) == authz.RoleAdmin
		rd := s.cfg.PublicURL + r.URL.RequestURI()
		if !admin {
			// Someone signed in, but not as an administrator, is told so on
			// the no-access page, which names the address they used and
			// offers to sign in again. Sending them to the email page instead
			// looked as though the sign-in had failed.
			if ok {
				http.Redirect(w, r, s.cfg.PublicURL+"/denied?rd="+url.QueryEscape(rd), http.StatusFound)
				return
			}
			http.Redirect(w, r, s.cfg.PublicURL+"/login?rd="+url.QueryEscape(rd), http.StatusFound)
			return
		}
		// An administrator holds the admin pages only with a recent second step
		// (adminTierHeld); without one they are sent to the admin door, which
		// brings them back here.
		// A session whose step is recent but whose groups predate a promotion
		// (or, with TOTP off, any promoted administrator) is renewed here, so
		// the admin group is added rather than the door asking for a step
		// that has already been taken.
		if !s.adminTierHeld(id) && s.adminStepFresh(id) {
			if !s.renewSession(w, r, id, s.now()) {
				return
			}
		}
		if !s.adminTierHeld(id) {
			http.Redirect(w, r, s.stepUpURL(rd), http.StatusFound)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), adminActorKey{}, id.Email)))
	})
}

// adminActorKey carries the address requireAdmin admitted (adminActor).
type adminActorKey struct{}

// csrfTTL bounds the lifetime of the CSRF cookie.
const csrfTTL = 12 * time.Hour

// checkCSRF verifies the submitted token; on failure it writes a 403 and
// returns false.
func (s *Server) checkCSRF(w http.ResponseWriter, r *http.Request) bool {
	if !s.sessions.VerifyCSRF(r, r.PostFormValue("csrf"), s.now()) {
		s.renderAdmin(w, r, http.StatusForbidden, "admin_message", adminData{
			Title: "Request rejected", Message: "Invalid or expired form token. Please try again.",
		})
		return false
	}
	return true
}

// auditAdmin records an attributable administrative action. The actor is taken
// from the already-validated admin session (this only runs behind requireAdmin).
// Best-effort: a write failure is logged but does not undo the action that has
// already happened. Call it AFTER the mutation succeeds.
func (s *Server) auditAdmin(r *http.Request, action, target, detail string) {
	actor := s.adminActor(r)
	if err := s.store.RecordAdminEvent(r.Context(), store.AdminEvent{
		Actor:     actor,
		Action:    action,
		Target:    target,
		Detail:    detail,
		ClientIP:  clientIP(r),
		UserAgent: clampUserAgent(r.UserAgent()),
		CreatedAt: s.now(),
	}); err != nil {
		log.Printf("record admin event %s (actor=%s target=%q): %v", action, actor, target, err)
	}
}

// --- Home ---

// handleAdminHome is the overview: what needs an administrator's attention,
// and a count of what the gateway holds.
func (s *Server) handleAdminHome(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	groups, err := s.store.ListGroups(ctx)
	if err != nil {
		s.adminError(w, r)
		return
	}
	codes, err := s.store.ListBreakGlassCodes(ctx)
	if err != nil {
		s.adminError(w, r)
		return
	}
	ov := &overviewView{Apps: len(s.appRoles.Apps), Groups: len(groups), TOTPEnabled: s.cfg.TOTPEnabled}
	for _, c := range codes {
		if c.Status == "active" {
			ov.ActiveCards++
		}
	}
	// The groups as the Groups pages see them, so that a group the Overview
	// calls unused is one the Groups pages mark "Not used by any app".
	view, err := s.groupViews(r)
	if err == nil {
		err = s.fillGroupRoles(r, view)
	}
	if err != nil {
		s.adminError(w, r)
		return
	}
	for _, g := range view {
		if g.NotYetCreated {
			continue
		}
		ov.Members += len(g.Members)
		if g.NotUsed {
			ov.UnusedGroups = append(ov.UnusedGroups, g.Name)
		}
	}
	includes, err := s.store.ListGroupIncludes(ctx)
	if err != nil {
		s.adminError(w, r)
		return
	}
	if states, err := s.store.ListGroupSyncStates(ctx); err == nil {
		for g := range s.feeds.feeds {
			if st, ok := states[g]; ok && st.Status != store.GroupSyncOK {
				ov.FeedProblems = append(ov.FeedProblems, g)
			}
		}
		sort.Strings(ov.FeedProblems)
	}
	for g := range s.feeds.feeds {
		if len(includes[g]) > 0 {
			ov.FeedIncludes = append(ov.FeedIncludes, g)
		}
	}
	sort.Strings(ov.FeedIncludes)
	if s.cfg.TOTPEnabled {
		for _, a := range s.totpAdminViews(ctx) {
			if !a.Enrolled {
				ov.AdminsWithoutTOTP = append(ov.AdminsWithoutTOTP, a.Email)
			}
		}
	}
	ov.Sites, ov.ReachIntro = s.routeAccess(), msgReachIntro
	// The Apps, Invitations and Cards pages' attention lines, so the
	// Overview lists everything that needs an administrator.
	if s.rolesOn() {
		world, err := s.loadRolesWorld(ctx)
		if err != nil {
			s.adminError(w, r)
			return
		}
		ov.Lines = append(closedAppLines(world), s.invitationLines(world)...)
	}
	stats, err := s.cardStats(ctx)
	if err != nil {
		s.adminError(w, r)
		return
	}
	sortCards(codes)
	ov.Lines = append(ov.Lines, cardLines(codes, stats)...)
	if apps := s.waitingReaders(ctx); len(apps) > 0 {
		ov.Lines = append(ov.Lines, feedsWaitingLine(apps))
	}
	ov.CardsTile = msgActiveCardsTile
	s.renderAdmin(w, r, http.StatusOK, "admin_home", adminData{Title: "Overview", Overview: ov})
}

// --- Login & access audit ---

// handleAdminAudit shows the administrative-action audit trail: which admin
// minted/revoked a break-glass code, changed groups, removed another admin's
// 2FA, or edited settings — the attributable record of privileged mutations.
func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	const limit = 250
	events, err := s.store.ListAdminEvents(r.Context(), limit, 0)
	if err != nil {
		s.adminError(w, r)
		return
	}
	s.renderAdmin(w, r, http.StatusOK, "admin_audit", adminData{
		Title:       "Admin audit",
		AdminEvents: s.toAdminEventViews(events),
	})
}

// --- Break-glass codes ---

// codeImage loads a code, decrypts its token, and renders the QR PNG of its
// scan URL. Returns ok=false having already written a response on any failure
// (including a revoked code, whose QR is not served).
func (s *Server) codeImage(w http.ResponseWriter, r *http.Request) ([]byte, store.BreakGlassCode, bool) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return nil, store.BreakGlassCode{}, false
	}
	code, found, err := s.store.GetBreakGlassCode(r.Context(), id)
	if err != nil {
		s.adminError(w, r)
		return nil, store.BreakGlassCode{}, false
	}
	if !found {
		http.NotFound(w, r)
		return nil, store.BreakGlassCode{}, false
	}
	// Do not render (QR/PDF) a revoked code: scanning it is denied at /break, and
	// serving its live token as an image would only hand back a dead credential.
	if code.Status != store.BreakGlassActive {
		http.NotFound(w, r)
		return nil, store.BreakGlassCode{}, false
	}
	token, err := s.secrets.Open(code.TokenEnc)
	if err != nil {
		s.adminError(w, r)
		return nil, store.BreakGlassCode{}, false
	}
	// High resolution so the printed PDF (QR at ~76mm) stays crisp (~340 DPI);
	// the on-screen preview just downscales it.
	png, err := breakglass.QRPNG(s.breakURL(token), 1024)
	if err != nil {
		s.adminError(w, r)
		return nil, store.BreakGlassCode{}, false
	}
	return png, code, true
}

// newToken mints a fresh token and returns its ciphertext and lookup hash.
func (s *Server) newToken() (tokenEnc, tokenHash string, err error) {
	token, err := breakglass.GenerateToken()
	if err != nil {
		return "", "", err
	}
	tokenEnc, err = s.secrets.Seal(token)
	if err != nil {
		return "", "", err
	}
	return tokenEnc, otp.Hash(token), nil
}

func (s *Server) breakURL(token string) string {
	return s.cfg.PublicURL + "/break/" + token
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}
