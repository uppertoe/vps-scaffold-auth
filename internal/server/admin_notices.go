package server

import (
	"net/http"
	"net/url"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
)

// adminNotices maps the notice code an admin action sets to the confirmation
// shown at the top of the next page. Only these fixed strings are ever shown.
var adminNotices = map[string]string{
	"group-created":  "The group has been created.",
	"group-deleted":  "The group has been deleted.",
	"label-saved":    "The label has been saved.",
	"member-added":   "The member has been added.",
	"member-removed": "The member has been removed.",
	"card-created":   "The code has been created. Open it to print the card.",
	"card-revoked":   "The code has been revoked. Scans of it are now refused.",
	"card-reminted":  "The code has been re-minted. Cards printed before now no longer work.",
	"card-branding":  "The card design for this code has been saved.",
	"branding-saved": "The branding has been saved.",
	"settings-saved": "The settings have been saved.",
}

// adminWarnings are notices that report an action was NOT taken, shown in
// the error style.
var adminWarnings = map[string]string{
	"member-invalid": "The member has not been added. Enter a full email address, such as name@example.org.",
}

// noticeCookie carries the notice code from an admin action to the page it
// redirects to. A cookie, not a query parameter, so a link someone sends an
// administrator cannot show a confirmation for an action that never happened.
// It is HttpOnly, SameSite=Strict, lives for a few seconds and is cleared when
// read. With TLS the __Host- prefix also stops a sibling subdomain setting it.
func (s *Server) noticeCookieName() string {
	if s.cfg.CookieInsecure {
		return "admin_notice"
	}
	return "__Host-admin_notice"
}

// redirectDone sends the browser back to path after an admin action, with the
// notice code in a short-lived cookie and, for the Groups page, the group to
// show expanded.
func (s *Server) redirectDone(w http.ResponseWriter, r *http.Request, path, done, group string) {
	http.SetCookie(w, &http.Cookie{
		Name: s.noticeCookieName(), Value: done, Path: "/", MaxAge: 30,
		HttpOnly: true, Secure: !s.cfg.CookieInsecure, SameSite: http.SameSiteStrictMode,
	})
	target := path
	// Only a well-formed group name goes into the Location header.
	if group != "" && authz.ValidGroupName(group) {
		target += "?" + url.Values{"open": {group}}.Encode() + "#g-" + group
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// takeNotice returns the notice and warning for the code in the notice cookie,
// and clears the cookie so the notice shows once.
func (s *Server) takeNotice(w http.ResponseWriter, r *http.Request) (notice, warning string) {
	ck, err := r.Cookie(s.noticeCookieName())
	if err != nil {
		return "", ""
	}
	s.clearNotice(w)
	return adminNotices[ck.Value], adminWarnings[ck.Value]
}

// clearNotice deletes the notice cookie.
func (s *Server) clearNotice(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: s.noticeCookieName(), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: !s.cfg.CookieInsecure, SameSite: http.SameSiteStrictMode,
	})
}
