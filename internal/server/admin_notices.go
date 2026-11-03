package server

import (
	"net/http"
	"net/url"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
)

// adminNotices maps the notice code an admin action sets to the confirmation
// shown at the top of the next page. Only these fixed strings are ever shown.
var adminNotices = map[string]string{
	"group-created":   "The group has been created.",
	"group-deleted":   "The group has been deleted.",
	"label-saved":     "The label has been saved.",
	"member-added":    "The member has been added.",
	"member-removed":  "The member has been removed.",
	"members-added":   "The members have been added.",
	"include-added":   "The group now admits the members of the included group.",
	"include-removed": "The group no longer admits the members of that group.",
	"sync-ok":         "The group has been synced from its feed.",
	"card-created":    "The code has been created. Open it to print the card.",
	"card-revoked":    "The code has been revoked. Scans of it are now refused.",
	"card-reminted":   "The code has been re-minted. Cards printed before now no longer work.",
	"card-branding":   "The card design for this code has been saved.",
	"branding-saved":  "The branding has been saved.",
	"settings-saved":  "The settings have been saved.",
}

// adminWarnings are notices that report an action was NOT taken, shown in
// the error style.
var adminWarnings = map[string]string{
	"member-invalid":    "The member has not been added. Enter a full email address, such as name@example.org.",
	"members-none":      "No members have been added, because none were ticked.",
	"members-refused":   "No members have been added. The allow-list does not admit those addresses, and the gateway does not add such an address to a group an application reads as one of its own roles.",
	"include-cycle":     "The group has not been included, because that would make a group include itself.",
	"group-synced":      "The members of this group come from its feed, so they cannot be changed here. To add people alongside them, include this group in another group.",
	"sync-held":         "The members have been kept as they were, because the change is large enough to need checking. The group lists what would change; accept it there if it is right.",
	"sync-nothing-held": "No change is held for this group, so nothing has been applied.",
	"keep-ok":           "The current members have been kept. The held change will be applied only if it is accepted.",
	"keep-applied":      "The change had already been applied automatically before the page was submitted. The group shows the members it applied.",
	"keep-replaced":     "The feed has changed since the page was shown, so the new change has its own wait. The group lists it.",
	"sync-replaced":     "The change you accepted has been replaced by a newer one, so nothing has been applied. The group lists the new change.",
	"sync-unreadable":   "The gateway could not read the group's last sync, so the feed has not been fetched. The members have been kept as they were.",
	"sync-failed":       "The members have been kept as they were, because the feed could not be used. The group shows the reason.",
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
