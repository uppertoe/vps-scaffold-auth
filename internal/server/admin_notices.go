package server

import (
	"net/http"
	"net/url"

	"github.com/uppertoe/vps-scaffold-auth/internal/authz"
)

// adminNotices maps the ?done= code an admin action redirects with to the
// confirmation shown at the top of the next page. Only these fixed strings are
// ever shown, so the query parameter cannot inject text into the page.
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

// adminWarnings are notices that report an action was NOT taken. They share
// the ?done= parameter and are shown in the error style.
var adminWarnings = map[string]string{
	"member-invalid": "The member has not been added. Enter a full email address, such as name@example.org.",
}

// redirectDone sends the browser back to path after an admin action, carrying
// a notice code and, for the Groups page, the group to show expanded.
func redirectDone(w http.ResponseWriter, r *http.Request, path, done, group string) {
	q := url.Values{"done": {done}}
	frag := ""
	// Only a well-formed group name goes into the Location header.
	if group != "" && authz.ValidGroupName(group) {
		q.Set("open", group)
		frag = "#g-" + group
	}
	http.Redirect(w, r, path+"?"+q.Encode()+frag, http.StatusFound)
}
