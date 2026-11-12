package server

import "github.com/uppertoe/vps-scaffold-auth/internal/store"

// The strings added in phase 2d, kept together here until they are
// approved. PROPOSED: every string in this file.

// A domain group's organisation name, on the group page and the new-group
// form, and in the audit log.
const (
	msgOrgLabel  = "Organisation name"
	msgOrgHint   = "The name a person sees when a break-glass card asks them to sign in instead, such as RCH. Leave it empty to leave the group out of that sentence."
	msgOrgButton = "Save the name"
	msgOrgSaved  = "The organisation name has been saved."
	msgOrgAudit  = "Organisation name changed"
)

// orgNameCopy is the organisation-name field's wording, for the templates.
type orgNameCopy struct{ Label, Hint, Button string }

var orgNameText = orgNameCopy{Label: msgOrgLabel, Hint: msgOrgHint, Button: msgOrgButton}

func init() {
	adminNotices["org-saved"] = msgOrgSaved
	adminActionLabels[store.AdminActionGroupOrg] = msgOrgAudit
}
