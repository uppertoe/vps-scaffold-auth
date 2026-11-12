package server

import "github.com/uppertoe/vps-scaffold-auth/internal/store"

// The strings added in phase 2d. Every string in this file was approved on
// 13 November 2026.

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

// The Invitations page's warning about an invitation the mailer refused,
// which closes it.
const msgInviteUndelivered = "The invitation to %s could not be delivered, so its link no longer works. Check the address, then send it again or withdraw it."

// The invitation's own code page, after Send the code.
const (
	msgInviteCodeTitle  = "Enter the code"
	msgInviteCodeBody   = "We have sent a code to %s. Enter it here to accept your invitation to %s."
	msgInviteCodeButton = "Accept the invitation"
	msgInviteCodeLate   = "If the code has not arrived after a few minutes, check your junk folder, then send a new code."
	msgInviteNewCode    = "Send a new code"
	msgInviteWrongCode  = "That code is not right. Check the latest email from us, then try again."
)

func init() {
	adminNotices["org-saved"] = msgOrgSaved
	adminActionLabels[store.AdminActionGroupOrg] = msgOrgAudit
}
