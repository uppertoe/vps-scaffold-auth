package server

// The strings added by the UI/UX fixes of 13 November 2026. None of them has
// been approved yet: each is kept here, once, so that the wording can be
// changed in one place.

// The Until cell of a person whose end date has passed, on an app's page.
const msgPersonEnded = "Ended %s"

// Withdrawing or resending an invitation is confirmed first, on the
// Invitations page and on an app's page (?withdraw=id, ?resend=id).
const (
	msgWithdrawConfirm = "Once the invitation is withdrawn, its link stops working, and %s is not given the role."
	msgWithdrawButton  = "Withdraw the invitation"
	msgWithdrawKeep    = "Keep the invitation"
	msgResendConfirm   = "Resending the invitation emails %s a new link, and the earlier link stops working at once."
	msgResendButton    = "Resend the invitation"
)

// The visible control at the foot of the app page's picker, which closes it.
const msgPickerDone = "Done"

// The Overview's tile that counts the active cards, in the cards' own
// vocabulary (it read "Active break-glass codes").
const msgActiveCardsTile = "Active break-glass cards"

// Removing a domain from a domain group is confirmed first (?remove=domain).
// The first sentence names the roles and apps; the second says what
// removing the domain does to them.
const (
	msgDomainRemoveHolds  = "%s holds %s, in %s."
	msgDomainRemoveLast   = "Once @%s is removed, the group will admit nobody, and nobody at @%s will hold those roles through %s."
	msgDomainRemoveSome   = "Once @%s is removed, nobody at @%s will hold those roles through %s."
	msgDomainRemoveNoRole = "%s holds no role yet, so removing @%s changes nobody's access."
	msgDomainRemoveButton = "Remove @%s"
	msgDomainRemoveKeep   = "Keep the domain"
)

// A domain group without an organisation name, in the Groups list's
// Organisation name column.
const msgNoOrgName = "No organisation name"

// The group's display name is called its name on every page: the group
// page's field and its button, and the notice once it is saved. The
// organisation name's button names its field, as both sit on one page.
const (
	msgNameHeading   = "Name"
	msgNameButton    = "Save the name"
	msgNameSaved     = "The name has been saved."
	msgOrgButtonFull = "Save the organisation name"
)

// groupNameCopy is the group page's name field's wording, for the template.
type groupNameCopy struct{ Heading, Button string }

var groupNameText = groupNameCopy{Heading: msgNameHeading, Button: msgNameButton}

func init() {
	adminNotices["label-saved"] = msgNameSaved
	orgNameText.Button = msgOrgButtonFull
}
