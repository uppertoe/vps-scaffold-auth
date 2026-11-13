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
