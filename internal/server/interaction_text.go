package server

// The strings added by the interaction pass of 15 November 2026. None of them
// has been approved yet: each is kept here, once, so that the wording can be
// changed in one place.

// A person added in a role's picker is shown on the role's row as a pending
// addition. The status line in the picker says so once the person is added.
const msgPersonPending = "%s will hold this role once you save the changes."

// The end date of a pending person, in the person's token on the role row.
const msgPersonUntil = "until %s"

// The plus token on a role row. It replaces "Give this role to a group, a
// list or a setting", since a person is now added from the same picker.
const msgAddTokenTitle = "Give this role to a group, a list, a setting or a person"

// The picker's link to the invitation form, which preselects the role.
const msgPickerInvite = "Invite by email"

// The wording of a refused person, which the app page has always used. Kept
// here so the picker's script and the server say the same thing.
const (
	msgPersonNotAddress = "The person has not been added. Enter a full email address, such as name@example.org."
	msgPersonBadDate    = "The person has not been added. Enter the end date as a day, month and year."
	msgPersonPastDate   = "The person has not been added, because the end date has passed."
)
