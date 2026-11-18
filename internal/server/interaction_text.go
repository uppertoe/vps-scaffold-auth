package server

// The strings added by the interaction pass of 15 November 2026. None of them
// has been approved yet: each is kept here, once, so that the wording can be
// changed in one place.

// A person added in a role's picker is shown on the role's row as a pending
// addition. The status line in the picker says so once the person is added.
const msgPersonPending = "%s will hold this role once you save the changes."

// The end date of a pending person, in the person's token on the role row.
const msgPersonUntil = "until %s"

// The title of a role row's Add token. It replaces "Give this role to a
// group, a list or a setting", since a person is now added from the same
// picker.
const msgAddTokenTitle = "Give this role to a group, a list, a setting or a person"

// The picker's link to the invitation form, which preselects the role.
const msgPickerInvite = "Invite by email"

// The overview's sentence when the address checked is not a full address.
const msgCheckNotAddress = "%s is not a full email address. Enter an address such as name@example.org."

// The wording of a refused person, which the app page has always used. Kept
// here so the picker's script and the server say the same thing.
const (
	msgPersonNotAddress = "The person has not been added. Enter a full email address, such as name@example.org."
	msgPersonBadDate    = "The person has not been added. Enter the end date as a day, month and year."
	msgPersonPastDate   = "The person has not been added, because the end date has passed."
)

// The strings added by the picker fixes of 18 November 2026, whose wording
// the owner has seen.

// The labels of a role row's token that opens its picker: one for a role
// nobody holds, and one for a role that has holders.
const (
	msgGiveToken = "Give this role"
	msgAddToken  = "Add"
)

// The changes bar while nothing is unsaved. It names the two labels above.
const msgChangesNone = "Choose Give this role or Add on a role to give it to a group, a list or a person, or the × beside one to take it away. Nothing is saved until you review the changes."

// A picker that has no domain group or list to offer says so, and links to
// the Groups page's new-group form; %s is the link, whose words are
// msgPickerGroupsPage. A picker that offers some has a quiet link to the
// same form, msgPickerNewGroup, at the foot of its group sections.
const (
	msgPickerNoGroups   = "No group can be chosen yet. You can create a domain group or a list on the %s."
	msgPickerGroupsPage = "Groups page"
	msgPickerNewGroup   = "New group"
	newGroupHref        = "/admin/groups/new"
)
