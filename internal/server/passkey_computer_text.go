package server

// The strings added for passkeys on a person's own computer, approved on 18
// November 2026. Each is kept here, once. msgPkComputerOnNetwork, added
// later the same day, awaits approval.

// The passkeys page on a computer. The intro and the button are shown first;
// the warning, the button again, and "Not now" once the person has chosen to
// add one (?add=computer).
const (
	msgPkComputerIntro       = "If this computer is your own and nobody else signs in to it, you can add a passkey on it. You will then sign in on this computer with Touch ID, Windows Hello or the computer's PIN instead of an email code."
	msgPkComputerAdd         = "Add a passkey on this computer"
	msgPkComputerWarning     = "Add a passkey only on a computer that nobody else signs in to. Anyone who can unlock this computer will be able to sign in to your account."
	msgPkComputerUnavailable = "This browser cannot keep a passkey on this computer, because it has no Touch ID, Windows Hello or similar check to use. You can still sign in with an email code."
	msgPkComputerExists      = "This computer already has a passkey for your account."
	msgPkComputerLost        = "If you lose a phone or computer, or stop using one, remove its passkey here. You can still sign in with an email code."
)

// A computer on a network in NETWORK_RANGES may not add a passkey. This is
// shown in place of the offer and as the refusal; %s is the network as
// NETWORK_RANGES names it ("RCH network"). The rule is the owner's, 18
// November 2026; the wording awaits approval.
const msgPkComputerOnNetwork = "A passkey cannot be added on a computer on the %s. You can add one on your own computer when it is not connected to that network."

// The refusal of a passkey that the browser saved on another device, such as
// a phone over Bluetooth or a QR code, when it was asked for one held by this
// computer. The page's title is the approved "Your passkey has not been
// added".
const msgPkComputerRefused = "The browser saved the passkey on another device, such as a phone, rather than on this computer, so we have not added it. If you want a passkey on this computer, try again and choose this computer when the browser asks where to save it."

// The page after a passkey is added on a computer. The second follows the
// approved "Signed in as …".
const (
	msgPkComputerAdded    = "A passkey has been added to this computer."
	msgPkComputerNextTime = "Next time, choose your passkey when the browser offers it on the sign-in page."
)

// The kind of device in each row of the passkeys page: "This …" for the
// passkey this device holds, as far as the gateway can tell.
const (
	msgPkThisPhone    = "This phone"
	msgPkThisComputer = "This computer"
	msgPkAPhone       = "A phone"
	msgPkAComputer    = "A computer"
)

// The Device column of a person's passkeys on the admin access page.
const (
	msgPkDeviceHeading  = "Device"
	msgPkDevicePhone    = "Phone"
	msgPkDeviceComputer = "Computer"
)

// The name given to a passkey added on a computer whose provider is not
// recognised, and the device named in the notice emails ("…, on a Mac.").
const (
	msgPkLabelMac      = "Passkey on a Mac"
	msgPkLabelWindows  = "Passkey on a Windows computer"
	msgPkLabelComputer = "Passkey on a computer"
	msgPkNoticeMac     = "a Mac"
	msgPkNoticeWindows = "a Windows computer"
	msgPkNoticeOther   = "a computer"
)

// passkeyText carries the strings above into the templates.
type passkeyText struct {
	Intro, Add, Warning, Unavailable, Exists, Lost, Added, NextTime string
}

var pkText = &passkeyText{
	Intro:       msgPkComputerIntro,
	Add:         msgPkComputerAdd,
	Warning:     msgPkComputerWarning,
	Unavailable: msgPkComputerUnavailable,
	Exists:      msgPkComputerExists,
	Lost:        msgPkComputerLost,
	Added:       msgPkComputerAdded,
	NextTime:    msgPkComputerNextTime,
}
