package server

import "strings"

// Wording from the UI/UX review, approved on 13 November 2026. Each string
// is kept here, once.

// Too many incorrect codes: on the invitation's code page and on the
// sign-in code page.
const (
	msgInviteCodeTooMany = "The code was entered incorrectly too many times, so we will not accept it. If you still want to accept the invitation, send a new code."
	msgLoginTooMany      = "The code was entered incorrectly too many times, so we will not accept it. Enter your email address again, and we will send you a new code."
)

// The sign-in page at a role guard: the hint from the role's domain groups,
// and the early decline where those groups are its only holders. Each %s is
// the domains joined with "or"; the decline's second names them with their
// article ("an rch.org.au").
const (
	msgRoleHint      = "If you have an %s email address, sign in with that address."
	msgDeclineDomain = "This app admits only %s email addresses. If you have %s address, sign in with that address."
)

// The page for a card the gateway does not know or that is not active.
const (
	msgCardUnknownTitle = "This card does not work"
	msgCardUnknownBody  = "We do not recognise this card. If you need access now, you can contact an administrator for assistance."
	msgCardUnknownLink  = "Sign in"
)

// The design editor's save bar: %s is "three cards" or "one card".
const msgDesignSaveNote = "Saving the design changes the look of %s. The printed cards keep working, and you can reprint them in the new design."

// The new-card form's pages, and the refusal when an app names none.
const (
	msgCardNoPagesApproved = "The app's snippet names no page for a scan to open."
	msgCardChooseAppFirst  = "Choose an app first. Its snippet names the pages a scan can open."
	msgCardPagesHint       = "The app's snippet names the pages a scan can open. A card holds the User role in %s, so its holder can reach every page that role reaches, but never an administrator's page or another app."
)

// withArticle is "an rch.org.au" or "a gosh.nhs.uk": the article as the
// first letter of a domain is read aloud, by its letter name.
func withArticle(domain string) string {
	label := strings.ToLower(domain)
	if i := strings.IndexByte(label, '.'); i >= 0 {
		label = label[:i]
	}
	if label == "" {
		return "a " + domain
	}
	// A first label of four letters or fewer, such as rch, mcri or svha, is
	// read letter by letter, so its article follows the first letter's name
	// ("an rch.org.au", "a uq.edu.au"). A longer one is read as a word: "an"
	// before a vowel sound, which a leading u rarely is ("a unimelb.edu.au").
	initialism := len(label) <= 4
	if initialism && strings.ContainsRune("aefhilmnorsx", rune(label[0])) ||
		!initialism && strings.ContainsRune("aeio", rune(label[0])) {
		return "an " + domain
	}
	return "a " + domain
}
