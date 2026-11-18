---
title: Passkeys
summary: How a person signs in on their phone, or on their own computer, with a passkey instead of an emailed code, and the rules that keep a passkey as safe as the sign-in it replaces.
weight: 4
lastmod: 2026-11-18
---

## What a passkey changes

A passkey lets a person sign in on their phone without an emailed code. The
phone keeps a private key for the sign-in host, and unlocks it only after
checking the person's face, fingerprint or PIN. The gateway keeps only the
matching public key. A passkey cannot be guessed, phished or replayed, and the
face, fingerprint and PIN never leave the phone.

The department's computers cannot hold passkeys, so the gateway never offers
one on a computer unasked. A computer continues to use the emailed code, and
the sign-in page shows nothing new there.

A person may add a passkey on their own computer, held by the computer itself
and unlocked with Touch ID, Windows Hello or the computer's PIN. The passkeys
page offers one on a computer only when the person chooses to add it, and
first warns them to do so only on a computer that nobody else signs in to. If
the browser has no such check, the page says so and offers nothing. The
gateway refuses a passkey that the browser saved on a phone instead, and it
never asks a computer to fetch a passkey from a phone. Only a computer that
already holds one of the person's passkeys is asked for it at sign-in.

Passkeys are built but switched off. Each server turns them on with one
setting, so the department's server can try them before the data lab's other
servers do.

## Adding a passkey

A person signs in on their phone with an emailed code as before. The gateway
then offers to add a passkey, and the person can decline. The offer comes
after every sign-in with an emailed code on a phone, so a person who
declined can add one the next time. Their passkeys page lists each passkey
with the kind of device it was added on, the date it was added and when it was
last used, and a passkey can be removed there. If a
person loses a phone, they remove its passkey and sign in with an emailed code
until they add a new one. Whenever a passkey is added, the gateway emails the
person to say so, with the date, the time and the kind of phone, and a link to
their passkeys page.

Adding a passkey needs a sign-in with an emailed code within the last fifteen
minutes. A sign-in with a passkey does not count, so a thief holding one
passkey cannot add a passkey of their own that would survive the stolen one
being removed. A person whose sign-in is older is asked to sign in again
before a passkey is added.

A guest, a break-glass session and an address the allow-list no longer
permits cannot add a passkey.

## Administrators

A passkey counts as two factors on its own: the phone, and the face,
fingerprint or PIN check that unlocks it. An administrator who signs in with
an admin passkey therefore has the second step already, and the admin door
offers that passkey first on a phone.

An administrator can add an admin passkey only after an authenticator code.
The offer comes at the admin door, straight after the code, rather than after
signing in. An administrator whose second step is not recent enters an
authenticator code on the passkeys page first, and the phone makes the
passkey only once the code has been accepted.

A passkey added before its owner became an administrator, or while the second
factor was switched off, gives an ordinary session, and the admin door asks
for the code. After the code, the door offers to add a new passkey on the
phone. Made for the same account, it replaces the older one there, and it
opens the admin pages by itself from then on. The gateway never upgrades the
older passkey in place, because the session that names it could have been
planted in the browser by another site on the domain.

An administrator who loses every passkey still signs in with an emailed code
and takes the second step with an authenticator code.

## Ending access

A session started with a passkey names that passkey. When the passkey is
removed, the session ends at its next request, on the tools as well as the
admin pages. A person removes their own passkeys on their passkeys
page, and the gateway emails them each time, as it does when a passkey is
added. An administrator removes all of one person's passkeys on that person's
access page, and the removal is recorded in the admin audit.

Sessions started with an emailed code can be ended too: the person, or an
administrator, can sign them out on every device, as
[Signing in](signing-in.md) describes.

## The rules the gateway enforces

- **A passkey belongs to the sign-in host alone.** It is bound to
  `auth.rch-anaesthesia.org`, not to the whole domain, so another tool on the
  domain cannot ask the phone to use it.
- **Each sign-in answers a fresh challenge.** The challenge expires after ten
  minutes and can be used once.
- **The phone must check the person.** A passkey that was used without the
  face, fingerprint or PIN check is refused. The same holds on a computer.
- **A computer's passkey is held by the computer.** The gateway asks the
  browser for a passkey kept on the computer, and refuses one that the browser
  reports was saved on a phone over Bluetooth or a QR code, or on a security
  key.
- **The rules are checked again at every passkey sign-in.** A passkey does not
  let in an address the allow-list no longer permits, and it never makes a
  guest.
- **Only one kind of key is accepted.** The gateway accepts the P-256 keys that
  Apple's and Google's passkeys use, and nothing else. It asks the phone for no
  proof of its make or model, so the gateway's checks are short enough to read
  in full.

## The one script

A passkey sign-in needs a script in the page, which asks the phone to use the
passkey. The sign-in pages had no scripts before passkeys, and the gateway's
content policy forbade them. With passkeys on, the pages that use a passkey
load one script from the gateway itself, and the content policy on those pages
allows that script and no other. Every other page still forbids scripts. The
script makes no requests of its own: it puts the phone's answer into an
ordinary form, and the gateway checks everything.

## Accepted

The gateway asks the phone for no proof of what made a passkey, as is usual
for passkeys. A program that has stolen a person's session cookie within
fifteen minutes of their sign-in could therefore register a key of its own,
which would then work until it is removed. The gateway emails the person
whenever a passkey is added, so they would be told, and their passkeys page
and the access page would list it.

The browser's report of where it saved a passkey is not signed, so the
refusal of a passkey saved on a phone guards against a mistaken choice in the
browser, not against a program that has stolen a session cookie. That program
could already register a key of its own, as the paragraph above describes.

A passkey on a computer is only as safe as the computer. Anyone who can unlock
the computer can sign in as its owner, which is why the gateway adds one only
when the person asks, after warning them.

A passkey is only as safe as the phone and the account it syncs to. Anyone who
can unlock the person's phone, or who controls the Apple or Google account
that holds the passkey, can sign in as that person. That is the same trust a
person already places in their phone for their email, and an emailed code
gives no more protection against it.
