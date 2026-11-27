---
title: Break-glass cards
summary: Emergency access by QR code, how each card is limited to one app, how its use is recorded and announced, and the risk accepted with it.
weight: 5
lastmod: 2026-11-19
---

## What a card is for

A break-glass card is a laminated QR code left in a known place, such as an
angiography lab or a resuscitation bay. It lets someone who cannot otherwise
sign in reach a particular app during a time-critical event. Scanning the
card opens a page with one button, and pressing it grants access at once,
with no email and no second factor.

## The accepted risk

The QR code is the only credential, and the card sits in the open. Anyone who
photographs a card can use it. The department accepts this risk because the
alternative is a clinician locked out during an emergency. The risk is limited
by the controls on the rest of this page: each card opens one app as an
ordinary user, its sessions are short, every use is recorded and announced,
and a card can be withdrawn at once.

## What a card can reach

A card opens one app's User role. Whoever scans it reaches every path that the
User role opens in that app, and never an administrator's path or another
app. Because the person carrying a card is not identified, a card can never
hold any other role. Each scan lands on one of the pages that the app's
snippet names for cards, chosen when the card is made.

A card can never grant the admin tier, because the admin pages refuse
break-glass sessions outright. A card's label cannot pass for an email
address at a domain either: the gateway never reads a domain from a
break-glass session, so a label such as `ops@rch.org.au` satisfies no domain
group.

## Cards made before app roles

A card made before app roles opens the sites of one group, as it always did.
Such a card cannot name a staff-only list, a group that a staff-only list
includes, or a group filled from a feed. A card whose list has become staff
only since the card was made grants nothing: the person scanning it sees the same page as for a withdrawn card,
the scan is recorded as refused, and the chosen administrators are notified.

An administrator can move a card of this kind onto an app whose site now uses
the role guard. The card keeps its code, so the printed copies keep working,
and from then on a scan opens the app's User role. A session started before
the move keeps only the group's sites until it ends. Once every site that a
group opened uses the role guard, a card for that group opens nothing until it
is moved.

## How long access lasts

A break-glass session lasts eight hours by default, and the gateway will not
allow more than twelve. It never renews, so it always ends at that time.

## What happens on each scan

| Step | What the gateway does |
|---|---|
| On opening the card's address | Shows a page with one button and grants nothing. Chat apps, link previews and mail scanners such as Safe Links fetch an address on their own, so a shared card's address starts no session and sends no notification. The visit is recorded as viewed. |
| Before granting | Writes the scan to the record: the card, the network address, the browser and the time. If the record cannot be written, no access is granted. |
| While granting | Notifies the chosen administrators by email, by a web notification, or both. The notification never delays access. |
| After granting | Sends the person to the card's page. |

Scans are limited per network address, more generously than sign-ins, so that
many staff behind one hospital address can scan at once. The limit is not what
protects a card. Each card's code is 128 random bits, so it cannot be guessed.

The card's code travels in the scanned address, so the server leaves those
requests out of its access log, and the code is never written to disk there.
The button sends the code in the body of a form, which the gateway accepts
only from its own pages, so another site cannot press it on someone's behalf.
The browser's history still holds the code, which is inherent to a card that
can be scanned.

## A person who is already signed in

If someone scans a card while already signed in as themselves, the gateway
keeps their own session and sends them to the card's page on it. Their own
access may be enough, and replacing it with a narrower emergency session would
cut them off from their other apps. If the app then refuses them, the no-access
page offers emergency access in one tap, without a second scan.

The one-tap offer is protected in three ways. It needs a form token that
another site cannot obtain. It works only while the person's own session is
still live. The gateway also checks again that the card is still active
before granting anything.

## Withdrawing a card

An administrator can withdraw a card, which refuses every later scan at once
and ends the sessions the card has granted. An administrator can also replace
an active card with a new code, which makes every printed copy of the old card
useless and ends its sessions in the same way. A withdrawn card cannot be
replaced and brought back. A scan of a withdrawn or unknown card shows the
same neutral page, and a scan of a withdrawn card is still recorded.

## The printed card

Each card has a printable PDF with its QR code and the place where the card
will be kept. The card's design sets its colours, logo, wording and printed
size, and administrators manage the designs on the break-glass pages. A
card's note for administrators is never printed. The gateway checks every uploaded image before it is stored and again
before it is printed, as [Security hardening](security-hardening.md) describes.
