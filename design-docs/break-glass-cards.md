---
title: Break-glass cards
summary: Emergency access by QR code, how each card is limited to the tools it names, how its use is recorded and announced, and the risk accepted with it.
weight: 5
lastmod: 2026-10-31
---

## What a card is for

A break-glass card is a laminated QR code left in a known place, such as an
angiography lab or a resuscitation bay. It lets someone who cannot otherwise
sign in reach a particular tool during a time-critical event. Scanning the
card grants access at once, with no email and no second factor.

## The accepted risk

The QR code is the only credential, and the card sits in the open. Anyone who
photographs a card can use it. The department accepts this risk because the
alternative is a clinician locked out during an emergency. The risk is limited
by the controls on the rest of this page: each card reaches only the tools it
names, its sessions are short, every use is recorded and announced, and a card
can be withdrawn at once.

## What a card can reach

Each card names one group, and a card's session reaches only a tool whose
rule lists that group. A tool with the plain "any signed-in person" rule
refuses it, and so does a tool that requires a domain. An administrator
therefore opens each location's card to exactly the tools it needs, and a
separate group for each card gives the narrowest scope.

A card can never grant the admin tier, because the three role names cannot be
used as a card's group and the admin pages refuse break-glass sessions
outright. A card's label cannot pass for an email address at a domain either:
the gateway never reads a domain from a break-glass session, so a label such
as `ops@rch.org.au` satisfies no domain rule.

## How long access lasts

A break-glass session lasts eight hours by default, and the gateway will not
allow more than twelve. It never renews, so it always ends at that time.

## What happens on each scan

| Step | What the gateway does |
|---|---|
| Before granting | Writes the scan to the record: the card, the network address, the browser and the time. If the record cannot be written, no access is granted. |
| While granting | Notifies the chosen administrators by email, by a web notification, or both. The notification never delays access. |
| After granting | Sends the person to the card's tool. |

Scans are limited per network address, more generously than sign-ins, so that
many staff behind one hospital address can scan at once. The limit is not what
protects a card. Each card's code is 128 random bits, so it cannot be guessed.

The card's code travels in the scanned address, so the server leaves those
requests out of its access log, and the code is never written to disk there.
The browser's history still holds the code, which is inherent to a card that
can be scanned.

## A person who is already signed in

If someone scans a card while already signed in as themselves, the gateway
keeps their own session and sends them to the tool on it. Their own access
may be enough, and replacing it with a narrower emergency session would cut
them off from their other tools. If the tool then refuses them, the no-access
page offers emergency access in one tap, without a second scan.

The one-tap offer is protected in three ways. It needs a form token that
another site cannot obtain. It works only while the person's own session is
still live. The gateway also checks again that the card is still active
before granting anything.

## Withdrawing a card

An administrator can revoke a card, which refuses every later scan at once.
Sessions already granted run until their short lifetime ends. An
administrator can also reissue a card with a new code, which makes every
printed copy of the old card useless. A scan of a revoked or unknown card
shows the same neutral page, and a scan of a revoked card is still recorded.

## The printed card

Each card has a printable PDF with its QR code, title, instructions and logo,
which administrators set on the branding page. A card can override any of
these. The gateway checks every uploaded image before it is stored and again
before it is printed, as [Security hardening](security-hardening.md) describes.
