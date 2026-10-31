---
title: Signing in
summary: The emailed code, the limits on guessing it, what the sign-in page reveals, how long a session lasts and where a person lands afterwards.
weight: 2
lastmod: 2026-10-31
---

## The code

A person enters their email address, and the gateway emails them a code to
type in. On the department's server the code has eight digits, and the
gateway refuses any setting below six. A code lasts ten minutes and can be
used once. The email puts the code in its subject line, so that phones can
offer to fill it in.

The gateway stores only a keyed hash of each code. A copy of the database
therefore reveals no live code, and the code cannot be worked out from the
hash without the gateway's key.

## Limits on guessing

On the department's server, ten wrong guesses at one code, from anywhere,
destroy the code. With eight digits, an attacker's chance of guessing a given
code is about one in ten million. The other limits stop one network or one
attacker from wearing down the defences or flooding an inbox.

| Limit | Gateway default | What it prevents |
|---|---|---|
| Wrong guesses at one code from one network | 5 | One network guessing at a code until it is destroyed for its owner |
| Wrong guesses at one code from all networks | 50 (10 on the department's server) | Many networks sharing out the guessing |
| Wrong codes from one network, across all addresses | 60 in 15 minutes | Guessing spread across many people's codes |
| Code requests from one network | 60 in 15 minutes (300 on the department's server) | Scripted requests from one place |
| Codes sent to one address from one network | 5 in 15 minutes | A stranger spending the owner's allowance |
| Codes sent to one address from all networks | 12 an hour | A distributed flood of one inbox |
| Codes sent from one network, across all addresses | 60 an hour (120 on the department's server) | Mail that would damage the sending account's reputation |

The limits are shaped around the hospital's network. Many staff reach the
server from one public address, so the limits per network are generous and a
correct code costs nothing against them. An address that has signed in
successfully from the same network in the past thirty days passes the two
sending ceilings, so an attacker who floods an address cannot lock its owner
out from their usual network.

A second request for a code within a minute of the first does nothing. The
existing code and its count of wrong guesses are kept, so refreshing the page
or opening a new tab cannot reset the count.

## What the sign-in page reveals

The sign-in page answers in the same way whether or not an address is
allowed. For an address that is not allowed, the gateway stores a code that is
never sent, so the step that follows behaves identically, down to the count of
wrong guesses. The email is sent after the page has answered, so the time
taken does not reveal the difference either.

One exception is deliberate. If a tool's rule names a domain, the sign-in
page says so, and it declines an address at another domain before sending a
code. The person is then not emailed a code that would be refused after they
had used it. The domain a tool requires is not a secret, and the rule itself
is enforced afterwards on every request.

## The sign-in forms

The gateway accepts the sign-in forms only from its own page. Every tool on
the department's domain counts as the same site, and browser cookie rules do
not separate one site's hosts from each other. Without this check, a
compromised tool could drive a visitor's browser through the sign-in steps
with a code its operator had requested, leaving the visitor signed in as
someone else. The gateway therefore refuses a form that the browser reports
as coming from another host.

The first version of this check refused the literal origin `null`, which
mobile browsers send for the sign-in page's own forms under its privacy
settings. On 11 October 2026 it stopped every mobile sign-in on two of the
data lab's servers until the release was rolled back. The check now relies on
the browser's separate report of whether a request is from the same host,
and every change is tested against nine recorded header patterns from real
desktop and mobile browsers. Older versions of Safari do not send that
report, and the remaining risk with them is accepted: another site can make
such a browser sign out or start a sign-in, but cannot complete one.

## How long a session lasts

A session lasts two hours by default, or twenty-four hours if the person ticks
"Keep me signed in". On the department's server the two lifetimes are twelve
hours and thirty days.

A session in use renews itself, every hour by default and every six hours on
the department's server. At each renewal the gateway checks the person against
the current rules and recalculates their groups. A person whose domain or
admin listing has been removed is signed out there, and a change to their
groups takes effect from that point. Renewal checks the rules, not the
mailbox, which is why the [front page](_index.md) lists an absolute limit
among the open decisions.

A guest is never given the longer lifetime, and a break-glass session never
renews. [Who can reach what](who-can-reach-what.md) and
[Break-glass cards](break-glass-cards.md) explain why.

## Signing out

Signing out ends the session for every tool on the domain. The gateway asks
for confirmation first, so a link alone cannot sign anyone out.

## Where a person lands

After signing in, a person returns to the page they asked for, provided it is
an `https` address on the server's own domain. Any other destination,
including an address on another site, is replaced with the gateway's own
signed-in page. The sign-in page therefore cannot be used to send someone to a
look-alike site after they have entered a code.
