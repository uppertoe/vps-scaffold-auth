---
title: Security hardening
summary: The defences in one place, from refusing to start on a bad setting to the limits that keep one visitor from taking every tool offline.
weight: 7
lastmod: 2026-10-31
---

## Failing closed

The gateway's first rule is that when it cannot be sure, it refuses. Every
other defence on this page follows from that rule.

| Situation | What the gateway does |
|---|---|
| A setting is missing, malformed or unsafe | Refuses to start, naming the setting |
| The signing key is short or plainly not random | Refuses to start |
| Mail is set to go to the log, where codes could be read | Refuses to start unless the server is in local development mode |
| A tool's rule is missing or malformed | Shows every visitor the no-access page |
| A session is of a kind this version does not know | Clears it and asks the person to sign in |
| A second-factor attempt cannot be recorded | Does not check the code |
| The check for a recent code fails | Treats the address as having one, so that a fresh code cannot reset the guess count |
| A card's scan cannot be recorded | Grants no access |

Refusing to start matters most of these. A gateway that started with the
second factor quietly off, for example because a setting read "yes" instead
of "true", would look healthy while protecting less than its settings claim.

## The session cookie

The cookie is signed with HMAC-SHA256 and records the purpose it was made for,
so no other cookie the gateway issues can be presented in its place. It is
sent only over HTTPS and cannot be read by scripts in the page. The gateway
also tells browsers to use HTTPS for every host on the domain.

Because the cookie is shared across the domain, any tool on the domain could
plant a second cookie with the same name. The gateway refuses a request that
carries two, rather than guessing which one is genuine. A tool that
overwrites the real cookie outright cannot be detected, which is why the
[front page](_index.md) asks whether any tool should move to its own domain.

Caddy removes the cookie before a request reaches any tool, including tools
with public pages, so that a compromised tool never holds a credential that
would open the others.

## Between Caddy and the gateway

The gateway relies on three things that Caddy guarantees on every request.

- Caddy deletes any identity headers the browser sent, before the gateway is
  asked, so a tool sees only the gateway's answer.
- Caddy replaces any copy of the rule header the browser sent with the rule
  from the tool's own route.
- Caddy records the visitor's real network address, and the gateway reads
  only the entry that Caddy wrote. A visitor therefore cannot pose as a new
  address on every request to escape the limits.

A public route has no guard, so Caddy removes the session cookie and any
identity headers the browser sent from those requests too. An app with a
public path therefore never sees a forged identity on it.

Every change to the gateway is tested end to end before an image is
published. The tests run the production version of Caddy with these guards,
in front of the image built from the change, and check what reaches the
browser and what reaches the app. Each assumption the chain relies on, and
the test that proves it, is listed in the repository's security register.

## The pages

The sign-in and admin pages contain no scripts, and the gateway's content
policy forbids scripts, frames and outside resources. Forms may be sent only
to the gateway itself and to hosts on the server's domain. The pages send no
referrer and are never cached. Uploaded images are served with a policy that
stops them from acting as a page, so a malicious image cannot run code even
if a browser tries to open it.

## Keeping the gateway available

Every request to every protected tool passes through the gateway, so a
visitor who can exhaust it takes every tool offline at once. The container
has 128 MB of memory, and three reviews in October 2026 found ways an
anonymous visitor could use it up. The gateway now applies these limits.

| Limit | Why |
|---|---|
| A sign-in form may be at most 64 KB, and a larger one is refused before it is read | A few oversized anonymous forms could fill the container's memory |
| Request headers may be at most 64 KB | Every request's headers reach the gateway |
| Each request has deadlines for arriving and being answered | A slow client cannot hold a connection open |
| The sign-in logo is cached in memory and in browsers | Requests for the logo competed with every tool's checks for the database |
| An upload may be at most 2 MB, and a PNG or JPEG image at most 1,000 pixels on a side | Larger images are costly to decode when a card is printed |
| Uploaded PNG images are decoded and re-encoded before storage | A 203 KB file was found that expanded to 448 MB while a card was being built |
| Uploaded SVG images are checked for constructs that expand, and refused if they contain them | A 1 KB file was found that expanded to 3 GB |

## Mail and notifications

The gateway sends codes only over an encrypted connection. If the mail server
does not offer encryption, the gateway refuses to send rather than send the
code in the clear. Every send has a deadline, and the email is built and sent
after the sign-in page has answered.

Break-glass notifications can go to a web address chosen by an administrator.
The gateway refuses to connect to its own host, to cloud metadata addresses
and to other addresses that should never receive a notification, and it does
not follow redirects. Line breaks are removed from every email header, so a
card's label cannot be used to add headers to a notification.

## The container

The gateway runs in a minimal image that contains the program and nothing
else: no shell and no package manager. It runs as an unprivileged user, with
every Linux capability removed and a read-only filesystem apart from its data
volume. It has limits on memory and processes, publishes no port, and shares
a network only with Caddy.

## Releases

Every change is checked before an image is published. The checks run the
tests with Go's race detector, scan the dependencies for known
vulnerabilities, and start the built image to confirm that it serves its
health check. The base images and the build tools are pinned to exact
versions, and Renovate proposes updates to them. The image is also rebuilt
every week, so that fixes to the base image reach the servers without a code
change. Each server pins the image it runs by digest.

## What the gateway does not protect against

- A person who controls a staff member's inbox can sign in as that staff
  member, because ordinary staff have no second factor.
- A stolen session cookie works until it expires, or until the person loses
  their listing and the session next renews.
- Anyone who photographs a break-glass card can use it within the limits
  [Break-glass cards](break-glass-cards.md) describes.
- A tool on the same domain can overwrite the session cookie.
- Anyone with control of the server itself can read the keys and act as
  anyone.
