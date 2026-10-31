---
title: Reviews
summary: How the gateway has been reviewed since it was built in May 2026, what each review found, and what it changed.
weight: 8
lastmod: 2026-10-31
---

## How the gateway is reviewed

Since it was built in May 2026, the gateway has been reviewed adversarially on
the dates in the table below, several of them in successive rounds. In
each review, reviewers read the code and the Caddy guards as an
attacker would and reported what they could reach. Every finding was fixed
with a test that would have caught it, and the tests run on every change.

## What each review found

| Date | Significant findings | What changed |
|---|---|---|
| 1 June 2026 | A person removed from the rules kept renewing their session indefinitely. A break-glass card could be given an admin group. The sign-in page's response time revealed which addresses were allowed. | Renewal re-checks the rules and signs out anyone no longer allowed. Role names were reserved. Code emails are sent after the page has answered. Codes are stored as keyed hashes, and uploaded images are served so that they cannot act as pages. |
| 2 June 2026 | A visitor could defeat every limit per network by forging the forwarded address. Administrators set up their own second factor, so whoever held the inbox could do so. | The gateway reads only the address Caddy wrote. Second-factor secrets are issued by an administrator. Each tool's rule moved into one header that Caddy replaces. |
| 6 June 2026 | A card labelled like an email address satisfied a domain rule. A group name containing a comma could smuggle in the admin role. | The gateway never reads a domain from a card. Group names are restricted to plain characters. Card sessions are capped at twelve hours, and a used authenticator code is refused a second time. |
| 6 July 2026 | Codes could be sent unencrypted if the mail server did not offer encryption. Issuing a card left no record of who issued it. | Mail encryption became mandatory. Every admin change is recorded. Card codes are kept out of the server's log. Second-factor attempts are limited per account. A tool route that sends no rule is refused. |
| 11 October 2026 | Anyone could sign in as any allowed address without its code, by presenting the cookie given to anyone who asks for a code as a session. Guesses at a code were limited per network only. The admin pages trusted a session's groups until it expired. Renewed sessions never reached the browser. | Each cookie records its purpose, and every existing session was ended. Each code has an overall guess limit. The admin pages check the current list on every request. The Caddy guards were rewritten to pass renewals on. Sign-in forms must come from the gateway's own page. |
| 29 October 2026 | Three successive reviews found ways an anonymous visitor could exhaust the gateway's memory, and so take every tool offline: oversized forms, floods of logo requests and images that expand when decoded. Send limits could be used up by a stranger. | The limits listed under [keeping the gateway available](security-hardening.md) were added, and the send limits were reshaped around the hospital's network. |
| 31 October 2026 | The server's [review](../server/security-reviews.md) examined the login wall as one of five areas and found no way in from outside. | No change was needed. |
| 31 October 2026 | A pass tested every assumption the chain relies on, through the production version of Caddy. It found that a public route passed identity headers sent by the browser on to its app. | Public routes now remove those headers. Every assumption is listed with the test that proves it, each test was shown to fail when its protection was removed, and the whole chain is tested before every release. |

The finding of 11 October was the most serious in the gateway's history. When
it was fixed, every session in use was ended, so everyone signed in again
once.

## The outage of 11 October

The same-origin check added on 11 October refused the origin `null`, which
mobile Safari, Chrome and Firefox send for the gateway's own sign-in forms.
Every mobile sign-in failed on two of the data lab's servers until those
servers were rolled back to the previous release. The check was corrected
the same day, as [Signing in](signing-in.md) describes. Every change that
touches sign-in is now tested against recorded header patterns from real
browsers, and checked against the live servers before release.

## Risks accepted

These risks are known and have been accepted, each for the reason given on
the page that describes it.

- A photographed break-glass card can be used until it is revoked, within the
  scope of its group.
- Another site can make an older version of Safari sign out or start a
  sign-in, because that browser does not report where a form came from. It
  cannot complete a sign-in.
- One administrator can act as another, because the person who issues a
  second-factor secret sees it once.
- A stolen session works until it expires or the person's listing is removed.
