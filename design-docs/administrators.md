---
title: Administrators
summary: How the admin tier is granted, how its second factor is issued and checked, and what the admin pages can change and record.
weight: 4
lastmod: 2026-11-04
---

## Who is an administrator

An administrator is an address on a fixed list in the gateway's settings. The
list is an exact list of addresses, not a domain, and no admin page can add to
it. Removing an address from the list takes effect at that person's next
session renewal on the tools, and on their very next request to the admin
pages, which check the current list every time.

Only a normal sign-in can hold the admin tier. A break-glass session or a
guest session is never treated as an administrator, whatever groups it
carries.

## The second factor

An emailed code is only as safe as the inbox it is sent to, so the gateway
can require administrators to take a second step as well: a six-digit code
from an authenticator app, or a passkey that stands in for one. The second
factor is on for the department's server.

Administrators sign in exactly as staff do, with an emailed code or a
passkey, and every site that admits staff opens for them at once. The second
step is asked for only at the admin door, which an administrator reaches by
opening the admin pages or a site restricted to administrators. Until then,
the sites see an administrator as an ordinary member of staff: the `admin`
group reaches a site only after the second step.

The second step lasts twelve hours, however long the session lasts. After
twelve hours, the `admin` group leaves the sites at the next request and the
admin door asks again; with a passkey, that is a single check of the face,
fingerprint or PIN. Removing an address from the administrators' list also
takes the `admin` group away at the next request.

Administrators do not set up their own second factor. If a sign-in could set
one up, whoever controlled the inbox could set it up, which would defeat its
purpose. The first administrator's secret is created with a command run on
the server. After that, a signed-in administrator creates or resets a
colleague's secret on the admin pages, where it is shown once to be passed on
in person. An administrator with no secret still signs in as staff, and the
admin door asks another administrator to set one up.

The person who creates a secret sees it once, and so could in principle act
as that administrator. Administrators are therefore trusted equally, as they
already are by their power to issue break-glass cards.

The gateway checks the authenticator code with these limits:

- Five wrong codes for one administrator within fifteen minutes lock that
  account for the rest of the period.
- Each attempt is recorded before the code is checked, so many attempts
  arriving together cannot all be checked before any is counted.
- If the gateway cannot record an attempt, it does not check the code, and
  the administrator is asked to try again shortly.
- A code that has been accepted once is refused if it is presented again,
  so that a code seen over someone's shoulder cannot be reused.

When the second factor is first turned on, administrators who are already
signed in lose the `admin` group at their next request and keep their access
as staff. A session from before the change, or from before a person became an
administrator, does not carry the second step, so the admin door asks for it.

## The admin pages

The admin pages sit on the gateway's own host.

| Page | What an administrator can do there |
|---|---|
| Groups | Create groups and manage their members |
| Break-glass | Issue, revoke and reissue cards, and download each card's printable PDF |
| Access log | See sign-in attempts and which tools each person reached |
| Audit | See every change made on the admin pages and who made it |
| Two-factor | Create, reset or remove administrators' authenticator secrets |
| Branding | Set the logos and the wording and colours of the printed cards |
| Settings | Change the break-glass session length and who is notified when a card is used |

The pages contain no scripts, and the gateway's content policy forbids
scripts from running on them. Every change requires a form token that is
bound to the administrator's own session, so another site cannot submit a
change on an administrator's behalf.

Every change is recorded with the administrator who made it, what changed,
their network address and the time. The access log keeps one row per person,
tool and hour rather than one per request. Both records are kept for one year
and then deleted.
