---
title: Administrators
summary: How the admin tier is granted, how its second factor is issued and checked, how it differs from an app's own roles, and what the admin pages can change and record.
weight: 4
lastmod: 2026-11-19
---

## Who is an administrator

An administrator is an address on a fixed list in the gateway's settings. The
list is an exact list of addresses, not a domain, and no admin page can add to
it. Removing an address from the list takes effect at that person's next
request, on the admin pages and on the tools.

Only a normal sign-in can hold the admin tier. A break-glass session, a guest
session or a member's session is never treated as an administrator, whatever
lists it carries.

Being a gateway administrator gives no role in any app. An app's roles are
given on its page, to administrators as to anyone else. On the department's
server, each administrator who needs an app's Administrator role has been
given it by name.

## The second factor

An emailed code is only as safe as the inbox it is sent to, so the gateway
can require administrators to take a second step as well: a six-digit code
from an authenticator app, or a passkey that stands in for one. The second
factor is on for the department's server.

Administrators sign in exactly as staff do, with an emailed code or a
passkey. The second step is asked for only at the admin door, which an
administrator reaches by opening the gateway's admin pages. An
administrator's roles in the apps do not depend on the second step: an
administrator who has been given an app's Administrator role holds it from
the moment of signing in, as anyone else given that role does. The `admin`
entry in the older groups header still reaches an app only after the second
step.

The second step lasts twelve hours, however long the session lasts. After
twelve hours, the admin door asks again; with a passkey, that is a single
check of the face, fingerprint or PIN.

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
signed in lose the admin pages at their next request and keep their other
access. A session from before the change, or from before a person became an
administrator, does not carry the second step, so the admin door asks for it.

## The admin pages

The admin pages sit on the gateway's own host. Anyone else who is signed in
and opens an admin page is shown the no-access page, which names the address
they signed in with.

| Page | What an administrator can do there |
|---|---|
| Overview | See anything that needs an administrator |
| Apps | Give each app's roles and take them away, and see which paths each role opens |
| Invitations | Invite people to a role in one app, and resend or withdraw an invitation |
| Groups | Manage domain groups and lists, including lists filled from a feed |
| Break-glass cards | Make, replace, withdraw and move cards, manage the card designs, and download each card's printable PDF |
| App feeds | Approve which apps may read the members of which lists |
| Access log | See sign-in attempts and which tools each person reached |
| Admin audit | See every change made on the admin pages and who made it |
| Admin 2FA | Create, reset or remove administrators' authenticator secrets |
| Settings | Change the break-glass session length, who is notified when a card is used, and the site logo |

Most of the pages contain no scripts. The Apps pages, the new-card form and
the card design editor each carry one script written into the page, and the
gateway's content policy allows that script alone, by its hash. Every change requires a form token that is
bound to the administrator's own session, so another site cannot submit a
change on an administrator's behalf.

Every change is recorded with the administrator who made it, what changed,
their network address and the time. The other administrators are also
emailed about each change to an app's roles and each approval on the App feeds
page. The access log keeps one row per person,
tool and hour rather than one per request. Both records are kept for one year
and then deleted.
