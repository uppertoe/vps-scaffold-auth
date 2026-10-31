---
title: Who can reach what
summary: The three roles, the groups administrators manage, the rule each tool declares, and how guests from the public are kept to the one tool meant for them.
weight: 3
lastmod: 2026-10-31
---

## Roles

Every session carries one of three roles, and the role is always the first
entry in the groups a tool receives.

| Role | Who holds it |
|---|---|
| `admin` | An address on the gateway's list of administrators |
| `user` | An address at one of the allowed domains |
| `guest` | Any other verified address, signed in on the way to a tool that admits the public |

A break-glass session has no role of its own. It carries only the group its
card names, as [Break-glass cards](break-glass-cards.md) describes.

Administrators also manage named groups on the gateway's admin pages, such as
the group for the clinical prototypes. Group names may contain only lower-case
letters, digits, hyphens and underscores, and the three role names are
reserved. These two restrictions mean that no group can make its members
administrators, and no group can make a member of staff look like a guest.

## The rule each tool declares

Each tool's Caddy route imports one guard, and the guard sends the gateway one
header that states the tool's rule. Caddy replaces any copy of that header the
browser sent, so a visitor cannot change or widen the rule.

| Guard | Who it admits |
|---|---|
| Any signed-in person | Any `user` or `admin`, but no guest and no break-glass card |
| Open to the public | Anyone signed in, guests included |
| Listed domains | People whose address is at one of the named domains |
| Listed groups | Members of the named groups, and break-glass cards that name one of them |
| Administrators only | Members of the `admin` group |
| Domains or groups | Either of the two conditions above |

The gateway reads the rule strictly. A guard that sends no rule, an empty
list, a misspelt field or a contradictory rule is refused, and every visitor
to that tool is shown the no-access page. A typing error in a guard therefore
closes the tool rather than opening it to everyone. The gateway also writes
the refused rule to its log, so that the fault is found quickly.

An earlier design used several headers, and each guard had to delete the ones
it did not set. A guard that forgot one deletion would have let a visitor add
a rule of their own. The single header, replaced on every request, removed
that risk.

## Signing in for a domain

When a tool's rule names a domain, the sign-in page tells the person which
addresses the tool accepts, and declines an address at another domain before
sending a code. A tool can show a phrase such as "an approved Victorian health
service" instead of listing the domains.

Administrators are not admitted by a domain rule unless their address is at
that domain. A tool that administrators from elsewhere must reach gives them a
separate entrance with the administrators-only guard, and the sign-in page
can carry a link to that entrance. The gateway checks that the link leads to
the server's own domain before showing it, so a tampered sign-in address
cannot turn the link into one that leads elsewhere.

## Guests

One tool on the department's server, the fellowship enquiries page, is for
members of the public. Its host is listed in the gateway's settings as open to
registration. A person who signs in on the way to that host, with an address
the allowed domains do not cover, is signed in as a guest.

A guest is admitted only where a tool's rule opts in. The open-to-the-public
guard admits guests, and a group guard admits a guest whom an administrator
has placed in one of its groups. Every other guard refuses them, including the
plain "any signed-in person" guard and a domain guard that names the guest's
own domain. A tool that forgets to set a rule therefore stays closed to the
public.

The host list decides only where the gateway offers a guest sign-in. It is not
the boundary, because the destination travels in the sign-in address, which a
visitor can change. The boundary is that only the tools which opt in admit
guests.

A guest session renews like any other but always keeps the short lifetime.
Removing every host from the list ends all guest sessions at their next
renewal. A guest who reaches a tool they cannot open is told they are signed
in as a guest and is offered a way to sign out, so that they can sign in again
with an approved address.

Listing a host also gives effect to group memberships that were previously
inert. A membership for an address outside the allowed domains did nothing
while that address could not sign in. Once a host is open, the same address
can sign in as a guest and the membership admits it. The admin groups page
marks each member whom the allowed domains no longer cover, so that such
memberships can be reviewed before a host is listed.

## Opening the gateway to everyone

The gateway can also be set to admit any verified address as a `user` on
every tool. This older setting is discouraged on a shared server, because any
tool that relies on the plain "any signed-in person" guard is then open to the
public. The department's server does not use it.
