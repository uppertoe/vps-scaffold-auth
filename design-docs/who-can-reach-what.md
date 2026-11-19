---
title: Who can reach what
summary: The roles each tool declares, who the gateway gives each role to, who may sign in, and how guests from the public are kept to the one tool meant for them.
weight: 3
lastmod: 2026-11-19
---

## What a tool declares

Each tool's Caddy snippet declares the tool's roles. Every tool has a User
role, and a tool with a staff or administrator side declares more, such as
Administrator. The snippet also says which paths need which role, which paths
are open by design and the reason for each, and which pages a break-glass card
may open. The server renders the snippets into one manifest, which the gateway
reads when it starts.

Each guarded path imports the role guard, which sends the gateway the tool's
name and the role the path needs. Caddy replaces any copy of those headers
that the browser sent, so a visitor cannot change the tool or the role being
asked for.

The gateway reads the guard strictly. A guard that names a tool or a role the
manifest does not declare, or that sits on a host the manifest does not give
the tool, is refused, and every signed-in visitor to that path is shown the
no-access page. A guard copied onto another site therefore cannot borrow a
tool's roles, and a typing error closes the path rather than opening it. The
gateway also writes each refusal to its log, so that the fault is found
quickly.

## How a role opens a path

Any role in a tool opens the tool's ordinary paths, which are the paths that
need the User role. A path that needs another role, such as an administrator's
page, opens only to the people who hold that role. The roles have no order of
rank, so holding one role never gives another.

The gateway works out a person's roles in a tool on every request, so a role
given or taken away applies from the person's next request.

## Who the gateway gives a role to

An administrator gives each role on the tool's page in the gateway's admin
pages. A role can be given to any of the following.

| Given to | Who it covers |
|---|---|
| A domain group | Every address at the group's domains, such as `rch.org.au` |
| A list | The members of a list, kept by hand or filled from a feed such as the roster |
| A person | One address, added by hand or by invitation, until an end date or permanently |
| A break-glass card | Whoever scans the card, as [Break-glass cards](break-glass-cards.md) describes |
| The hospital network | Every request from the network's address ranges, whether or not the person has signed in |
| Guests | Anyone signed in with a verified address, on a tool that admits the public |

A card, the hospital network and guests identify nobody, so each can be given
only the User role. The gateway refuses any other role for them, so no one
becomes a tool's administrator by carrying a card, by being on the network or
by confirming an address.

Before a change is saved, the page lists it for review. The review warns when
the change would leave a role with nobody, and when it would open a role to
the network or to guests. Each saved change is recorded in the admin audit,
and the other administrators are emailed.

An invitation gives one person a role in one tool. The gateway emails the
invitation to that address, and its link works only for that address, for
fourteen days. The person accepts it with a code sent to the same address, and
then holds the role until the end date, if the administrator set one. Seven
days before a person's role ends, the gateway emails the person and the
administrator who gave the role.

## Who can sign in

An address at one of the domains on the allow-list in the gateway's settings
signs in as staff, and an address on the gateway's list of administrators
signs in as an administrator. When a server leaves the allow-list empty, the
gateway counts as staff every address at a domain of a domain group that holds
a role in at least one tool. A domain group that holds no role admits nobody.
While the allow-list is set, the domain groups add no one to staff. An address
that is not staff signs in as a member if it holds a role in some tool through
a domain group, a list or a person assignment. An address with an open
invitation signs in through the invitation's link and code. On a tool that
admits the public, any other verified address signs in as a guest, as
described below.

The hospital network and guests give nobody a reason to sign in, because they
admit people without naming them. An address that may not sign in is sent no
code and sees the same page as any other address, so the sign-in page does
not reveal who holds a role.

The allow-list predates app roles, and the department's server still sets it
to the hospital's and the institute's domains. The domain groups for RCH and
MCRI staff carry the same two domains. The allow-list will be removed only once
every tool has moved to app roles and each of those groups holds a role, and
then no one's sign-in will change. Until then, a tool behind an older guard
admits staff, so with the allow-list gone, a domain group holding a role in any
tool would open such a tool to everyone at its domains. On a server where some tools still use the older guards,
those guards admit a member only where they would admit a guest.

The same test of who is staff decides which addresses a roster feed keeps,
which members a tool reading a list is given, and which members the Groups
page marks as not staff. A person who is not staff is never counted as a
member of a list that the server's settings close to outsiders, and the
gateway drops such a list from that person's session. On the department's server these are the
administrators lists of the airway database, the enquiries page, the project
boards and the roster insights, and the prototypes list. An administrator can
still give such a person the role by name.

## Signing in for a domain

When the role a page needs is given only to domain groups, the sign-in page
names those domains, and it declines an address at another domain before
sending a code. When the role is also given to a list, a person, the network
or guests, the page names no domain, because an address at any domain might
hold the role. When a card or an open invitation also gives the role, the
page names the domains but declines no address.

## Guests

One tool on the department's server, the fellowship enquiries page, is for
members of the public, and its User role is given to guests. A person who
signs in on the way to that tool, with an address the gateway would not
otherwise admit, is signed in as a guest. The gateway offers a guest sign-in
only on a host that its settings open to registration.

A guest holds a role only where a tool gives the role to guests, and guests
can be given only the User role. Every other tool refuses them. A tool that
gives guests nothing therefore stays closed to the public.

The host list decides only where the gateway offers a guest sign-in. It is not
the boundary, because the destination travels in the sign-in address, which a
visitor can change. The boundary is that only the tools which give a role to
guests admit them.

A guest session renews like any other but always keeps the short lifetime.
Removing every host from the list ends all guest sessions at their next
renewal. A guest who reaches a tool they cannot open is told they are signed
in as a guest and is offered a way to sign out, so that they can sign in again
with an approved address.

## Opening the gateway to everyone

The gateway can also be set to admit any verified address as staff. The
department's server does not use this setting.
