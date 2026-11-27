---
title: How it works
summary: The path of a request through the reverse proxy and the gateway, what the session cookie carries, and what a tool is told about the person.
weight: 1
lastmod: 2026-11-27
---

## The path of a request

Caddy, the server's reverse proxy, is the only program that faces the
internet. When a request arrives for a protected tool, Caddy first sends the
request's headers to the gateway and waits for its answer. The headers name
the tool and the role the path needs. The gateway reads the session cookie,
works out which roles the person holds in that tool, and gives one of three
answers.

| Answer | When it is given | What the person sees |
|---|---|---|
| Admit | The person holds a role that opens the path, or the request comes from a network that holds it | The tool itself |
| Sign in | There is no session, or the session has expired or can no longer be honoured | The sign-in page, which returns the person to the tool afterwards |
| No access | The session is valid but the person holds no role that opens the path | A page explaining that the person is signed in but cannot open this tool, with a link to sign in with another address |

The gateway makes this decision on every request, not once per visit. A role
given or taken away on a tool's page therefore applies from the person's next
request, and so does a change to the members of a list, as
[Signing in](signing-in.md) describes.

A person who is refused a tool is never sent back to the sign-in page. They
are already signed in, and signing in again would not help. Their session is
left intact, so the tools they may open keep working.

## The session

After a successful sign-in, the gateway starts a session and sets one cookie
on the whole domain, so that one sign-in serves every tool. The cookie carries
only a random token. The gateway keeps the session itself: the person's email
address, the kind of session, the lists they belong to, when they signed in,
when the session was last used and when it expires. The gateway works out the
person's roles on each request. It stores only a hash of each token, so a copy
of its database cannot be used as anyone's session.

The gateway holds its sessions in memory as well as in the database, so the
check on each request stays fast. Because the gateway keeps each session, an
administrator can end one session, all of one person's sessions, or everyone's,
on the Sessions page, and the ending takes effect at once on every tool.

The gateway issues four other short-lived cookies, each limited to the
gateway's own host: one carries a sign-in in progress, one carries
a passkey ceremony, one holds a break-glass offer, and one protects the forms. Each cookie records the purpose it was made
for, and the gateway refuses a cookie presented for any other purpose. A
computer that holds a passkey also keeps a cookie listing its passkeys, so
that the gateway asks the computer only for those.

## What a tool is told

When the gateway admits a request, Caddy passes the tool the person's
identity, their email address and, in `Remote-Roles`, the roles they hold in
that tool, such as `user,admin`. A request admitted because it comes from the
hospital network, with no session, carries the roles and no identity.

No tool is told which lists the person is on. The gateway still sends the
older groups header, empty, because one route on another server copies it;
the header will be dropped once no route copies it.

A tool can trust these headers because Caddy deletes any copy the browser
sent, `Remote-Roles` included, before it asks the gateway, and because only
Caddy can reach the tool.
Caddy also removes the gateway's session cookie before the request reaches the
tool. The cookie would open every other tool on the domain, so no tool is ever
given it.

## Where it runs

The gateway is a single program written in Go, running in its own container
with a small database file on a named volume. It publishes no port of its own,
so only Caddy can reach it. Each tool's Caddy snippet declares the tool's
roles and imports the gateway's role guard on each guarded path, as
[Who can reach what](who-can-reach-what.md) describes.

## Why it was built

The department's rule for most tools is simple: a person may sign in if they
control an email address at an allowed domain. No existing product matched
that rule with a small footprint. The lightweight proxies do not sign people in
by email, and the products that do are full identity providers, with password
stores and federation protocols the department does not need. An emailed code
and a session the gateway keeps give a surface small enough for one person to read from
end to end.
