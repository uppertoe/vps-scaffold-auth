---
title: How it works
summary: The path of a request through the reverse proxy and the gateway, what the session cookie carries, and what a tool is told about the person.
weight: 1
lastmod: 2026-10-31
---

## The path of a request

Caddy, the server's reverse proxy, is the only program that faces the
internet. When a request arrives for a protected tool, Caddy first sends the
request's headers to the gateway and waits for its answer. The gateway reads
the session cookie, applies the rule that the tool's route declares, and
gives one of three answers.

| Answer | When it is given | What the person sees |
|---|---|---|
| Admit | The session is valid and the tool's rule allows it | The tool itself |
| Sign in | There is no session, or the session has expired or can no longer be honoured | The sign-in page, which returns the person to the tool afterwards |
| No access | The session is valid but the tool's rule does not allow it | A page explaining that the person is signed in but cannot open this tool, with a link to sign in with another address |

The gateway makes this decision on every request, not once per visit. A change
to a tool's rule therefore applies from the next request. A change to a
person's groups applies when their session next renews, which is described in
[Signing in](signing-in.md).

A person who is refused a tool is never sent back to the sign-in page. They
are already signed in, and signing in again would not help. Their session is
left intact, so the tools they may open keep working.

## The session

After a successful sign-in, the gateway sets one cookie on the whole domain,
so that one sign-in serves every tool. The cookie carries the person's email
address, their role and groups, when it was issued and how long it lasts, all
signed with a key that only the gateway holds. The gateway keeps no list of
sessions. A cookie is accepted because its signature is valid and it has not
expired.

The design keeps the check fast and the gateway small, which matters because
every request to every tool passes through it. It also has a cost: one
person's session cannot be ended on its own. The
[front page](_index.md) lists this among the open decisions.

The gateway issues four other short-lived cookies, each limited to the
gateway's own host: one carries a sign-in in progress, one marks an
administrator who still owes a second factor, one holds a break-glass offer,
and one protects the admin forms. Each cookie records the purpose it was made
for, and the gateway refuses a cookie presented for any other purpose.

## What a tool is told

When the gateway admits a request, Caddy passes the tool three headers: the
person's identity, their email address and their groups. The groups header
begins with the person's role, which is `admin`, `user` or `guest`, followed
by any groups an administrator has placed them in.

A tool can trust these headers because Caddy deletes any copy the browser
sent before it asks the gateway, and because only Caddy can reach the tool.
Caddy also removes the gateway's session cookie before the request reaches the
tool. The cookie would open every other tool on the domain, so no tool is ever
given it.

## Where it runs

The gateway is a single program written in Go, running in its own container
with a small database file on a named volume. It publishes no port of its own,
so only Caddy can reach it. Each tool's Caddy route imports one of the
gateway's guard snippets, and the snippet is how the tool declares its rule;
[Who can reach what](who-can-reach-what.md) lists them.

## Why it was built

The department's rule for most tools is simple: a person may sign in if they
control an email address at an allowed domain. No existing product matched
that rule with a small footprint. The lightweight proxies do not sign people in
by email, and the products that do are full identity providers, with password
stores and federation protocols the department does not need. An emailed code
and a signed cookie give a surface small enough for one person to read from
end to end.
