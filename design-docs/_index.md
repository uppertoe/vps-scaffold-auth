---
title: The sign-in gateway
summary: One small service signs people in with an emailed code and decides, on every request, whether they may open each of the department's web tools.
status: live
contact: Eamonn Upperton
decided-by: Eamonn Upperton, for the department's data lab, with the owner of each tool
link: https://auth.rch-anaesthesia.org
weight: 2
lastmod: 2026-10-31
---

Almost every web tool on the department's server sits behind one sign-in, the
gateway at `auth.rch-anaesthesia.org`. A person enters their work email
address, receives a code by email and types it in. From then on, the gateway
decides on every request to every protected tool whether that person may open
it. These pages explain how the gateway works, the rules it applies, and how
it has been hardened against attack. They are written for someone who is
comfortable with terms such as cookie and reverse proxy but has not read the
code.

The gateway is described entirely by one Git repository,
`vps-scaffold-auth`, and is released as a container image. The department's
server runs it, as do the data lab's other servers, each with its own
settings, domain and records. The gateway is deliberately small. It stores no
passwords, uses no outside identity provider, and keeps its records in a
single database file. The server's own pages describe
[the login wall](../server/the-login-wall.md) from the side of the tools;
these pages describe the gateway itself.

## The pages

[How it works](how-it-works.md) follows a request from the browser through
the reverse proxy to the gateway and back. [Signing in](signing-in.md) covers
the emailed code, the limits on guessing it, and how long a session lasts.
[Who can reach what](who-can-reach-what.md) sets out the roles, the groups and
the rule each tool declares. [Administrators](administrators.md) covers the
admin tier, its second factor and its records.
[Break-glass cards](break-glass-cards.md) explains emergency access by QR code
and the risk the department has accepted with it.
[What the gateway holds](what-the-gateway-holds.md) lists the records the
gateway keeps and how each is protected.
[Security hardening](security-hardening.md) gathers the defences in one place,
and [Reviews](reviews.md) records how the gateway has been reviewed and what
each review changed.

## Decisions still open

These questions are listed here so that there is one list.

- Whether a session should have an absolute limit. A session renews itself
  while it is in use, and renewal checks the person's email domain but not
  their mailbox. A person who leaves the department therefore keeps a working
  session on any device they signed in on, for as long as they keep using it.
  On the department's server, where "remember me" lasts thirty days, that
  period has no end.
- Whether one person's session should be revocable on its own. Sessions are
  not recorded anywhere, so the only ways to end one early are to remove the
  person's domain or admin listing, which takes effect at their next renewal,
  or to sign everyone out.
- Whether any tool should move to a separate domain. Every tool on the
  department's domain can set the shared session cookie in a visitor's
  browser, so a compromised tool could sign a visitor in as someone else. The
  gateway refuses the cruder forms of this, but only a separate domain with
  its own gateway removes the risk.
