---
title: What the gateway holds
summary: The records in the gateway's database, how each is protected, how long it is kept, and what a stolen copy would reveal.
weight: 6
lastmod: 2026-10-31
---

## The records

The gateway keeps everything in one database file. It holds no patient data
and no passwords.

| Record | Holds | Protected by | Kept for |
|---|---|---|---|
| Sign-in codes | A keyed hash of each code, its expiry and its count of wrong guesses | The hash, which cannot be reversed without the gateway's key | Until used or expired |
| Authenticator secrets | Each administrator's secret | Encryption | Until removed |
| Break-glass cards | Each card's label, note, group, destination and code | A hash for looking the code up, and an encrypted copy for reprinting the card | Indefinitely, since a revoked card stays on record |
| Break-glass scans | The card, network address, browser and time of each scan | Access to the admin pages | Indefinitely |
| Groups | Group names and their members' addresses | Access to the admin pages | Until removed |
| Sign-in log | Address, network address, browser, step and outcome of each attempt | Access to the admin pages | One year |
| Access log | Address, tool and hour, one row for each combination | Access to the admin pages | One year |
| Admin audit | Who changed what on the admin pages, when, and from where | Access to the admin pages | One year |
| Branding and settings | Logos, card wording and colours, and notification settings | Access to the admin pages | Until changed |

Sessions are not in the database at all. Each session lives only in the
person's browser, as a signed cookie.

## Encryption at rest

The two secrets that must be read back, administrators' authenticator secrets
and the cards' codes, are encrypted with AES-256-GCM. A stolen database file
reveals neither without the key, which is held in the server's settings and
not in the file.

The encryption key can be set separately from the key that signs the session
cookie. Signing everyone out by changing the signing key then leaves the
stored secrets readable. If no separate key is set, the gateway derives one
from the signing key and warns at every start that it has done so.

## What a stolen copy would reveal

A copy of the database without the server's settings would reveal the
addresses of people who have signed in, the members of each group, the logs
and the branding. It would not reveal a live sign-in code, an authenticator
secret or a card's code, and it could not be used to make a session, because
the signing key is not in it.

## Backups and the server's logs

The department's server backs the database up with its other data, encrypted
and off the server, as the server's page on
[data, backups and logs](../server/data-backups-and-logs.md) describes.

The gateway writes no codes, cookies or card codes to its own log. The
server's access log never records the session cookie, and it leaves
break-glass scans out entirely, so that a card's code never reaches it.
