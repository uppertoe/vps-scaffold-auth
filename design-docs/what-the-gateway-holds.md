---
title: What the gateway holds
summary: The records in the gateway's database, how each is protected, how long it is kept, and what a stolen copy would reveal.
weight: 6
lastmod: 2026-11-27
---

## The records

The gateway keeps everything in one database file. It holds no patient data
and no passwords.

| Record | Holds | Protected by | Kept for |
|---|---|---|---|
| Sign-in codes | A keyed hash of each code, its expiry and its count of wrong guesses | The hash, which cannot be reversed without the gateway's key | Until used or expired |
| Authenticator secrets | Each administrator's secret | Encryption | Until removed |
| Role assignments | Each app role and who it is given to: a domain group, a list, a person with any end date, the hospital network or guests | Access to the admin pages | Until removed |
| Invitations | The address, app, role, end date and message of each invitation, and a hash of its link's token | The hash, from which the link cannot be rebuilt | Indefinitely, with the date it was accepted or withdrawn |
| Break-glass cards | Each card's location, note, app and page (or, for an older card, its group), design and code | A hash for looking the code up, and an encrypted copy for reprinting the card | Indefinitely, since a withdrawn card stays on record |
| Break-glass scans | The card, network address, browser and time of each scan | Access to the admin pages | Indefinitely |
| Passkeys | Each passkey's public key, account ID, label, and the dates it was added and last used | Nothing further is needed, since a public key cannot sign anyone in | Until removed |
| Groups | Each domain group's domains and organisation name, and each list's members and any feed it is filled from | Access to the admin pages | Until removed |
| Sessions | Each session's address, kind, lists, admin step, the passkey or card behind it, when it signed in, was renewed and was last used, its expiry, a summary of the browser, and a hash of its cookie's token | The hash, from which the cookie cannot be rebuilt | Until the session ends, and at most an hour past its expiry |
| Sign-in log | Address, network address, browser, step and outcome of each attempt | Access to the admin pages | One year |
| Access log | Address, tool and hour, one row for each combination | Access to the admin pages | One year |
| List reads | Which app read which list's members, from which address, in each hour, and the approvals that allow it | Access to the admin pages | One year for the reads, and until withdrawn for the approvals |
| Admin audit | Who changed what on the admin pages, when, and from where | Access to the admin pages | One year |
| Card designs and settings | Logos, card colours, wording and sizes, and notification settings | Access to the admin pages | Until changed |

## Encryption at rest

The two secrets that must be read back, administrators' authenticator secrets
and the cards' codes, are encrypted with AES-256-GCM. A stolen database file
reveals neither without the key, which is held in the server's settings and
not in the file.

The encryption key can be set separately from the key that signs the gateway's
short-lived cookies, such as a sign-in in progress. Changing the signing key
then leaves the stored secrets readable. If no separate key is set, the gateway derives one
from the signing key and warns at every start that it has done so.

## What a stolen copy would reveal

A copy of the database without the server's settings would reveal the
addresses of people who have signed in, who holds each role, the members of
each list, the addresses invited, the logs and the card designs. It would not
reveal a live sign-in code, an authenticator secret, a card's code or an
invitation's link, and it could not be used as a session, because it holds
only a hash of each session's token.

## Backups and the server's logs

The department's server backs the database up with its other data, encrypted
and off the server, as the server's page on
[data, backups and logs](../server/data-backups-and-logs.md) describes.

The gateway writes no codes, cookies, card codes or invitation links to its
own log. The server's access log never records the session cookie, and it
leaves break-glass scans and invitation links out entirely, so that neither a
card's code nor an invitation's token reaches it.
