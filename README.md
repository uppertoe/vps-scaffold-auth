# vps-scaffold-auth

A minimal **email one-time-code `forward_auth` gateway** for the
[vps-scaffold](https://github.com/uppertoe/vps-base-template) family. It puts a
passwordless login wall in front of any web app behind Caddy: users enter their
email, receive a one-time code (`OTP_LENGTH` digits), type it in, and get a session — no passwords
and no third-party identity provider. Passkeys on phones can be switched on as a
faster way back in (`PASSKEYS_ENABLED`; see "Passkeys" below).

It runs as a normal app under `apps/auth/` in a server repo and is consumed as
a prebuilt image from GHCR.

## Why this exists

The apps are browser apps behind a single Caddy reverse proxy on a small VPS.
The access rule is simply *"controls an email at an allowed domain"* (regular
user) or *"is on the admin whitelist"* (admin). No off-the-shelf tool fits that
with a low footprint — the lightweight proxies don't do email login, and the
ones that do are heavyweight identity providers whose OIDC we don't need. An
email-code flow is a small, auditable surface: no password storage and no
federation protocol, just a one-time code and an HMAC-signed cookie.

## How it works

```
browser ──▶ Caddy (app.example.com)
               │  import role "app" "user" ─▶ GET auth:8080/verify
               │                          ├─ holds the role → 200 + Remote-User/Email/Roles → upstream app
               │                          └─ no session    → 302 to auth.example.com/login
               ▼
            auth.example.com  ── login page → email → one-time code → signed-cookie session
```

1. Caddy calls `GET /verify` on every request to a protected app.
2. No/invalid session → `/verify` returns a 302 to the login page.
3. User enters email → a one-time code (`OTP_LENGTH` digits, six by default) is emailed (single-use, ~10 min).
4. User types the code → an HMAC-signed session cookie is set on `.example.com`
   (shared across all app subdomains).
5. `/verify` now returns 200 when the person holds the role the guard names,
   plus `Remote-User`, `Remote-Email` and `Remote-Roles`, which Caddy
   forwards to the app.

`Remote-Roles` is a **comma-separated set** of the roles the person holds in
that app (e.g. `user,admin`). The session carries the person's groups, which
decide the roles held through lists; they are computed at login and again when
a session renews, and at a session's next request after any membership change,
so a change (an addition or a removal) takes effect at the person's next
request. Apps decide by `Remote-Roles` and never see the groups. The gateway
still sends `Remote-Groups` empty, because one inline guard (markbot's
`pstonn.caddy`) copies the header, and a copy of a header the gateway does not
send would hand the app Caddy's placeholder text.

**Lists closed to outsiders.** A list that holds any app role other than User
(an app's Administrator or Board owner, say) is closed to anyone the gateway
does not count as staff: a guest, a member who is not staff, or a card. Such a
list cannot be a break-glass card's target, the admin pages refuse to add an
outsider to it by hand, in bulk or through an include, and an outsider who is
on it all the same is never counted as its member, in a session or by the
members endpoint. The rule is read from the role assignments, so a list closes
as soon as it is given such a role.

Sessions are **stateless signed cookies** — no session store. Persisted state
(single-use OTP codes, admin TOTP secrets, DB-managed groups, and break-glass
codes + their audit log) lives in a small **SQLite** file. No Postgres, no Redis.
Reversible secrets in that file (break-glass tokens, TOTP seeds) are **encrypted
at rest** with AES-256-GCM.

## Using it in a server repo

Want to try it standalone first? [`deploy/standalone/`](deploy/standalone/) is a
complete, runnable example (Caddy + this image from GHCR + a demo protected app)
— `cp .env.example .env && docker compose up -d`.

The `server-instance-template` ships the wiring under `apps/auth/`
(`docker-compose.yml`, `auth.caddy`, `.env.example`) — reference copies live in
[`deploy/`](deploy/). To enable it:

1. Add the include to the server's root `docker-compose.yml`:
   ```yaml
   include:
     - scaffold/docker/caddy.base.yml
     - apps/auth/docker-compose.yml
   ```
2. Create `apps/auth/.env` from the example and fill it in (see config below).
3. Deploy. The image is pulled from `ghcr.io/uppertoe/vps-scaffold-auth`.

### Protecting an app

Each app declares its roles in its Caddy snippet, and the gateway's admin pages
decide who holds them: domain groups, lists, named people, break-glass cards, a
network or guests. The scaffold renders the declarations into the app-roles
manifest (`.generated/caddy/app-roles.tsv`), which the gateway reads from
`APP_ROLES_FILE`; scaffold docs/07 "Protecting an app with roles" describes the
markers. Add one `import` line to the app's Caddy snippet, naming the app and
the role the path needs. The last argument is the app's upstream address. The
guard runs the auth gate and proxies to the upstream, so there is no separate
`reverse_proxy` line:

```caddyfile
# apps/dashboard/dashboard.caddy
# scaffold-app: dashboard
dashboard.{$DOMAIN} {
    import role "dashboard" "user" dashboard:3000
}
```

The app reads identity from the `Remote-User` and `Remote-Email` request
headers, and the roles the person holds in that app from `Remote-Roles`, and
does its own per-feature authorization from them.

> **Trust model:** apps trust these headers because **only Caddy can reach
> them** — they publish no host ports, and Caddy strips any client-supplied
> `Remote-*` before injecting its own. Never expose a protected app directly,
> and never put two apps on one Docker network: on the scaffold's servers each
> app has its own `<app>_proxy` network shared only with Caddy, and the compose
> audit refuses a shared one. The single `caddy` network in `deploy/` is a
> shortened sample, not that layout.
>
> **The session cookie never reaches the app.** It's scoped to `.<domain>`, so
> the browser sends it to every app subdomain, and the gate would otherwise
> pass it through to the backend. Since the cookie is an estate-wide bearer
> credential (ended only by signing out on every device), an app that received it
> could replay it against every other app. Each guard therefore strips
> `vps_auth_session` from the upstream request automatically (via the
> `strip_auth_cookie` snippet folded into it), leaving the app's own cookies
> intact. Apps take identity from the `Remote-*` headers, never the cookie. If you
> hand-roll a guarded `reverse_proxy`, `import strip_auth_cookie` inside it; for a
> public route, import `strip_public` instead (below).

#### Per-app access

Any role in an app admits that app's ordinary paths, and a path may need one
role in particular, with no hierarchy between roles. Put a guard inside a
`handle` block to give a path its own role:

```caddyfile
# scaffold-app: enquiries
# scaffold-roles: admin "Administrator"
enquiries.{$DOMAIN} {
    handle /admin* {
        import role "enquiries" "admin" enquiries:8080
    }
    handle {
        import role "enquiries" "user" enquiries:8080
    }
}
```

Guard summary (`<up>` is the app's upstream `host:port`, always the **last**
argument):

| Snippet | Grants access to |
|---|---|
| `import role "<app>" "<role>" <up>` | a person who holds the role in the app; `user` is also admitted by any other role in the app |
| `import role_gate "<app>" "<role>"` | the same, for a site with no upstream, such as a static `file_server` |
| `import role_redir "<app>" "<role>" "<url>"` | the same, for a site that only redirects |

The app and role must be declared in the manifest, and the guard's host must be
one of the app's hosts there; otherwise every request is refused. A guard that
names no app, such as a hand-rolled `forward_auth`, is refused as well: the
gateway sends every signed-in person to the "no access" page. A signed-in person
who holds no role in an app is **not** bounced to login (they *are*
authenticated); they see a "no access to this page" page with a sign-in link, and
their session is left intact, so the apps they can reach keep working.

Always use these snippets rather than hand-rolling the gate. Each one names its
app and role in `X-Auth-App` and `X-Auth-Role`, set with `header_up`, which
**replaces** any client-sent value, so a client cannot choose the app or role it
is judged by. Each guard also owns the `reverse_proxy` to the upstream and strips
the session cookie there (see the trust-model note above). The gate is written
out in full rather than as `forward_auth` because of one thing `forward_auth`
cannot do: when `/verify` renews the session it answers 2xx with a `Set-Cookie`,
and `forward_auth`'s `copy_headers` only copies into the upstream request, so
the renewed cookie would never reach the browser and every session would run
out at its original expiry. The gate adds the gateway's own cookie (matched by
name) to the response the browser receives, alongside any cookie the app sets.

**Early hint and decline.** When a role is held only by domain groups, the
login page shows their domains ("This page is for `rch.org.au` email
addresses"), and an address at none of them is declined *before* a code is
sent. When anyone else can hold the role, the page neither hints nor declines.
This is a courtesy, **not** the security boundary: the hint rides in the
(client-modifiable) login URL, and the authoritative check always happens at
`/verify`.

The renderer also writes `route-access.tsv` (`ROUTE_ACCESS_FILE`), each site's
paths that are open by design and the roles that guard the rest, which the
overview shows as a "who can reach what" table.

##### Open registration for one app

Some apps are meant for people the department does not yet know, such as an
applicant portal. Set `OPEN_REGISTRATION_HOSTS` to that app's host, and give the
app's User role to guests on its admin page:

```caddyfile
# .env:  OPEN_REGISTRATION_HOSTS=apply.example.com
apply.{$DOMAIN} { import role "apply" "user" apply:3000 }
```

When someone signs in on the way to a listed host and their address is not
staff, the gateway sends them a code as usual and, once they enter it, signs
them in as a **guest**. A member of staff, or an admin, signs in with their usual
role on the open host as anywhere else.

A guest holds only the roles given to guests, and those given to a list an
admin has placed the guest in. A role held by guests is the User role only, and
a guest is never an admin and never sees the TOTP step.

Guest sessions renew like ordinary ones, keeping their guest kind, but a guest
never receives the remember-me lifetime: sessions are stateless, so a stranger
is kept on the short lifetime to bound how long an unwanted guest can hold a
cookie before renewal re-checks it. If a guest reaches a page they cannot open,
the "no access" page tells them they are signed in as a guest and offers to sign
them out, so they can sign in again with an approved address. Guest visits
appear as `guest` in the admin access log.

The host check decides only where the gateway offers a guest sign-in; it is not
the boundary. The destination rides in the login URL, so anyone who can receive
mail can obtain a guest session once any host is listed. What keeps guests
contained is that only roles given to guests, or to a list a guest is in, admit
them.

Listing a host also gives effect to list memberships that were previously
inert. A membership for an address that is not staff used to do nothing,
because that address could never sign in. Once any host is open, the same
address can sign in as a guest and hold every role given to that list. Before
listing a host, review the admin groups page, which marks each member who is
not staff, and remove any membership that should have ended with the person's
access. Removing a domain from `ALLOWED_EMAIL_DOMAINS`, or from a domain group,
does not remove list memberships.

`OPEN_REGISTRATION_HOSTS` takes a comma-separated list of bare hostnames, each
either `DOMAIN` or a subdomain of it. The gateway refuses to start if an entry is
anything else, such as a URL, a host with a port, or a sibling domain.

**The global form, `ALLOWED_EMAIL_DOMAINS=*`.** This older switch still works:
any email verified by a one-time code signs in as staff, on every host. Each
app's roles still decide what such a person reaches. Admin stays an exact
`ADMIN_EMAILS` allow-list either way.

#### Mixing public and protected routes

Not every route needs a login. A webhook receiver, a health check, or a public
landing page can sit on the same host as a protected app. Give the public paths
a plain `reverse_proxy` (no guard), mark them as open by design for the
renderer, and let a fallback `handle` protect the rest:

```caddyfile
app.{$DOMAIN} {
    # Public: no login, no session (e.g. a webhook receiver and health check).
    @public path /webhooks/* /healthz
    handle @public {
        # scaffold-lint: open-path -- /webhooks/* /healthz: the sender signs each webhook delivery
        reverse_proxy app:3000 {
            import strip_public   # no login, but strip the cookie and forged identity
        }
    }
    # Everything else needs the app's User role.
    handle {
        import role "app" "user" app:3000
    }
}
```

A fully public app is just a host with no guard at all:
`public.{$DOMAIN} { reverse_proxy public:3000 { import strip_public } }`.

> **Strip the cookie and forged identity on public routes too.** The session
> cookie is scoped to `.<domain>`, so the browser sends it to **every** subdomain
> and every path — public ones included. A guard strips it automatically, but a
> plain `reverse_proxy` does not, so a public backend would receive the
> estate-wide bearer token that protected routes carefully withhold. A public
> route also has no guard to remove the `Remote-*` headers a client sends, so an
> app that reads `Remote-User` anywhere (a mixed host whose webhook path shares
> the app's middleware) would believe a forged identity there. `import
> strip_public` inside any public backend's `reverse_proxy` removes both. It only
> scrubs the request Caddy forwards upstream — it sends nothing to the browser, so
> it does **not** log the user out. Never use it inside a guard, where the
> `Remote-*` headers are the gateway's own; there, `strip_auth_cookie` is the
> right snippet.

## Configuration

All settings come from the environment; see [`deploy/.env.example`](deploy/.env.example)
for the annotated list. Key ones:

| Variable | Purpose |
|---|---|
| `AUTH_PUBLIC_URL` | Base URL of the `auth.<domain>` site |
| `ALLOWED_EMAIL_DOMAINS` | CSV of domains whose addresses sign in as staff; `*` = open registration on every host (discouraged on a shared server). Optional on a server with app roles (`APP_ROLES_FILE`): without it, the domains of the domain groups that hold an app role decide who is staff; see [Without the allow-list](#without-the-allow-list) |
| `OPEN_REGISTRATION_HOSTS` | CSV of hosts (`DOMAIN` or a subdomain) where other addresses may sign in as guests; see [Open registration for one app](#open-registration-for-one-app) |
| `ADMIN_EMAILS` | CSV of explicit admin addresses |
| `SESSION_SECRET` | 32+ random bytes (`openssl rand -hex 32`) |
| `COOKIE_DOMAIN` | Leading-dot domain for the shared session cookie |
| `EMAIL_BACKEND` | `smtp` \| `resend` \| `log` (`log` is dev-only; refused unless `COOKIE_INSECURE=true`) |
| `TOTP_ENABLED` | Optional admin TOTP (off by default) |
| `PASSKEYS_ENABLED` | Offer passkey sign-in on phones (off by default); see [Passkeys](#passkeys-optional) |
| `DISPLAY_TIMEZONE` | IANA name for admin-UI timestamps (e.g. `Australia/Melbourne`); empty = UTC |
| `MEMBER_READERS_FILE` | The scaffold-rendered list of the groups each app may read (`.generated/caddy/member-readers.tsv`, mounted read-only at `/etc/vps-auth/member-readers.tsv`); see [Group members for apps](#group-members-for-apps) |
| `MEMBER_READERS` | The same list written as `app=group,group` entries, for a deployment without the renderer; used together with the file |
| `MEMBER_READER_TOKEN_<APP>` | Each reading app's own bearer token, from `openssl rand -hex 32` |
| `BREAKGLASS_REFUSED_GROUPS` | **Deprecated; read for one release only.** Lists to close to outsiders as well as those the role rule closes (space or comma separated). The gateway logs at start that the setting is deprecated, and names each list it closes that holds no app role other than User. Remove it once that line names nothing you need closed |
| `DOMAIN` | The server domain (provided by the server `.env`) |

The gateway refuses to start when neither `ALLOWED_EMAIL_DOMAINS` nor `ADMIN_EMAILS` is set.

#### Without the allow-list

A server that uses app roles (`APP_ROLES_FILE`) can leave `ALLOWED_EMAIL_DOMAINS`
empty. The gateway then counts as staff the administrators in `ADMIN_EMAILS` and
every address at a domain of a domain group that holds at least one app role the
manifest declares. A domain group that holds no role admits nobody, and the
sign-in page does not name its domains. Staff sign in as before, feeds and the members endpoint keep them,
and the lists closed to outsiders are kept in their sessions. Anyone else signs in
as a member when they hold a role through a list, by name or by an invitation, or
as a guest on an open host. While `ALLOWED_EMAIL_DOMAINS` is set, it alone decides
who is staff, and a domain group adds no one. Without it, giving a domain group
its first role lets everyone at its domains sign in, and they reach the apps
where the group holds a role, and no other. Taking the group's last role
away, or removing a domain, signs those people out at their next request, or makes
them members if they still hold a role. If the gateway has not been able to read
its domain groups since it started, it answers sign-in and session checks with a
503 and ends no session until it can.

At start, a gateway without the allow-list logs who can sign in.


### Passkeys (optional)

Set `PASSKEYS_ENABLED=true` to let people sign in on their phones with a
passkey instead of an emailed code. After an emailed code on a phone, the
gateway offers to add one; `/passkeys` lists and removes a person's passkeys,
and an administrator removes all of one person's passkeys from the access
page. On a computer, `/passkeys?add=computer` adds a passkey held by the
computer (Touch ID, Windows Hello) only when the person asks, and a
registration the browser reports as held elsewhere (`hybrid`, a security key,
no `internal` transport) is refused. A computer whose client address is in
`NETWORK_RANGES` cannot add one, checked when the challenge is minted and
when the registration is posted; phones there are unchanged. Only a computer
marked by the `__Host-vps_auth_pk_here` cookie (unprefixed only with
`COOKIE_INSECURE`), set when it adds or uses a passkey, is asked for a passkey
at sign-in, only for those passkeys, and only by the button, never in the
email field. Passkeys are bound to the auth host (the relying-party ID is the host of
`AUTH_PUBLIC_URL`), accept only ES256 with user verification and no
attestation, and need no new dependency: the verifier is `internal/passkey`.

- Adding a passkey needs an emailed-code sign-in within the last 15 minutes
  (a passkey sign-in never counts); an administrator also needs a recent
  second step, or an authenticator code entered first. The admin door offers
  a passkey straight after the code: on a phone while the account holds no
  admin passkey, and on a computer while that computer holds none of the
  account's (`adminPasskeysHere`) and its address is not in `NETWORK_RANGES`,
  behind the same warning and under the same computer rules.
- An administrator's passkey, added that way with `TOTP_ENABLED=true`, is the
  second step at sign-in and at the admin door. One added before its owner
  became an administrator, or while TOTP was off, is not; after the code at
  the admin door, the door offers a new one, which replaces it on the phone.
- A session started with a passkey loses the admin pages and `/passkeys` at
  once when the passkey is removed, and the apps at its next renewal.
- The account holder is emailed whenever a passkey is added.
- This is the only setting that puts a script on the sign-in pages:
  `/passkey.js`, allowed by `script-src 'self'` on the pages that run a
  ceremony and nowhere else.

### Admin two-factor (optional)

Magic codes inherit the security of the user's inbox. For the higher-trust
admin tier you can require TOTP: set `TOTP_ENABLED=true`. Signing in never asks
for it: an admin signs in like anyone else and holds ordinary `user` groups. The
admin door (`/totp`) asks for a 6-digit authenticator code, or an admin passkey,
when an admin opens `/admin` or a route whose `groups=` names `admin`; only then
does the session carry the `admin` group. The second step lasts 12 hours
(`adminStepMaxAge`), after which `admin` leaves the apps' headers at the next
request and the door asks again. Removing an address from `ADMIN_EMAILS` also
drops `admin` at the next request.

**Enabling TOTP re-challenges existing admin sessions.** Admin sessions minted
before TOTP was turned on carry no second step, so at their next request they
lose the `admin` group (at `/verify` and the `/admin` UI) and keep their `user`
access; the admin door restores it. The switch can't be bypassed by riding a
pre-existing cookie. **Provision admins' secrets before you flip
`TOTP_ENABLED`** (bootstrap the first one with the `-totp-enroll` CLI below):
once it's on, an admin with no secret is locked out until one is issued.

**Secrets are admin-provisioned, never self-enrolled.** A login only proves
control of the inbox — so letting a login *bootstrap* its own TOTP secret would
hand the second factor to whoever controls the inbox, defeating the point. So
secrets are issued out of band:

- **First admin / bootstrap.** Run the one-off CLI in the same container and
  environment as the server (so it shares the at-rest encryption key):
  ```bash
  docker compose exec auth /app -totp-enroll you@example.com
  ```
  It prints the setup key + `otpauth://` URL once (treat as a secret); add it to
  your authenticator app. `auth -totp-remove you@example.com` deletes a secret.
- **Subsequent admins.** A signed-in admin provisions others from
  **`/admin/totp`**: it lists the configured admins and their enrolment status,
  mints (or resets) a secret — shown once, to be conveyed over a trusted channel
  — and can remove one. An admin with no provisioned secret is **denied at
  login** (with a "contact an administrator" page), not enrolled.

> Admins are mutually trusted: whoever provisions a secret sees it once, so they
> could in principle act as that admin (the same model that lets any admin mint
> break-glass credentials). Convey secrets in person, not by email.

**Strongly recommended when using the admin UI** (below): the admin UI can mint
instant-grant break-glass credentials, so the admin tier should carry a second
factor.

### Signing out

`GET /logout` on the auth host shows a confirmation; `POST /logout` ends the
session for every app on the domain. An app's "Sign out" link may add
`?rd=<https URL on the domain>`; it is validated like the login page's `rd`,
carried through the confirmation form, and handed to the login page, so the
person returns to that app's sign-in rather than the bare login page.

The confirmation page also offers **"Sign out on every device"**, which ends
every session the person has, here and elsewhere, including one someone else
may hold. An administrator can do the same for anyone from that person's view of
the Access log. A session also ends early when:

- the person's administrator authenticator is replaced or removed;
- the passkey it was started with is removed;
- the break-glass card that granted it is revoked or re-minted;
- `SESSION_MAX_AGE` has passed since the person signed in (default: the longer
  of `SESSION_REMEMBER_TTL` and 7 days; it may not be shorter than
  `SESSION_REMEMBER_TTL`), however often the session has renewed.

Sessions are still signed cookies. The gateway keeps, per person, per passkey and
per card, only the time before which every session has ended, in SQLite and in
memory, and checks it on every request. This needs one gateway process per
database, as the SQLite store already does.

### Staying signed in

The login page has a **"Keep me signed in"** checkbox. Unchecked, a session
lasts `SESSION_TTL` (default 2h); checked, it lasts `SESSION_REMEMBER_TTL`
(default 24h). Both slide on activity (renewing every `SESSION_RENEW_AFTER`,
default 1h), up to `SESSION_MAX_AGE` from sign-in. Removing a domain from the
allow-list (or, without one, from the domain groups), a person from the admin listing, or every host from
`OPEN_REGISTRATION_HOSTS` takes effect at each person's next request once the
gateway has restarted with the new setting, as a group change does. The renewal is issued by `/verify`
and carried to the browser by the guard's auth gate; a hand-rolled
`forward_auth` would drop it (see the note under "Protecting an app").

### Groups and the admin UI

Admins (anyone in the `admin` group) get a web UI on the `auth.<domain>` host:

- **`/admin/groups`** — define named groups (e.g. `whitelisted`) and manage their
  member emails. A role given to a list reaches its members at their next request.
- **`/admin/break`** — manage break-the-glass codes (below).
- **`/admin/access`** — the access log: login attempts and outcomes, plus which
  apps each person has reached (deduplicated to one row per user/app/hour, not
  per request). Filter by email. Rows are pruned after `AUDIT_RETENTION`
  (default one year; `0` keeps them forever).
- **`/admin/audit`** — the administrative-action trail: which admin minted,
  revoked, or re-minted a break-glass code, changed groups/memberships, removed
  another admin's 2FA, or edited branding/settings — each attributed to the
  acting admin with a client IP and timestamp. Same retention as the access log.
- **`/admin/totp`** — when `TOTP_ENABLED=true`, provision/reset/remove admins'
  two-factor secrets (see [Admin two-factor](#admin-two-factor-optional)).
- **`/admin/branding`** — two logos plus the break-glass card content. The
  **site logo** is shown on the sign-in pages (a colour logo inverts to white in
  dark mode). The **PDF card logo** is the default on break-glass cards, which
  have a dark header, so use a white/light version (blank reuses the site logo).
  The card content (title/body/instructions), an optional glyph, and the five
  palette colours (default to the RCH palette) drive the printed cards. Each
  break-glass code can **override any of these per card** on its detail page
  (blank fields inherit the global branding).
- **`/admin/settings`** — runtime operational settings that override the env
  defaults: the break-glass session duration, and the notification email list +
  webhook URL.

The UI is script-free (tight CSP, same as the login pages) and protects every
state-changing action with a signed CSRF token.

### Break-the-glass QR codes

For physical, emergency access — laminated QR cards left in known locations (an
angiography lab, a resus bay) so that someone who **cannot otherwise log in** can
still reach an app during a time-critical event (e.g. a code stroke).

- Each code has a unique **label** (e.g. "Angiography Lab 1"), a note, and the
  **app** it opens, with the page a scan lands on.
- **A card opens one app's User role and nothing else.** A break-glass session
  is *deny-by-default*: no domain group, list, network or guests assignment
  admits it, so a card opens exactly the app it names, not the whole estate. A
  holder who reaches another app gets the "no access" page (with a sign-in
  link), and the card keeps working on its own app.
- **Cards made before app roles named a group.** A role guard admits no such
  card, so a group card opens nothing; the card's page offers to move it to an
  app, keeping its printed token. The gateway still refuses a group card whose
  group is a list closed to outsiders (one that holds an app role other than
  User, or that the deprecated `BREAKGLASS_REFUSED_GROUPS` names).
- **Scanning is an instant grant**: the token in the QR URL is the only
  credential, by design. The scan is rate-limited, **logged synchronously**
  (label, client IP, user-agent, time), and **notifies admins** out of band via
  email and/or a webhook — never blocking the grant.
- The granted session is **short-lived** (`BREAKGLASS_SESSION_TTL`, default 8h,
  overridable on the admin Settings page) and is **never renewed**, so it always
  expires at that absolute timeout.
- Codes can be **revoked** (blocks future scans and ends the sessions the card
  granted, immediately) and **re-minted** (issues a fresh token, invalidating
  every already-printed card for that location and ending its sessions).
- Each code has a printable **PDF** (with the QR), downloadable from its detail
  page, for lamination and placement. The card's title, body, instructions, card
  logo, and an optional accent glyph are editable on the admin **Branding** page
  (`/admin/branding`); logos with text should be PNG/JPEG (the SVG rasteriser
  draws shapes, not fonts).

> **Accepted risk:** a break-glass QR is a bearer secret left in the open. Anyone
> who photographs a card gets temporary access to one app with no second
> factor. That is the point — the mitigations are the short TTL, the mandatory
> audit log, the admin notification on every use, and instant revocation.


### Group members for apps

Apps learn a person's roles on every request through `Remote-Roles`. For
work an app does outside a request, such as a weekly email to a group, the
gateway can tell the app who is in the group, so membership is kept in the
gateway and nowhere else.

In a scaffold server repo, an app declares the groups it reads with a
marker in its Caddy snippet, with the groups separated by spaces or commas
before ` -- ` and the reason after it. The route renderer writes every app's
groups to `.generated/caddy/member-readers.tsv`:

```
# scaffold-members: teaching_cases_coordinators, rch-consultants -- weekly digest to the coordinators
```

Mount that file read-only at `/etc/vps-auth/member-readers.tsv` and set
`MEMBER_READERS_FILE` to that path, so the group names are written once, in
the snippet. The only per-app setting left is the app's token, which goes in
the gateway's environment:

```
MEMBER_READERS_FILE=/etc/vps-auth/member-readers.tsv
MEMBER_READER_TOKEN_TEACHING_CASES=<openssl rand -hex 32>
```

The file proposes which groups each app reads, and an administrator approves
each app and group on the App feeds page before the gateway serves it. The
page calls each app and group a feed, and an approval starting the feed. It
appears in the admin menu whenever `MEMBER_READERS` or `MEMBER_READERS_FILE`
is set, and the menu item and the Overview show the feeds waiting to start.
The page lists one row per app and group, waiting feeds first: each is
waiting to start, with a Start the feed button; feeding, with a Stop the feed
button; or not usable, with the reason. Each button asks for confirmation in
place before it acts. An approval or a withdrawal takes effect at the app's next read. The
gateway emails the other administrators about each approval and withdrawal,
and records both in the admin log. Until a pair is approved, the app's reads
of that group get the same 403 as a group it may not read, and are not
recorded. An approval is for a group that exists: the page shows "Group does
not exist yet" for a group that has not been created, and deleting
a group deletes its approvals. When a row leaves the file, the scaffold's
deploy recreates the gateway, because a mounted file has changed, and the
gateway stops serving the row from then on. At start-up the gateway clears the
approval of every row that a fully read file no longer lists, records each in
the admin log, and emails the other administrators, so a row that is added
again needs approval again. The gateway also clears the approvals of an app in
`MEMBER_READERS`, which decides that app's groups. It keeps the approvals when
the file cannot be read, and while an app the file still lists has an
unusable token. The file can therefore narrow an app's access on its
own, but never widen it.

The file holds one `app<TAB>group` row per line, and the gateway skips blank
lines and lines starting with `#`. The gateway also accepts `MEMBER_READERS`
(whitespace-separated `app=group,group` entries), for a deployment without
the renderer. When both are set, the gateway uses every app from either. For
an app named in both, `MEMBER_READERS` decides its groups, because the
operator reviewed that entry, and the gateway ignores the file's rows for that
app. An app in `MEMBER_READERS` needs no approval, and the page lists its feeds as started in the
gateway's settings. A group name in either place is a gateway group name: lower-case letters,
digits, `-` and `_` (`^[a-z0-9_-]+$` once lower-cased), with no dots.

Each app has its own token in `MEMBER_READER_TOKEN_<APP>`, with the app name
in capitals and `-` written as `_`. The token must be 32 or more characters
with more than eight different characters, must not be shared with another
app, and must not be the same as any other secret the gateway holds, so
generate it with `openssl rand -hex 32`. An app may read only the groups
listed for it, and the base roles (`admin`, `user`, `guest`, in any case) can
never be listed. A domain group admits everyone at its domains and has no
member list, so the gateway refuses a read of one with a 409 rather than
answering with nobody. The gateway checks a group's kind at every read,
because group kinds are kept in the gateway's database rather than its
settings, and lists an app named for a domain group on the App feeds page.

The gateway refuses to start when `MEMBER_READERS` itself is wrong, as it
does for any other setting. A problem with the file never stops the gateway,
because a gateway that will not start takes sign-in away from every app on the
server. The gateway reads the file once at start-up and treats problems with
it as follows:

- If the file is missing or cannot be read, the gateway logs an error and
  serves only the apps in `MEMBER_READERS`.
- If a row is malformed, names a base role, or uses a name the gateway does
  not accept, the gateway logs an error and skips that row.
- If an app in the file has no token, a token shorter than 32 characters, or
  a token another app also uses, the gateway logs an error naming the app and
  the variable its token belongs in. The gateway refuses that app's reads as
  an unknown token, and the App feeds page lists the app as not usable
  until the token is set and the gateway has been recreated.
- If an app's token, from the file or from `MEMBER_READERS`, has eight or
  fewer different characters or is the same as another of the gateway's
  secrets, the gateway treats the app in the same way. This check never stops
  the gateway, so an existing deployment with a weak token keeps running.
- If an app is listed in both places and the file names groups that
  `MEMBER_READERS` does not, the gateway logs an error naming those groups,
  refuses reads of them, and lists the app on the App feeds page.
- If the readers come only from the file and `MEMBERS_LISTEN_ADDR` is
  malformed, or its name resolves to none of the gateway's own addresses, the
  gateway logs an error and runs without the members listener. When
  `MEMBER_READERS` lists an app, the same problems stop the gateway, as they
  always have.
- If an app in the file or in `MEMBER_READERS` is listed for a domain group,
  the gateway logs an error at start-up, refuses each read of that group with
  a 409, and lists the app and group on the App feeds page.

The endpoint is served on its own port, `MEMBERS_LISTEN_ADDR` (default
`auth-members:8081`), which Caddy never proxies. An app reaches it at
`http://auth-members:8081` over its own `<app>_members` network: an internal
network that only the gateway and that app join, generated by the scaffold's
route renderer for an app whose Caddy snippet carries a
`# scaffold-members: <groups>` marker. On every members network the gateway
carries the alias `auth-members`. At start-up it resolves the host in
`MEMBERS_LISTEN_ADDR`, keeps the answers that are its own addresses, binds the
members listener to those alone, and has the public listener (`LISTEN_ADDR`)
close any connection that arrives on one of them. An app on its members
network therefore reaches the members endpoint and nothing else of the
gateway's, and Caddy's network cannot reach the members endpoint at all.
At every start the gateway resolves that name, whatever its settings, and the
public listener refuses connections on any of the gateway's own addresses
under it, so an app on a members network never reaches the public listener,
even before the readers are configured. If the name resolves to every one of
the gateway's addresses, it is also the name Caddy uses (a leftover
`MEMBERS_LISTEN_ADDR=auth:8081`, say), so the gateway logs an error and does
neither, rather than refuse Caddy; give the gateway a name of its own on the
members networks, such as `auth-members`. The members listener answers an
unknown token with 401.
Never reach the endpoint over `auth_proxy`, which the gateway shares with
Caddy, and never publish the port (no `ports:` entry in compose). The gateway refuses to start if that port is the one in
`LISTEN_ADDR`, answers only callers on a loopback or private address (every
Docker network is one, and a published port keeps the caller's public
address), and refuses any request that carries forwarding headers.

```
GET http://auth-members:8081/v1/groups/{group}/members
Authorization: Bearer <token>

200 {"group": "...", "members": ["a@…", "b@…"], "as_of": "2026-11-03T10:00:00Z"}
401 no token, or a token the gateway does not know
403 a group this app may not read, or a group that does not exist (the same answer),
    or a caller outside the private network
409 a domain group, which has no member list: {"error": "domain group has no member list"}
405 any method but GET
429 more than 120 reads a minute from one app
```

The members are the people the gateway applies now: the group's own members
and, through includes, the members of every group it includes, as a session
holds them at sign-in. A held feed change is not included
until it is applied, and an address that is not staff is left
out, so a guest member is never reported. Each read is recorded, one row per
app, group, caller address and hour, and the App feeds page lists the
reads of the last 30 days. A token used from a second container shows there
as a second address.

## Security notes

- **Every app on the cookie domain is trusted equally.** The session cookie is
  scoped to `.<domain>` so one login serves every app, which also means any
  host on that domain can set, overwrite or shadow a cookie of the same name in
  a visitor's browser. The gateway refuses a request that carries more than one
  session cookie rather than honouring whichever came first, but a sibling that
  overwrites the shared cookie outright looks like a fresh login. Do not put an
  app you would not trust with your users' sessions on the same domain; give it
  its own domain and its own gateway.
- One-time codes are single-use, short-lived, attempt-capped, and stored only
  as a **keyed HMAC-SHA256** (so a stolen `auth.db` can't brute-force the small
  numeric code space offline); comparison is constant-time.
- No user enumeration: `/request` always responds the same way, and the OTP
  email is dispatched off the request path so response timing doesn't reveal
  whether an address is permitted.
- Rate limiting, shaped so that a stranger cannot spend a person's own sending
  allowance, a person can still get a code on the network they usually sign in
  from, and a shared egress IP (e.g. a hospital NAT) doesn't throttle many
  distinct users who type their codes correctly:
  - code sends are limited per (address, client IP) (`RATELIMIT_PER_EMAIL`), per
    address across all IPs in an hour (`RATELIMIT_PER_EMAIL_CEILING`) and in a
    day (`RATELIMIT_PER_EMAIL_DAILY`), and per client IP across all addresses
    (`RATELIMIT_SENDS_PER_IP`); an address that signed in from the same IP
    within 30 days passes the last three;
  - code requests are limited per client IP (`RATELIMIT_PER_IP`, generous);
  - wrong email or authenticator codes are limited per client IP
    (`RATELIMIT_WRONG_CODES_PER_IP`), refunded on a correct code;
  - the per-code attempt caps (`OTP_MAX_ATTEMPTS`, `OTP_MAX_TOTAL_ATTEMPTS`) bound
    guessing against any one code. Break-glass scans use a separate,
  more permissive per-IP limit (`RATELIMIT_BREAKGLASS_PER_IP`) since the 128-bit
  token — not the IP throttle — is the real boundary there.
- Six digits is the supported production default. Each code accepts at most
  `OTP_MAX_TOTAL_ATTEMPTS` wrong guesses from all networks together, after
  which the gateway deletes it. The count is stored with the code, so a restart
  does not reset it. Codes sent to one address from unfamiliar networks are
  limited per hour (`RATELIMIT_PER_EMAIL_CEILING`) and per day
  (`RATELIMIT_PER_EMAIL_DAILY`). The administrators are emailed when an address
  reaches the daily limit or a code is destroyed, so that a slow attempt is
  noticed. Every code a guesser triggers is also emailed to the person. The
  send limits are held in memory and reset when the gateway restarts, which
  only the server's operator can do.
- Open-redirect safe: the post-login target must be `https` and on a subdomain
  of the server domain. A login with no app target (or one resolving to the bare
  apex) lands on the auth host's own signed-in page instead — that host always
  has a valid certificate, so a missing/misconfigured `DEFAULT_REDIRECT` can never
  strand a user on a TLS error.
- Tight CSP, `Secure`/`HttpOnly`/`SameSite=Lax` cookies, no inline scripts.
  Admin state-changing actions require a signed CSRF token.
- Reversible secrets (break-glass tokens, admin TOTP seeds) are encrypted at
  rest with AES-256-GCM; a stolen `auth.db` is inert without the key.
- The session cookie is signed, not stored, so a single device's session can't be
  ended on its own; **"Sign out on every device"** ends all of a person's
  sessions at their next request (see "Signing out"), and no session outlives
  `SESSION_MAX_AGE`. **Policy revocation takes effect at the next request**:
  once the gateway restarts with the new settings, a person removed from the
  admin list loses the admin tier, and a person whose domain is de-listed is
  refused and their cookie cleared, at their next `/verify`, as group changes
  are. Break-glass sessions use a short, non-renewable
  TTL, end when their card is revoked or re-minted, and are never accepted by the
  admin UI.
- Break-glass target groups and DB group names cannot be the reserved roles
  `admin`/`user`/`guest`, so emergency access can never silently confer the admin
  tier, and no group can make a member of staff look like a guest. A card cannot
  target a group an app reads as its own role either, and a guest cannot be made
  a member of one (see [Break-the-glass QR codes](#break-the-glass-qr-codes)), so
  emergency access never confers an application's administrator role.

## Local development

```bash
go test ./...                       # unit + handler integration tests
CGO_ENABLED=0 go build -o auth .    # static binary
docker build -t vps-scaffold-auth . # image

# Run standalone with the log email backend (codes printed to stdout):
SESSION_SECRET=$(openssl rand -hex 32) \
AUTH_PUBLIC_URL=https://localhost DOMAIN=localhost \
ALLOWED_EMAIL_DOMAINS=example.com EMAIL_BACKEND=log \
COOKIE_INSECURE=true SQLITE_PATH=./auth.db \
./auth
```

For an end-to-end test through Caddy with self-signed certs and a dummy
protected app, see the auth doc in the scaffold (`docs/07-auth.md`).

## Layout

```
main.go                 entrypoint + graceful shutdown + -healthcheck probe
internal/config         env parsing + validation (fail fast)
internal/server         routes, handlers, embedded HTML templates
internal/session        HMAC-signed session / state / pending / CSRF cookies
internal/otp            one-time code generation + hashing
internal/store          Store interface + CGO-free SQLite implementation
internal/authz          domain/whitelist roles, group set, redirect validation
internal/email          smtp | resend | log backends
internal/totp           optional admin TOTP (pquerna/otp)
internal/secretbox      AES-256-GCM at-rest encryption for stored secrets
internal/breakglass     token gen, QR (boombuler), branded PDF (go-pdf/fpdf
                        + oksvg), async notifier
internal/ratelimit      in-memory token-bucket limiter
deploy/                 reference server wiring (compose, caddy, env)
```

## License

MIT
