# vps-scaffold-auth

A minimal **email one-time-code `forward_auth` gateway** for the
[vps-scaffold](https://github.com/uppertoe/vps-base-template) family. It puts a
passwordless login wall in front of any web app behind Caddy: users enter their
email, receive a 6-digit code, type it in, and get a session — no passwords, no
passkeys, no third-party identity provider.

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
               │  import protected  ─▶  forward_auth GET auth:8080/verify
               │                          ├─ valid session → 200 + Remote-User/Email/Groups → upstream app
               │                          └─ no session    → 302 to auth.example.com/login
               ▼
            auth.example.com  ── login page → email → 6-digit code → signed-cookie session
```

1. Caddy calls `GET /verify` on every request to a protected app.
2. No/invalid session → `/verify` returns a 302 to the login page.
3. User enters email → a 6-digit code is emailed (single-use, ~10 min).
4. User types the code → an HMAC-signed session cookie is set on `.example.com`
   (shared across all app subdomains).
5. `/verify` now returns 200 plus `Remote-User`, `Remote-Email`, and
   `Remote-Groups`, which Caddy forwards to the app.

`Remote-Groups` is a **comma-separated set**: the base role (`admin` or `user`)
followed by any DB-managed groups the user belongs to (e.g.
`user,whitelisted`). The role is always present, so existing role-equality
matchers keep working — but matchers that want the richer groups should test for
membership in the list. The group set is computed at login and re-computed when a
session renews, so membership changes take effect within `SESSION_RENEW_AFTER`.

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

Add one `import` line to the app's Caddy snippet — the last argument is the
app's upstream address. The guard runs `forward_auth` **and** proxies to the
upstream, so there's no separate `reverse_proxy` line:

```caddyfile
# apps/dashboard/dashboard.caddy
dashboard.{$DOMAIN} {
    import protected dashboard:3000
}
```

The app then reads identity from the `Remote-User`, `Remote-Email`, and
`Remote-Groups` request headers and does its own per-feature authorization off
them.

> **Trust model:** apps trust these headers because **only Caddy can reach
> them** — they publish no host ports, and Caddy strips any client-supplied
> `Remote-*` before injecting its own. Never expose a protected app directly.
>
> **The session cookie never reaches the app.** It's scoped to `.<domain>`, so
> the browser sends it to every app subdomain, and `forward_auth` would otherwise
> pass it through to the backend. Since the cookie is a stateless, estate-wide
> bearer credential with no per-session revocation, an app that received it could
> replay it against every other app. Each guard therefore strips
> `vps_auth_session` from the upstream request automatically (via the
> `strip_auth_cookie` snippet folded into it), leaving the app's own cookies
> intact. Apps take identity from the `Remote-*` headers, never the cookie. If you
> hand-roll a `reverse_proxy` instead of using a guard, `import strip_auth_cookie`
> inside it.

#### Per-app access

`import protected` lets in **any** signed-in user. To restrict an app to
particular people, the access rule lives in **that app's own `.caddy` snippet**
(the scaffold's per-app folder), and the gateway enforces it. Authentication
stays global (`ALLOWED_EMAIL_DOMAINS` is the superset of who can sign in *at
all*); each app then narrows to its own subset (the upstream is the last arg):

```caddyfile
# only @rch.org.au may open this one
clinical.{$DOMAIN}  { import protected_domains "rch.org.au" clinical:3000 }
# two domains may open this one
shared.{$DOMAIN}    { import protected_domains "rch.org.au partner.com" shared:3000 }
# members of a group (manage membership in /admin/groups)
reports.{$DOMAIN}   { import protected_groups  "reports_team" reports:3000 }
# in a domain OR a group (here: all RCH staff, plus named external guests)
dash.{$DOMAIN}      { import protected_access   "rch.org.au" "dash_guests" dash:3000 }
```

Guard summary (domains/groups are space- or comma-separated; `<up>` is the app's
upstream `host:port`, always the **last** argument):

| Snippet | Grants access to | Login hint + early decline? |
|---|---|---|
| `import protected <up>` | any signed-in user (**not** break-glass) | no |
| `import protected_domains "<domains>" <up>` | signed-in users at a listed email domain | **yes** |
| `import protected_domains_labeled "<domains>" "<label>" <up>` | same, but the hint/decline shows `<label>` instead of listing the domains | **yes** |
| `import protected_domains_alt "<domains>" "<url>" "<label>" <up>` | same, plus a "sign in another way" link to `<url>` for non-domain users | **yes** |
| `import protected_groups "<groups>" <up>` | members of a listed group, or a break-glass card whose target group is listed | no |
| `import protected_admin <up>` | admins only (= `protected_groups "admin"`); for a separate admin entrance | no |
| `import protected_access "<domains>" "<groups>" <up>` | in a listed domain **OR** a listed group | yes (by domain) |

A signed-in user who isn't allowed on an app is **not** bounced to login (they
*are* authenticated); they get a "no access to this page" page with a sign-in
link, and their session is left intact so apps they *can* reach keep working.
Always use these snippets rather than hand-rolling `forward_auth`: each one
declares its requirement in a single `X-Auth-Policy` header set with `header_up`,
which **replaces** any client-sent value — so a client can't inject or widen it,
and there's no per-guard "delete the rest" list to keep in sync as features are
added. A custom guard that omits `X-Auth-Policy` is treated as a plain
`protected` (any signed-in user), and the gateway logs a warning if it still
sends the old `X-Auth-Require-*` headers, so an unmigrated guard is caught loudly
rather than silently failing open. Each guard also owns the `reverse_proxy` to
the upstream and strips the session cookie there (see the trust-model note
above), so neither is something an app author can forget; an app that genuinely
needs custom proxy options hand-rolls `forward_auth` + `reverse_proxy` and adds
`import strip_auth_cookie` itself.

**Early hint + decline (any route with a domain).** Whenever a route declares a
required domain (`protected_domains`, or the domain side of `protected_access`),
the login page shows the expected domain ("This page is for `rch.org.au` email
addresses") and an address whose domain can't qualify is declined *before* a
code is sent — so a wrong-domain user isn't emailed a code only to hit a wall
after logging in. A **group-only route** (`protected_admin` / `protected_groups`)
declares no domain, so it neither hints nor declines — that's the door for people
who legitimately don't match the domain. This is a UX courtesy, **not** the
security boundary: the requirement rides in the (client-modifiable) login URL, so
the authoritative check always happens at `/verify` with Caddy's trusted header.

When a route allows several domains, enumerating them gets unwieldy — use
`protected_domains_labeled "<domains>" "<label>"` to show a phrase instead:
*"This page is for **an approved Victorian health service** email address."* The
full domain list still drives the actual hint/decline; only the wording changes.

**Admins (and other non-domain users) get their own door.** Admins are **not**
auto-allowed. The domain door declines any address that doesn't match its
domain — admins included — so don't expect an off-domain admin to come through
the main gate. Give them a separate group-gated entrance with
`import protected_admin` (no domain → no hint, no decline). Admins whose email
already matches the app's domain don't need it — they pass the gate.

A path-based admin entrance on the same host (admin features live under `/admin`).
The staff door uses `protected_domains_alt` so a declined non-domain user is
pointed at the admin door instead of being stranded:

```caddyfile
app.{$DOMAIN} {
    @admin path /admin*
    handle @admin {
        import protected_admin app:3000     # admins only; no hint, no early decline
    }
    handle {
        import protected_domains_alt "rch.org.au" "https://app.{$DOMAIN}/admin" "Administrators sign in here" app:3000
    }
}
```

The "Administrators sign in here" link appears as small text on the login and
decline pages. Its URL is **re-validated server-side to be within your domain**
before it's ever rendered, so a tampered login URL can't turn it into an
off-site (phishing) link. If an off-domain admin needs the *whole* app (not just
`/admin`), point a second host at the same backend instead:
`admin.app.{$DOMAIN} { import protected_admin app:3000 }`.

Per-route is just per-route Caddy: put a guard inside a `handle @path { … }`
block so one app can have, say, a staff entrance and a separate emergency one
(see the worked example in [`deploy/standalone/Caddyfile`](deploy/standalone/Caddyfile)).

#### Mixing public and protected routes

Not every route needs a login. A webhook receiver, a health check, or a public
landing page can sit on the same host as a protected app — give the public paths
a plain `reverse_proxy` (no guard) and let a fallback `handle` protect the rest:

```caddyfile
app.{$DOMAIN} {
    # Public — no login, no session (e.g. a webhook receiver + health check).
    @public path /webhooks/* /healthz
    handle @public {
        reverse_proxy app:3000 {
            import strip_auth_cookie   # still strip — see the note below
        }
    }
    # Everything else requires a signed-in user at the domain.
    handle {
        import protected_domains "rch.org.au" app:3000
    }
}
```

A fully public app is just a host with no guard at all:
`public.{$DOMAIN} { reverse_proxy public:3000 { import strip_auth_cookie } }`.

> **Strip the cookie on public routes too.** The session cookie is scoped to
> `.<domain>`, so the browser sends it to **every** subdomain and every path —
> public ones included. A guard strips it automatically, but a plain
> `reverse_proxy` does not, so a public backend would receive the estate-wide
> bearer token that protected routes carefully withhold. `import
> strip_auth_cookie` inside any public (or otherwise untrusted) backend's
> `reverse_proxy` closes that. It only scrubs the cookie from the request Caddy
> forwards upstream — it sends nothing to the browser, so it does **not** log the
> user out; their session is untouched and still works on protected routes.

## Configuration

All settings come from the environment; see [`deploy/.env.example`](deploy/.env.example)
for the annotated list. Key ones:

| Variable | Purpose |
|---|---|
| `AUTH_PUBLIC_URL` | Base URL of the `auth.<domain>` site |
| `ALLOWED_EMAIL_DOMAINS` | CSV of domains whose users may sign in |
| `ADMIN_EMAILS` | CSV of explicit admin addresses |
| `SESSION_SECRET` | 32+ random bytes (`openssl rand -hex 32`) |
| `COOKIE_DOMAIN` | Leading-dot domain for the shared session cookie |
| `EMAIL_BACKEND` | `smtp` \| `resend` \| `log` |
| `TOTP_ENABLED` | Optional admin TOTP (off by default) |
| `DOMAIN` | The server domain (provided by the server `.env`) |

### Admin two-factor (optional)

Magic codes inherit the security of the user's inbox. For the higher-trust
admin tier you can require TOTP: set `TOTP_ENABLED=true`. Once enabled, an admin
must enter a 6-digit authenticator code after the email step; regular users stay
code-only.

**Enabling TOTP re-challenges existing admin sessions.** Admin sessions minted
before TOTP was turned on carry no second-factor assurance, so the gateway stops
honouring them for admin access (at `/verify` and the `/admin` UI) and bounces
them to a fresh login that runs the TOTP step — the switch can't be bypassed by
riding a pre-existing cookie. **Provision admins' secrets before you flip
`TOTP_ENABLED`** (bootstrap the first one with the `-totp-enroll` CLI below):
once it's on, an admin with no secret is locked out until one is issued.

**Secrets are admin-provisioned, never self-enrolled.** A login only proves
control of the inbox — so letting a login *bootstrap* its own TOTP secret would
hand the second factor to whoever controls the inbox, defeating the point. So
secrets are issued out of band:

- **First admin / bootstrap.** Run the one-off CLI in the same container and
  environment as the server (so it shares the at-rest encryption key):
  ```bash
  docker compose exec auth auth -totp-enroll you@example.com
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

### Staying signed in

The login page has a **"Keep me signed in"** checkbox. Unchecked, a session
lasts `SESSION_TTL` (default 2h); checked, it lasts `SESSION_REMEMBER_TTL`
(default 24h). Both are still stateless cookies, and both slide on activity
(renewing every `SESSION_RENEW_AFTER`, default 1h, which is also where policy
revocation and group changes take effect).

### Groups and the admin UI

Admins (anyone in the `admin` group) get a web UI on the `auth.<domain>` host:

- **`/admin/groups`** — define named groups (e.g. `whitelisted`) and manage their
  member emails. Memberships surface in `Remote-Groups` at next login/renewal.
- **`/admin/break`** — manage break-the-glass codes (below).
- **`/admin/access`** — the access log: login attempts and outcomes, plus which
  apps each person has reached (deduplicated to one row per user/app/hour, not
  per request). Filter by email. Rows are pruned after `AUDIT_RETENTION`
  (default one year; `0` keeps them forever).
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

- Each code has a unique **label** (e.g. "Angiography Lab 1"), a note, and a
  **target group** (e.g. `code_stroke_break_glass`) that the granted session
  carries.
- **The target group scopes the card to specific apps/routes.** A break-glass
  session is *deny-by-default*: it reaches only an app (or route) whose Caddy
  guard lists that group — `import protected_groups "code_stroke_break_glass"`.
  A plain `import protected` app rejects it, and a domain-gated app rejects it
  (the card has no email domain). So a card opens exactly the location(s) you
  opt in, not the whole estate. Use a dedicated group per card for the tightest
  scope. A holder who reaches a non-covered app gets the "no access" page (with
  a sign-in link), and their card keeps working everywhere it *is* allowed.
- **Scanning is an instant grant**: the token in the QR URL is the only
  credential, by design. The scan is rate-limited, **logged synchronously**
  (label, client IP, user-agent, time), and **notifies admins** out of band via
  email and/or a webhook — never blocking the grant.
- The granted session is **short-lived** (`BREAKGLASS_SESSION_TTL`, default 8h,
  overridable on the admin Settings page) and is **never renewed**, so it always
  expires at that absolute timeout.
- Codes can be **revoked** (blocks future scans immediately; sessions already
  granted lapse on their own short timeout) and **re-minted** (issues a fresh
  token, invalidating every already-printed card for that location).
- Each code has a printable **PDF** (with the QR), downloadable from its detail
  page, for lamination and placement. The card's title, body, instructions, card
  logo, and an optional accent glyph are editable on the admin **Branding** page
  (`/admin/branding`); logos with text should be PNG/JPEG (the SVG rasteriser
  draws shapes, not fonts).

> **Accepted risk:** a break-glass QR is a bearer secret left in the open. Anyone
> who photographs a card gets temporary, group-scoped access with no second
> factor. That is the point — the mitigations are the short TTL, the mandatory
> audit log, the admin notification on every use, and instant revocation.

## Security notes

- One-time codes are single-use, short-lived, attempt-capped, and stored only
  as a **keyed HMAC-SHA256** (so a stolen `auth.db` can't brute-force the small
  numeric code space offline); comparison is constant-time.
- No user enumeration: `/request` always responds the same way, and the OTP
  email is dispatched off the request path so response timing doesn't reveal
  whether an address is permitted.
- Per-email and per-IP rate limiting. The per-email limit plus the per-code
  attempt cap are the primary brute-force bounds; the per-IP limit is a secondary
  guard, kept generous (default `60/15m`) so a shared egress IP (e.g. a hospital
  NAT) doesn't throttle many distinct users. Break-glass scans use a separate,
  more permissive per-IP limit (`RATELIMIT_BREAKGLASS_PER_IP`) since the 128-bit
  token — not the IP throttle — is the real boundary there.
- Open-redirect safe: the post-login target must be `https` and on a subdomain
  of the server domain. A login with no app target (or one resolving to the bare
  apex) lands on the auth host's own signed-in page instead — that host always
  has a valid certificate, so a missing/misconfigured `DEFAULT_REDIRECT` can never
  strand a user on a TLS error.
- Tight CSP, `Secure`/`HttpOnly`/`SameSite=Lax` cookies, no inline scripts.
  Admin state-changing actions require a signed CSRF token.
- Reversible secrets (break-glass tokens, admin TOTP seeds) are encrypted at
  rest with AES-256-GCM; a stolen `auth.db` is inert without the key.
- The session cookie is stateless, so an *individual* session can't be revoked
  before expiry — keep `SESSION_TTL` moderate. However, **policy revocation is
  enforced at renewal**: a principal removed from the admin list or a de-listed
  domain is denied (and their cookie cleared) at the next `/verify` past
  `SESSION_RENEW_AFTER`, and group/role changes are recomputed there too.
  Break-glass sessions use a short, non-renewable TTL so revoking a code bounds
  exposure tightly, and are never accepted by the admin UI.
- Break-glass target groups and DB group names cannot be the reserved roles
  `admin`/`user`, so emergency access can never silently confer the admin tier.

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
internal/otp            6-digit code generation + hashing
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
