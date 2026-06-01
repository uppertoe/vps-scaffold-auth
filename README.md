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

Add `import protected` to the app's Caddy snippet:

```caddyfile
# apps/dashboard/dashboard.caddy
dashboard.{$DOMAIN} {
    import protected
    reverse_proxy dashboard:3000
}
```

The app then reads identity from the `Remote-User`, `Remote-Email`, and
`Remote-Groups` request headers and does its own per-feature authorization off
them.

> **Trust model:** apps trust these headers because **only Caddy can reach
> them** — they publish no host ports, and Caddy strips any client-supplied
> `Remote-*` before injecting its own. Never expose a protected app directly.

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
admin tier you can require TOTP: set `TOTP_ENABLED=true`. Admins are enrolled on
first login (shown an `otpauth://` URL for their authenticator app) and
challenged for a code thereafter. Regular users stay code-only.

**Strongly recommended when using the admin UI** (below): the admin UI can mint
instant-grant break-glass credentials, so the admin tier should carry a second
factor.

### Staying signed in

The login page has a **"Keep me signed in"** checkbox. Unchecked, a session
lasts `SESSION_TTL` (default 12h); checked, it lasts `SESSION_REMEMBER_TTL`
(default 30 days). Both are still stateless cookies.

### Groups and the admin UI

Admins (anyone in the `admin` group) get a web UI on the `auth.<domain>` host:

- **`/admin/groups`** — define named groups (e.g. `whitelisted`) and manage their
  member emails. Memberships surface in `Remote-Groups` at next login/renewal.
- **`/admin/break`** — manage break-the-glass codes (below).
- **`/admin/branding`** — the global PDF card content (title/body/instructions),
  a logo, an optional glyph, and the five palette colours (default to the RCH
  palette). The logo also appears on the login page. Each break-glass code can
  **override any of these per card** on its detail page (blank fields inherit the
  global branding), so cards for different services can look distinct.
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
- Each code has a printable **PDF** (RCH-branded, with the QR), downloadable from
  its detail page, for lamination and placement. The card's title, body,
  instructions, logo, and an optional accent glyph are editable in the admin
  **PDF branding** page (`/admin/branding`); logos with text should be PNG/JPEG
  (the SVG rasteriser draws shapes, not fonts).

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
- Per-email and per-IP rate limiting.
- Open-redirect safe: the post-login target must be `https` and within the
  server domain.
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
