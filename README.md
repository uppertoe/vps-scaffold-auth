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
   `Remote-Groups` (`admin`/`user`), which Caddy forwards to the app.

Sessions are **stateless signed cookies** — no session store. The only
persisted state is single-use OTP codes (SHA-256 hashed) and optional admin
TOTP secrets, in a small **SQLite** file. No Postgres, no Redis.

## Using it in a server repo

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

## Security notes

- One-time codes are single-use, short-lived, attempt-capped, and stored only
  as SHA-256 hashes; comparison is constant-time.
- No user enumeration: `/request` always responds the same way.
- Per-email and per-IP rate limiting.
- Open-redirect safe: the post-login target must be `https` and within the
  server domain.
- Tight CSP, `Secure`/`HttpOnly`/`SameSite=Lax` cookies, no inline scripts.
- The session cookie is stateless, so individual sessions can't be revoked
  before expiry — keep `SESSION_TTL` moderate.

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
internal/session        HMAC-signed session / state / pending cookies
internal/otp            6-digit code generation + hashing
internal/store          Store interface + CGO-free SQLite implementation
internal/authz          domain/whitelist roles + redirect validation
internal/email          smtp | resend | log backends
internal/totp           optional admin TOTP (pquerna/otp)
internal/ratelimit      in-memory token-bucket limiter
deploy/                 reference server wiring (compose, caddy, env)
```

## License

MIT
