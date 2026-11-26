# Standalone example

A complete, runnable deployment that brings its own Caddy reverse proxy, pulls
the prebuilt gateway image from GHCR, and includes a demo protected app — so you
can see the whole email-OTP `forward_auth` flow end to end.

```bash
cp .env.example .env     # edit DOMAIN, SESSION_SECRET, DATA_ENCRYPTION_KEY, email
docker compose up -d
```

First sign in to the admin pages at `https://auth.<DOMAIN>/admin` with an
address in `ADMIN_EMAILS`, open the Demo app under Apps, and give its User role
to a domain group, a list or yourself. Then visit `https://app.<DOMAIN>`: you
will be sent to sign in, receive a 6-digit code, and land on the demo app, which
shows the `Remote-User`, `Remote-Email` and `Remote-Roles` headers the gateway
sent.

Files:

| File | Purpose |
|---|---|
| `docker-compose.yml` | caddy + auth (from GHCR) + a demo `whoami` app |
| `Caddyfile` | TLS, the role guard, and the two sites |
| `app-roles.tsv` | the demo app's roles (`APP_ROLES_FILE`) |
| `.env.example` | the settings; copy to `.env` |

Notes:
- **Pin the image** to a `:vX.Y.Z` tag in production instead of `:latest`.
- **Never publish the auth or app container's ports** — only Caddy may reach
  them; that header-trust boundary is the security model.
- Remove the `whoami` service once you've confirmed the flow, and protect your
  real apps by declaring their roles in `app-roles.tsv` and adding
  `import role "<app>" "<role>" <upstream>` to their Caddy site blocks.
- For running this inside an existing scaffold server repo (shared external
  `caddy` network) instead of standalone, use the compose in the parent
  [`deploy/`](../) directory.
