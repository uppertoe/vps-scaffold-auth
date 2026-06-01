# Standalone example

A complete, runnable deployment that brings its own Caddy reverse proxy, pulls
the prebuilt gateway image from GHCR, and includes a demo protected app — so you
can see the whole email-OTP `forward_auth` flow end to end.

```bash
cp .env.example .env     # edit DOMAIN, SESSION_SECRET, DATA_ENCRYPTION_KEY, email
docker compose up -d
```

Then visit `https://app.<DOMAIN>`: you'll be redirected to the login, enter your
email, receive a 6-digit code, and land on the demo app showing the
`Remote-User` / `Remote-Email` / `Remote-Groups` headers the gateway injected.
The admin UI lives at `https://auth.<DOMAIN>/admin` (admins only).

Files:

| File | Purpose |
|---|---|
| `docker-compose.yml` | caddy + auth (from GHCR) + a demo `whoami` app |
| `Caddyfile` | TLS, the `forward_auth` guard, and the two sites |
| `.env.example` | the settings; copy to `.env` |

Notes:
- **Pin the image** to a `:vX.Y.Z` tag in production instead of `:latest`.
- **Never publish the auth or app container's ports** — only Caddy may reach
  them; that header-trust boundary is the security model.
- Remove the `whoami` service once you've confirmed the flow, and protect your
  real apps by adding `import protected` to their Caddy site blocks.
- For running this inside an existing scaffold server repo (shared external
  `caddy` network) instead of standalone, use the compose in the parent
  [`deploy/`](../) directory.
