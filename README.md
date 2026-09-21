# xBloom MCP Server

Self-hosted MCP server for xBloom coffee and tea recipes. It provides OAuth 2.0/PKCE, RFC 8628 device login for CLI clients, Streamable HTTP, SSE, per-client encrypted xBloom sessions, and eight MCP tools.

## What runs

- Deno MCP application
- PostgreSQL for OAuth/session state
- PostgREST as a private database API
- Nginx or another HTTPS reverse proxy in front of `https://your-host/mcp`

PostgreSQL and PostgREST have no host ports. MCP binds only to `127.0.0.1:8000`.

## Requirements

- Linux server with Docker Engine and Compose v2
- A DNS name with HTTPS for the MCP endpoint
- Nginx/Caddy or another reverse proxy

## Install

```bash
git clone https://github.com/YOUR_USER/xbloom-mcp.git
cd xbloom-mcp
./scripts/generate-env.sh
```

Set the public URL in `.env`:

```dotenv
XBLOOM_MCP_BASE_URL=https://mcp.example.com/mcp
```

`generate-env.sh` creates the database password, PostgREST JWT secret, service-role JWT, and AES session-encryption key. Keep `.env` mode `600`; never commit or paste it.

Validate and start:

```bash
docker compose config
docker compose build
docker compose up -d
docker compose ps
```

All three services should become healthy/running. Database initialization scripts run only on a new PostgreSQL volume. For an existing volume, apply a new migration manually and notify PostgREST to reload its schema.

## HTTPS reverse proxy

Copy `deploy/nginx.conf.example` into the HTTPS virtual host and adapt the hostname. The proxy must preserve long-lived HTTP/SSE connections, disable buffering, and route `/mcp/` to `http://127.0.0.1:8000`.

Do not put an interactive login wall such as Authelia in front of `/mcp/`; the MCP server publishes its own OAuth metadata and PKCE/device flow.

After reloading Nginx, verify:

```bash
curl -fsS https://mcp.example.com/mcp
curl -fsS https://mcp.example.com/.well-known/oauth-authorization-server
```

The metadata must advertise `authorization_endpoint`, `device_authorization_endpoint`, `token_endpoint`, and `registration_endpoint` under the same public base URL.

## Hermes login

Register and authenticate the server from Hermes:

```bash
hermes mcp add xbloom --url https://mcp.example.com/mcp --auth oauth
hermes mcp login xbloom --flow device
hermes mcp test xbloom
```

Open the displayed verification URL, enter the terminal code, and approve. A successful test reports eight discovered tools. MCP OAuth authorization and the xBloom account login are separate; call `xbloom_login` once before private account tools.

## Tools and safety

- `xbloom_login` — links an xBloom account to the current MCP session
- `xbloom_account_profile` — verifies the linked account
- `xbloom_list_recipes`
- `xbloom_create_recipe`
- `xbloom_create_tea_recipe`
- `xbloom_edit_recipe`
- `xbloom_delete_recipe`
- `xbloom_fetch_recipe`

The application never logs passwords, bearer tokens, or credential payloads. xBloom session credentials are encrypted at rest with `SESSION_ENCRYPTION_KEY`. Account mutations must be approval-gated by the MCP client or agent using this server.

## Backup and restore

```bash
./scripts/backup-db.sh
./scripts/restore-db.sh backups/xbloom-YYYYMMDDTHHMMSSZ.dump
```

Backups contain OAuth/session rows and encrypted xBloom credentials. Store them offline with mode `600`; never commit or upload them.

## Operations

```bash
docker compose ps
docker compose logs --tail=100 db postgrest mcp
docker compose restart mcp
```

For an update: back up the database, run `docker compose config`, build the new image, restart, then verify health, OAuth discovery, MCP initialize, and `tools/list`. Roll back the image/source if those checks fail.

## Security checklist

- Use a unique HTTPS hostname and valid TLS certificate.
- Keep `.env`, backups, and logs out of Git.
- Do not publish PostgreSQL, PostgREST, or MCP directly to the Internet.
- Apply rate limiting and a request-size limit at the reverse proxy.
- Rotate `POSTGREST_JWT_SECRET`, `SUPABASE_SERVICE_ROLE_KEY`, and `SESSION_ENCRYPTION_KEY` together only with a planned session/database migration.
- Never place xBloom credentials in issues, screenshots, CI logs, or chat.
