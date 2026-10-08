# xBloom MCP Server

Self-hosted remote MCP server for xBloom coffee and tea recipes, intended for ChatGPT and Claude. It provides OAuth 2.0/PKCE, Streamable HTTP, SSE, per-client encrypted xBloom sessions, and eight MCP tools. A public HTTPS deployment is required before either cloud client can connect.

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
git clone https://github.com/norwindickson/xbloom-mcp.git
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

Copy `deploy/nginx.conf.example` into the HTTPS virtual host and adapt the hostname. Also add its `limit_req_zone` directive in Nginx's `http` scope (outside the `server` block); otherwise `nginx -t` fails. The proxy must preserve long-lived HTTP/SSE connections, disable buffering, and route `/mcp` and `/mcp/` to `http://127.0.0.1:8000` without redirecting the POST request.

Do not put an interactive login wall such as Authelia in front of `/mcp/`; the MCP server publishes its own OAuth metadata and PKCE/device flow.

After reloading Nginx, verify the MCP URL and both OAuth discovery documents:

```bash
curl -fsS http://127.0.0.1:8000/        # on the server: health JSON
curl -i https://mcp.example.com/mcp  # should be HTTP 401 with WWW-Authenticate
curl -fsS https://mcp.example.com/.well-known/oauth-authorization-server
curl -fsS https://mcp.example.com/.well-known/oauth-protected-resource
```

The local health request should return JSON. The public MCP request must return `401` with `WWW-Authenticate: Bearer resource_metadata=...`, which starts the clients' OAuth flow. The authorization-server document must advertise `authorization_endpoint`, `token_endpoint`, and `registration_endpoint` under the same public base URL. The protected-resource document must point back to the same authorization server. Proxy both `/.well-known/…` endpoints as shown in the Nginx example; forwarding only `/mcp/` breaks client OAuth discovery.

## Connect from ChatGPT

1. Deploy this server first and verify the public HTTPS endpoint and OAuth discovery above. Use your **actual** `XBLOOM_MCP_BASE_URL`, for example `https://mcp.example.com/mcp`; the example domain is not a working server.
2. In ChatGPT web, enable **Developer mode** under **Settings → Apps → Advanced settings** (or ask a workspace admin to enable it). In **Settings → Apps → Create**, create a custom MCP app named `xBloom`, set its server URL to your HTTPS `/mcp` URL, and select OAuth authentication.
3. Select **Scan Tools**, complete the OAuth authorization in your browser, check that eight tools appear, then select **Create**. In a new chat, enable the draft xBloom app from the tools menu. To use account tools, call `xbloom_login` with your xBloom account credentials (see the credential warning below). MCP authorization and xBloom account login are two separate steps.

**Plan limits:** Full custom-MCP read/write access is currently offered to ChatGPT Business and Enterprise/Edu. ChatGPT Pro can connect MCPs in developer mode with read/fetch-only permissions; this server's `xbloom_login` is a non-read action, so account tools may be unusable on Pro, not merely the recipe write tools. Workspace publication and who can access the app are controlled by the workspace admin. See [OpenAI's current developer-mode and MCP app guide](https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt).

## Connect from Claude

1. Deploy and verify your public HTTPS `/mcp` URL as above. In Claude **Free, Pro or Max**, open [Customize → Connectors](https://claude.ai/customize/connectors), choose **+ Add → Add custom connector**, name it `xBloom`, and enter your `/mcp` URL. Free accounts currently allow one custom connector.
2. Continue with OAuth sign-in. If asked how to identify the OAuth client, choose **Register automatically** so the server's `/register` endpoint provides a client ID. Finish **Add**, then click **Connect** to authorize.
3. In a conversation, enable the connector under **+ → Connectors**. To link your xBloom account, call `xbloom_login` with your credentials (see the warning below); then test `xbloom_account_profile` and `xbloom_list_recipes`.

On Claude Team/Enterprise, an organization owner must first add the custom web connector under **Organization settings → Connectors**; members then connect individually. Claude's remote connector calls originate from its cloud infrastructure, so a LAN-only or VPN-only endpoint will not work. See [Anthropic's current remote MCP connector guide](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp).

**Credential warning:** `xbloom_login` currently takes an xBloom email and password as MCP tool arguments. That means ChatGPT/Claude processes those credentials; this project does **not** yet provide a separate browser-only xBloom login flow. Do not use your primary account if that exposure is unacceptable. The server does not retain the password, but stores the resulting xBloom session encrypted. Never publish credentials in issues or logs.

**Security:** The server's OAuth tokens identify individual MCP client sessions; xBloom account login is separate. Review write/delete tool approvals in the client. Do not publish database or PostgREST ports or put an interactive reverse-proxy login wall in front of MCP/OAuth routes.

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
