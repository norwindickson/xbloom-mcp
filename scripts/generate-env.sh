#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

if [[ -e .env ]]; then
  printf '.env already exists; refusing to overwrite.\n' >&2
  exit 1
fi

export POSTGRES_PASSWORD="$(openssl rand -hex 24)"
export POSTGREST_JWT_SECRET="$(openssl rand -hex 48)"
export SESSION_ENCRYPTION_KEY="$(openssl rand -hex 32)"

b64url() { printf '%s' "$1" | openssl base64 -A | tr '+/' '-_' | tr -d '='; }
header=$(b64url '{"alg":"HS256","typ":"JWT"}')
payload=$(b64url '{"role":"service_role","iss":"xbloom-mcp"}')
signature=$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -hmac "$POSTGREST_JWT_SECRET" -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
export SUPABASE_SERVICE_ROLE_KEY="$header.$payload.$signature"

sed -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$POSTGRES_PASSWORD|" \
    -e "s|^POSTGREST_JWT_SECRET=.*|POSTGREST_JWT_SECRET=$POSTGREST_JWT_SECRET|" \
    -e "s|^SUPABASE_SERVICE_ROLE_KEY=.*|SUPABASE_SERVICE_ROLE_KEY=$SUPABASE_SERVICE_ROLE_KEY|" \
    -e "s|^SESSION_ENCRYPTION_KEY=.*|SESSION_ENCRYPTION_KEY=$SESSION_ENCRYPTION_KEY|" \
    .env.example > .env
chmod 600 .env
printf 'Created .env with generated secrets. Set XBLOOM_MCP_BASE_URL before starting.\n'
