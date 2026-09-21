#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
mkdir -p backups
set -a; . ./.env; set +a
file="backups/xbloom-$(date -u +%Y%m%dT%H%M%SZ).dump"
docker compose exec -T db pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc > "$file"
chmod 600 "$file"
printf 'Backup written: %s\n' "$file"
