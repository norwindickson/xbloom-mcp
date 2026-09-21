#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
backup=${1:?Usage: $0 backups/file.dump}
[[ -f "$backup" ]] || { printf 'Backup not found: %s\n' "$backup" >&2; exit 1; }
set -a; . ./.env; set +a
printf 'This replaces all data in %s. Type RESTORE to continue: ' "$POSTGRES_DB" >&2
read -r confirmation
[[ "$confirmation" == RESTORE ]] || { printf 'Cancelled.\n' >&2; exit 1; }
docker compose exec -T db psql -U "$POSTGRES_USER" -d postgres -c "DROP DATABASE IF EXISTS \"$POSTGRES_DB\";" 
docker compose exec -T db psql -U "$POSTGRES_USER" -d postgres -c "CREATE DATABASE \"$POSTGRES_DB\";"
docker compose exec -T db pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists < "$backup"
docker compose exec -T db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "NOTIFY pgrst, 'reload schema';"
printf 'Restore completed.\n'
