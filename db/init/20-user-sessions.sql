-- user_sessions: durable, encrypted store for XBloom MCP sessions.
-- Keyed by the MCP session / OAuth access token. The refresh_token column lets an
-- OAuth token rotation carry the logged-in session forward to the new access token.
--
-- Idempotent: safe to run whether or not the table already exists. The table was
-- originally created out-of-band with (access_token, encrypted_creds); this brings
-- it in line with the code in xbloom-mcp/index.ts.

create table if not exists public.user_sessions (
  access_token   text primary key,
  refresh_token  text,
  encrypted_creds text,
  expires_at     timestamptz,
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now()
);

-- Add any columns missing from a pre-existing table.
alter table public.user_sessions add column if not exists refresh_token   text;
alter table public.user_sessions add column if not exists encrypted_creds text;
alter table public.user_sessions add column if not exists expires_at      timestamptz;
alter table public.user_sessions add column if not exists created_at      timestamptz not null default now();
alter table public.user_sessions add column if not exists updated_at      timestamptz not null default now();

-- The OAuth authorization_code grant pre-creates a row (linking access_token to
-- refresh_token) BEFORE the user logs in, so encrypted_creds must be nullable. The
-- original out-of-band table declared it NOT NULL; relax that or those inserts 23502.
alter table public.user_sessions alter column encrypted_creds drop not null;

-- Backfill expiry for rows created before this column existed, so enforcing
-- expires_at > now() in the read path doesn't retroactively invalidate live sessions.
update public.user_sessions set expires_at = now() + interval '1 year' where expires_at is null;

-- merge-duplicates upsert on access_token needs a unique/PK constraint on it.
-- (Present automatically when the table is created above; guarded for the
-- pre-existing case in case it was created without one.)
do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conrelid = 'public.user_sessions'::regclass and contype in ('p', 'u')
      and conkey = array[
        (select attnum from pg_attribute
         where attrelid = 'public.user_sessions'::regclass and attname = 'access_token')
      ]
  ) then
    alter table public.user_sessions add constraint user_sessions_access_token_key unique (access_token);
  end if;
end $$;

-- refresh_token lookups during OAuth rotation must be unique.
create unique index if not exists user_sessions_refresh_token_key
  on public.user_sessions (refresh_token)
  where refresh_token is not null;

-- Only the service role (used by the Edge Function) touches this table.
alter table public.user_sessions enable row level security;
