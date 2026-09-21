-- RFC 8628 device authorization state for Hermes CLI OAuth login.
create table if not exists public.oauth_device_codes (
  device_code_hash text primary key,
  user_code text not null unique,
  client_id text not null,
  scope text,
  status text not null default 'pending' check (status in ('pending','approved','denied','consumed')),
  expires_at timestamptz not null,
  interval_seconds integer not null default 5,
  created_at timestamptz not null default now()
);
create index if not exists oauth_device_codes_user_code_idx on public.oauth_device_codes (user_code);
create index if not exists oauth_device_codes_expiry_idx on public.oauth_device_codes (expires_at);
alter table public.oauth_device_codes enable row level security;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.oauth_device_codes TO service_role;
