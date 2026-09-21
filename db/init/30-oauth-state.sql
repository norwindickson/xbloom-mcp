-- OAuth durable state for PKCE + registered-client validation.
--
-- These are written by one request (/register, /authorize) and read by another
-- (/authorize, /token) that may land on a DIFFERENT Edge isolate, so the state must
-- live in the DB, not in module memory — the same statelessness that broke sessions.
--
-- Only the service role (the Edge Function) touches these tables; RLS is enabled with
-- no policies so nothing else can read them.

-- Dynamically-registered clients (from /register). Lets /authorize enforce exact
-- redirect_uri matches, closing the open-redirect hole.
create table if not exists public.oauth_clients (
  client_id     text primary key,
  redirect_uris jsonb not null default '[]'::jsonb,
  created_at    timestamptz not null default now()
);

-- Short-lived authorization codes (from /authorize, consumed once at /token). Holds the
-- PKCE challenge so the token exchange can prove the caller started the flow.
create table if not exists public.oauth_codes (
  code                  text primary key,
  code_challenge        text,
  code_challenge_method text,
  redirect_uri          text not null,
  client_id             text,
  expires_at            timestamptz not null,
  created_at            timestamptz not null default now()
);

create index if not exists oauth_codes_expires_at_idx on public.oauth_codes (expires_at);

alter table public.oauth_clients enable row level security;
alter table public.oauth_codes   enable row level security;
