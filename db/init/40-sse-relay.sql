-- SSE transport relay. The legacy HTTP+SSE transport opens a long-lived GET /sse
-- stream and POSTs messages to /message; the response must return on the stream. On
-- Supabase Edge those two requests can land on different isolates, so both the session
-- auth and the outbound message queue live here rather than in isolate memory:
--   POST /message  -> writes the response row to sse_outbox
--   GET  /sse loop -> polls sse_outbox and flushes rows onto its stream
-- Only the service role (the Edge Function) touches these; RLS on, no policies.

create table if not exists public.sse_sessions (
  session_id   text primary key,
  access_token text,
  expires_at   timestamptz not null,
  created_at   timestamptz not null default now()
);

create table if not exists public.sse_outbox (
  id         bigint generated always as identity primary key,
  session_id text not null,
  payload    jsonb not null,
  created_at timestamptz not null default now()
);

create index if not exists sse_outbox_session_idx on public.sse_outbox (session_id, id);

alter table public.sse_sessions enable row level security;
alter table public.sse_outbox   enable row level security;
