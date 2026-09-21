-- PostgREST uses service_role for all application requests.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO service_role;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO service_role;

-- The anonymous role has no table privileges. OAuth/MCP requests must carry the
-- signed service_role JWT generated for this private PostgREST instance.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon;
