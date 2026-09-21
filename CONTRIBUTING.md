# Contributing

1. Keep credentials, tokens, database dumps, domains, IPs, and deployment identifiers out of commits.
2. Run `docker compose config` and `docker compose build` before opening a change.
3. Test OAuth discovery and MCP `tools/list` against a disposable deployment.
4. Do not test recipe creation, editing, or deletion against a real account without explicit approval.
