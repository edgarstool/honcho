# Honcho MCP Server

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server for [Honcho](https://honcho.dev). The hosted path is a Cloudflare Worker; the same tools also run over stdio and over Streamable HTTP (`bun src/http.ts`) for Docker and other long-lived process hosts.

## Quickstart: Use the Hosted Server

1. Get an API key at <https://app.honcho.dev>
2. Add Honcho to your Claude Desktop config:

```json
{
  "mcpServers": {
    "honcho": {
      "command": "bunx",
      "args": [
        "mcp-remote",
        "https://mcp.honcho.dev",
        "--header",
        "Authorization:${AUTH_HEADER}"
      ],
      "env": {
        "AUTH_HEADER": "Bearer <your-honcho-key>"
      }
    }
  }
}
```

Every workspace-scoped tool takes a `workspace_id` argument. If you set `X-Honcho-Workspace-ID` on the connection, that value fills `workspace_id` when the argument is omitted. Use `list_workspaces` to discover IDs.

## Naming your client

Set `X-Honcho-Plugin` on the connection to name whatever configured it: `<name>/<version>` for an integration (`cursor-honcho/0.2.0`), or a short slug for a hand-written config (`cursor`). Without it, the server records the caller's `User-Agent`. Optional; nothing changes without it.

## Available Tools

**Workspace:** `list_workspaces` (id, metadata, created_at), `create_workspace` (get-or-create with optional metadata), `inspect_workspace` (aggregates metadata, configuration, and peer/session IDs), `search` (semantic search scoped by optional peer/session/scope params), `workspace_chat` (reasoned answer across all peers; optional session / scope recall bounds), `get_metadata`, `set_metadata`

**Peers:** `create_peer`, `list_peers`, `chat` (reasoned answer about one peer; optional session / scope / sessions recall bounds), `get_peer_card`, `set_peer_card`, `get_peer_context`, `get_representation` (optional session / scope / sessions recall bounds)

**Sessions:** `create_session` (optional `scopes` to join at creation), `list_sessions`, `delete_session`, `clone_session`, `add_peers_to_session`, `remove_peers_from_session`, `get_session_peers`, `inspect_session`, `add_messages_to_session`, `get_session_messages`, `get_session_message`, `get_session_context` (optional `peer_target` with `peer_perspective` / `scope` / `limit_to_session` to include a peer's representation and card)

**Scopes:** `list_scopes`, `get_scope_sessions`, `create_scope` (get-or-create with optional metadata), `add_sessions_to_scope`, `remove_session_from_scope`, `get_scope_status` (backfill progress per session)

**Conclusions:** `list_conclusions`, `query_conclusions`, `create_conclusions`, `delete_conclusion`

**System:** `schedule_dream`, `get_queue_status`

## Architecture

```
src/
  index.ts              # Worker entry point — parse config, delegate to MCP handler
  stdio.ts              # Local stdio host (bun src/stdio.ts)
  http.ts               # Streamable HTTP host (bun src/http.ts / Docker)
  server.ts             # createServer() — registers all tools on an McpServer
  config.ts             # HonchoConfig, parseConfig(), Honcho clients + X-Honcho-* headers
  types.ts              # ToolContext, result helpers
  tools/
    workspace.ts        # inspect, list, search, workspace_chat, metadata
    peers.ts            # CRUD, chat (session / scope / sessions recall bounds), card, context, representation
    scopes.ts           # list/create scopes, scope membership, backfill status
    sessions.ts         # CRUD, peers, messages, inspect, context, clone
    conclusions.ts      # list, query, create, delete
    system.ts           # dream, queue status
```

Built on:

- **[agents](https://www.npmjs.com/package/agents)** — `createMcpHandler` for Cloudflare Workers
- **[@modelcontextprotocol/sdk](https://www.npmjs.com/package/@modelcontextprotocol/sdk)** — `McpServer` for tool registration
- **[@honcho-ai/sdk](https://www.npmjs.com/package/@honcho-ai/sdk)** v2 — Honcho TypeScript SDK

## Self-Hosted Honcho

If you run Honcho yourself, point this server at it with `HONCHO_API_URL`.
When unset, requests go to `https://api.honcho.dev`.

`HONCHO_TIMEOUT_MS` caps each Honcho API request (default 300000, 5 minutes).
Raise it if `chat` runs longer than that on your model. A reverse proxy in
front of the HTTP host needs a read timeout at least this long.

**Cloudflare Worker (`bun run dev` / `bun run deploy`):** create `mcp/.dev.vars`:

```
HONCHO_API_URL=http://127.0.0.1:28000
```

For a deployed Worker: `wrangler secret put HONCHO_API_URL`.

To report errors to Sentry, set `SENTRY_DSN` the same way
(`wrangler secret put SENTRY_DSN`). The HTTP and stdio hosts read `SENTRY_DSN`
from the environment. Without it, error reporting is a no-op on every host.

## HTTP host

For Docker or any platform that runs a long-lived process, use the Streamable
HTTP entry instead of the Worker. Clients keep the same `mcp-remote` shape as
`https://mcp.honcho.dev`. Sessions live in process memory — run one instance.

```bash
cd mcp && bun install
HONCHO_API_URL=http://127.0.0.1:8000 bun run http
```

```bash
bunx mcp-remote http://127.0.0.1:3000 \
  --header "Authorization:Bearer <key>"
```

Auth is the `Authorization: Bearer` header (same as the Worker). Established
sessions still require that same bearer. Optional `X-Honcho-Workspace-ID`
fills `workspace_id` when the tool argument is omitted, and optional
`X-Honcho-Plugin` names the caller (see [Naming your client](#naming-your-client)).

`HOST` defaults to `0.0.0.0`, `PORT` to `3000`. `GET /health` is unauthenticated.
MCP is served at `/` and `/mcp`. Idle sessions expire after
`MCP_SESSION_IDLE_MS` (default 30 minutes); `MCP_SESSION_MAX` (default 128)
caps concurrent sessions.

A platform start command is `bun src/http.ts` (or `bun run http` from `mcp/`).
This repo does not ship a `vercel.json`; serverless replicas do not share the
in-memory session map.

### Opt-in OAuth access tokens (EDG-15 stage)

By default the bearer token is the caller's own Honcho API key, unchanged.
Operators can instead front the server with an OAuth 2.1 authorization
server: callers present an RS256 access token, the server verifies it
against the issuer's JWKS (signature, `iss`, `aud`, `exp`, `nbf`, scope),
and maps the token's `(client_id, sub)` server-side to the Honcho
workspace(s) — and optionally the observer peer — it may touch. The
backend Honcho key (`HONCHO_API_KEY`) stays server-side and is never sent
to clients; self-declared `workspace_id`/`peer_id` arguments can only pick
among the mapped grant, never widen it, and the check runs on every tool
call, not just at initialize.

```bash
MCP_OAUTH_ENABLED=1 \
MCP_OAUTH_ISSUER=https://auth.example \
MCP_OAUTH_AUDIENCE=https://mcp.example/mcp \
MCP_OAUTH_JWKS_URL=https://auth.example/jwks.json \
MCP_OAUTH_REQUIRED_SCOPE=mcp \
MCP_OAUTH_MAPPING='{"mappings":[{"client_id":"c","sub":"s","workspace_id":"w","peer_id":"p"}]}' \
HONCHO_API_KEY=<server-side honcho key> \
bun run http
```

**Revocation.** A signed, unexpired token can still have been revoked,
and JWKS verification cannot see that. Point the adapter at the
authorization server's RFC 7662 introspection endpoint and it asks about
the presented token on every request — there is no positive-result
cache, and a timeout, a non-200, or a reply that disagrees with the
token's own claims fails closed as `401 invalid_token`:

```bash
MCP_OAUTH_INTROSPECT_URL=https://auth.example/introspect \
MCP_OAUTH_INTROSPECT_CLIENT_ID=<confidential client id> \
MCP_OAUTH_INTROSPECT_CLIENT_SECRET=<confidential client secret> \
```

The endpoint must be `https://` (the request carries client credentials
in an HTTP Basic header). Configuring the URL without credentials, or
over plain HTTP, is a startup-time configuration error, not a silent
downgrade. Without the URL the adapter keeps JWKS-only verification,
which does not see revocation.

**Per-tool scopes.** The base `MCP_OAUTH_REQUIRED_SCOPE` (default `mcp`)
gates entry. On top of it, `mcp:read` narrows a token to read-only tools
and `mcp:write` grants mutations: a token carrying `mcp:read` without
`mcp:write` does not see mutating tools in `tools/list`, and a direct
`tools/call` to one is refused server-side. A token carrying only the
coarse `mcp` scope keeps full access, so tokens issued before the
fine-grained scopes existed behave as before. Unknown tool names are
denied by default.

**Single-peer mappings.** When a mapping pins `peer_id`, the grant is
per-peer: workspace-wide tools (`list_sessions`, `list_peers`,
`inspect_workspace`, `search`, `workspace_chat`, the scope tools, and
workspace-wide conclusion fetches) are unavailable, and session content,
membership, and destructive ops require the mapped peer to actually take
part in that session — checked against the live member list. Drop
`peer_id` from the mapping for a workspace-wide grant.

Without `MCP_OAUTH_ENABLED` nothing changes: the native
`Authorization: Bearer <honcho-key>` path is byte-for-byte what it was.
While the adapter is on, non-JWT bearers are refused unless
`MCP_OAUTH_ALLOW_NATIVE_BEARER=1` explicitly keeps the native path open
for them. `GET /.well-known/oauth-protected-resource` then advertises the
OAuth issuer instead of the Honcho API URL. See `src/oauth.ts` and
`src/oauth.test.ts` for the verification and fail-closed scoping rules.

### Docker

```bash
docker build -f mcp/Dockerfile -t honcho-mcp mcp
docker run --rm -p 3000:3000 \
  -e HONCHO_API_URL=http://host.docker.internal:8000 \
  honcho-mcp
```

`docker-compose.yml.example` includes an `mcp` service beside `api` and
`deriver` (`HONCHO_API_URL=http://api:8000`, port `127.0.0.1:3000`).

## Local stdio

For a local Honcho instance, or any MCP client that spawns a process, run the
stdio host. `--cwd` loads `mcp/bunfig.toml` (Markdown loader) from this package.

```bash
cd mcp && bun install

claude mcp add honcho \
  -e HONCHO_API_KEY=hch-your-key-here \
  -e HONCHO_API_URL=http://127.0.0.1:28000 \
  -e HONCHO_WORKSPACE_ID=my-workspace \
  -- bun --cwd "$(pwd)" src/stdio.ts
```

`HONCHO_API_URL` defaults to `https://api.honcho.dev`. `HONCHO_WORKSPACE_ID` is
optional; without it, pass `workspace_id` on each tool call.

## Development

### Setup

```bash
bun install
```

### Local dev

```bash
bun dev
```

### Type-check

```bash
bun run tsc --noEmit
```

### Test locally

Worker (`bun dev`, port 8787) or HTTP host (`bun run http`, port 3000):

```bash
bunx mcp-remote http://localhost:8787 \
  --header "Authorization:Bearer <key>"
```

### Deploy

```bash
bun run deploy              # production
bun run deploy:staging      # staging
```
