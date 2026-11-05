# EDGAR Memory MCP v1.0 — Product Contract
Status: **PRODUCT_SCOPE_FROZEN / RELEASE_NOT_ACCEPTED**
Decision date: 2026-11-06 (Asia/Taipei)
Canonical issue: https://edgars.youtrack.cloud/issue/EDG-15
Related auth gate: https://edgars.youtrack.cloud/issue/EDG-456
Baseline implementation: commit `e9f8203b945c1bfe241a9dd0ede2a1697969897e` (official Honcho native MCP HTTP adapter on this branch)

## Product promise
One real, self-hosted long-term memory service usable by a human in ChatGPT and by authorized Hermes, Codex, and OpenClaw agents. Users can actually read, write, recall, and manage memory under their identity and authorization, not merely view static UI cards or copy bearer tokens.

## Frozen architecture and ownership
- **Product name:** EDGAR Memory MCP.
- **Canonical user-facing MCP endpoint:** `https://honcho.edgars.tools/mcp`. Streamable HTTP.
- **Only human OAuth issuer:** self-hosted EDGAR Auth at `https://auth.edgars.tools`; separate authorization server.
- **MCP resource server:** official plastic-labs/Honcho native MCP HTTP implementation plus a minimal maintained OAuth/JWKS/introspection/ACL adapter. Avoid forking unrelated Honcho core behavior.
- **Backend:** independent self-hosted Honcho API and existing Neon/Postgres/pgvector estate. It must remain available when Hermes is down. No hosted Honcho fallback.
- **No Identity Gate:** never redeploy the retired identity-gate listener/container as a prerequisite.
- **Existing service identities:** `edgar` (human) and fixed `codex`, `hermes`, `openclaw` peers. Existing `edgar-team` workspace remains the established team scope; other workspaces require server-authorized provisioning, never client self-claims.
- **Commercial constraint:** zero new recurring cost, reuse provisioned hosts/keys/providers. Never imply a free provider can generate real embeddings without entitlement.

## Human experience (must be a real working flow)
1. In ChatGPT, connect EDGAR Memory MCP as an authenticated custom MCP/plugin.
2. Discovery loads a valid HTTPS OAuth protected-resource metadata document, EDGAR Auth authorization-server metadata, and the public authorization/consent pages.
3. ChatGPT identifies/registers its OAuth client using the current supported flow. **v1 compatibility baseline: DCR**, because the current EDGAR Auth flow already has isolated DCR/PKCE evidence; add CIMD when issuer/client-metadata checks pass, but do not block v1 on a second registration method.
4. Human logs in and grants explicit scopes; actual callback, authorization-code + PKCE S256, token/refresh, and per-tool authorization must work in the real ChatGPT client.
5. Authenticated tools return **real Honcho contents**, create/read/update memory as allowed, and persist through server restart and a new client session. Unauthorized requests receive actionable 401/403, not mock success.

## Agent experience
- Hermes/Codex/OpenClaw retain individually scoped identities, independent credentials and fixed server-side workspace/peer bindings. Agents may use a private trusted service-to-service boundary compatible with the existing native credential contract; no raw backend signing secrets in browser or public client.
- The public ChatGPT OAuth endpoint must never fall back to arbitrary raw Honcho keys. Any private legacy native-bearer bridge is an explicitly isolated compatibility path, not a public universal bypass.
- An agent failure must not interrupt the core Honcho API or other consumer identities.

## Tool and authorization contract
- Preserve the official **40-tool native MCP inventory** as the capability ceiling, subject to feature compatibility and explicit per-tool authorization; do not downgrade the product to a seven-tool wrapper or a read-only demo.
- OAuth access tokens: validate signature (RS256/JWKS), `iss`, exact resource `aud`, `exp`, `nbf`, scopes, server-side client/subject -> workspace/peer mapping; enforce on **every** request/tool call.
- For public human OAuth mode, require operational, HTTPS confidential-token introspection with fail-closed response/revocation behavior. A configured but unreachable introspection endpoint is a failure, not optional success.
- Fine-grained `mcp:read` only cannot delete/create/modify; `mcp:write` may mutate only granted objects. Unknown tools fail closed. Do not let a legacy broad `mcp` token silently grant mutation on the public human endpoint; this compatibility behavior must be gated by public issuer policy or revised with a regression test before release.
- Peer- and session-scoped retrieval cannot leak other peers' private data; workspace-wide tools require an explicit wider grant. A user-entered workspace/peer/session field cannot increase authority.
- Authorization checks must use the backend's true consumption boundary and prove data-side outcomes; hiding tools in `tools/list` alone is insufficient.

## Release acceptance — all must pass
1. Public `/.well-known/oauth-protected-resource[/mcp]` and `auth.edgars.tools/.well-known/oauth-authorization-server` resolve with valid HTTPS/JSON/issuer/resource metadata. Existing observed states (PRM 404, AS 410) are release blockers.
2. Real EDGAR Auth authorization-code + PKCE S256 + registered client (DCR v1) -> actual native MCP `initialize`, `tools/list`, read, scoped write, and confirmed persisted backend Honcho readback; no stub backend or fake UI.
3. Negative E2E: revoked JWT denied on next real request, wrong issuer/audience/expiry/scope denied, read-only write denied, cross-workspace/peer/session denied, anonymous denied; no backend write on negative cases.
4. Source compatibility: typecheck and full Bun suite green; existing native authorized agents perform real write/read/restart recall independently, with no Identity Gate and no unauthorized new peer creation.
5. Data continuity: verify old corpus and new memory are actually accessible under the intended merged/query path; legacy vector recovery and 18,058 historical vectors remain separately unaccepted until supported by live-scale readback.
6. Human ChatGPT authenticated login/consent and tool use works through the official plugin/client UI, including refresh/reconnection; no inventing a success from curl/HTTP200 alone.
7. Production-only acceptance: no unauthorized public backend port, rollback rehearsed with data intact, health/restart and independent consumer readback; `Auth`, `MCP`, `Honcho` can fail/recover independently where designed.
8. No recurring charge or new infrastructure dependency, no changes to the retired Identity Gate.

## Delivery states
- **FROZEN:** product, architecture, capabilities, authentication method and release criteria decided here.
- **STAGING_TESTED:** existing adapter (baseline `e9f8203...`) passes 70/70 Bun tests + TypeScript. These tests stub AS and Honcho. This is *not* production evidence.
- **BLOCKED:** isolated real-Honcho backend attempt was unable to start offline due to missing `o200k_base.tiktoken`; the disposable containers/network were removed. This is a narrow test-fixture/bootstrap blocker.
- **NOT_RELEASED:** public OAuth PRM/AS discovery, real Honcho OAuth DB E2E, real ChatGPT consent/binding, historical corpus and multi-agent cross-session E2E are not accepted.
- **GO-LIVE** only after the acceptance gates above. Do not equate product specification freeze with a production release.

## Single critical path (no new scope exploration)
Use a clean, disposable Honcho+pgvector backend with packaged *public* tokenizer or an authorized independent synthetic-provider fixture, no production data/secrets and no extra monthly cost. Once real backend is up, do genuine EDGAR Auth token -> native MCP -> persisted Honcho read/write/negative E2E, then publish OAuth metadata to the existing domains through a guarded rollbackable change and complete ChatGPT mobile/browser consent acceptance. Keep issue EDG-15 as source of truth and Drive CURRENT as pointer; do not open parallel research epics or restart an Identity Gate project.

## Evidence & sources
- P0 commit: https://github.com/edgarstool/honcho/tree/edg15/oauth-honcho-stage-20261106
- P0 controller receipt: https://edgars.youtrack.cloud/issue/EDG-15#focus=Comments-7-3518.0-0
- Official Honcho MCP: https://github.com/plastic-labs/honcho/blob/main/docs/v3/guides/integrations/mcp.mdx
- Official Honcho self hosting: https://github.com/plastic-labs/honcho/blob/main/docs/v3/contributing/self-hosting.mdx
- Current OpenAI MCP OAuth contract: https://developers.openai.com/plugins/build/auth
