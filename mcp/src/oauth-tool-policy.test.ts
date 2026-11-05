/**
 * EDG-15 P0 closure — per-tool authorization (gap 2).
 *
 * The stage guard mapped workspace/peer on every tool call but never
 * distinguished mcp:read from mcp:write, so a read-only token could still
 * invoke delete_session and every other mutation; and a single-peer
 * mapping could still enumerate the workspace (list_sessions) or read
 * sessions its peer has nothing to do with.
 *
 * These tests drive the real Streamable HTTP handler (src/http.ts) with
 * the real MCP SDK transport against a synthetic Honcho backend whose
 * session membership the test controls. RED until tool-level filtering
 * and server-side validation are enforced.
 */
import { expect, test, afterEach } from "bun:test";
import {
  createSign,
  generateKeyPairSync,
  randomUUID,
  type KeyObject,
} from "node:crypto";
import { fetch } from "./http.ts";
import { resetJwksCache } from "./oauth.js";

const origin = "http://127.0.0.1:3000";

// ── synthetic signing keys ────────────────────────────────────────────
const trusted = generateKeyPairSync("rsa", { modulusLength: 2048 });

function b64url(input: Buffer | string): string {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function jwkFor(publicKey: KeyObject, kid: string): Record<string, string> {
  const j = publicKey.export({ format: "jwk" }) as { n: string; e: string };
  return { kty: "RSA", n: j.n, e: j.e, alg: "RS256", use: "sig", kid };
}

const TRUSTED_KID = "edgar-as-test-kid";
const ISSUER = "https://auth.edgars.tools";
const AUDIENCE = "https://mcp.edgars.tools/mcp";
const JWKS_URL = "https://auth.edgars.tools/jwks.json";
const CLIENT_ID = "honcho-console";
const SERVER_KEY = "server-side-honcho-key-never-exposed";
const NATIVE_KEY = "caller-own-honcho-key";

function mint(options: { sub?: string; scope?: string } = {}): string {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "at+jwt", kid: TRUSTED_KID };
  const claims: Record<string, unknown> = {
    iss: ISSUER,
    sub: options.sub ?? "peer-demo",
    aud: AUDIENCE,
    client_id: CLIENT_ID,
    scope: options.scope ?? "mcp",
    jti: randomUUID(),
    iat: now,
    nbf: now,
    exp: now + 600,
    ver: 1,
  };
  const signer = createSign("RSA-SHA256");
  signer.update(`${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`);
  const signature = signer.sign(trusted.privateKey);
  return `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}.${b64url(signature)}`;
}

// ── fixtures ──────────────────────────────────────────────────────────
/**
 * peer-demo  -> single-peer mapping (ws-alpha, pinned to peer "peer-demo")
 * ws-demo    -> workspace mapping (ws-gamma, no pinned peer)
 * ro-demo    -> single-peer mapping used for the read-only token
 */
const MAPPING = JSON.stringify({
  mappings: [
    {
      client_id: CLIENT_ID,
      sub: "peer-demo",
      workspace_id: "ws-alpha",
      peer_id: "peer-demo",
      scopes: ["mcp", "mcp:read", "mcp:write"],
    },
    {
      client_id: CLIENT_ID,
      sub: "ro-demo",
      workspace_id: "ws-alpha",
      peer_id: "peer-demo",
      scopes: ["mcp", "mcp:read", "mcp:write"],
    },
    {
      client_id: CLIENT_ID,
      sub: "ws-demo",
      workspace_id: "ws-gamma",
      scopes: ["mcp", "mcp:read", "mcp:write"],
    },
  ],
});

const FULL_SCOPE = "mcp mcp:read mcp:write";
const READ_SCOPE = "mcp mcp:read";

function oauthEnv(overrides: Record<string, string> = {}): Record<string, string> {
  return {
    MCP_OAUTH_ENABLED: "1",
    MCP_OAUTH_ISSUER: ISSUER,
    MCP_OAUTH_AUDIENCE: AUDIENCE,
    MCP_OAUTH_JWKS_URL: JWKS_URL,
    MCP_OAUTH_MAPPING: MAPPING,
    MCP_OAUTH_REQUIRED_SCOPE: "mcp",
    HONCHO_API_KEY: SERVER_KEY,
    HONCHO_API_URL: "http://honcho.invalid",
    ...overrides,
  };
}

const originalEnv = { ...process.env };
const originalFetch = globalThis.fetch;

function setEnv(env: Record<string, string>): void {
  for (const key of Object.keys(process.env)) {
    if (key.startsWith("MCP_OAUTH_") || key === "HONCHO_API_KEY") {
      delete process.env[key];
    }
  }
  Object.assign(process.env, env);
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// ── synthetic Honcho backend ──────────────────────────────────────────
interface MessageRow {
  id: string;
  content: string;
  peer_id: string;
  session_id: string;
  workspace_id: string;
  metadata: Record<string, unknown>;
  created_at: string;
  token_count: number;
}

interface FakeSession {
  id: string;
  peers: string[];
  messages: MessageRow[];
}

const backend = {
  sessions: new Map<string, FakeSession>(),
  calls: [] as { method: string; path: string }[],
  deleted: [] as string[],
  created: [] as string[],
  nextMessage: 0,
};

function messageRow(
  id: string,
  content: string,
  peerId: string,
  sessionId: string,
  workspaceId: string,
): MessageRow {
  return {
    id,
    content,
    peer_id: peerId,
    session_id: sessionId,
    workspace_id: workspaceId,
    metadata: {},
    created_at: "2026-11-06T00:00:00Z",
    token_count: 1,
  };
}

function seedBackend(): void {
  backend.sessions.clear();
  backend.calls = [];
  backend.deleted = [];
  backend.created = [];
  backend.nextMessage = 0;
  backend.sessions.set("ws-alpha/s-mine", {
    id: "s-mine",
    peers: ["peer-demo", "ally"],
    messages: [messageRow("m1", "hello there", "peer-demo", "s-mine", "ws-alpha")],
  });
  backend.sessions.set("ws-alpha/s-foreign", {
    id: "s-foreign",
    peers: ["stranger"],
    messages: [messageRow("m2", "not yours", "stranger", "s-foreign", "ws-alpha")],
  });
  backend.sessions.set("ws-gamma/s-gamma-1", {
    id: "s-gamma-1",
    peers: ["ws-demo"],
    messages: [],
  });
}

function page(items: unknown[], total = items.length) {
  return { items, page: 1, size: 10, total, pages: 1 };
}

function sessionResponse(id: string, workspaceId: string) {
  return {
    id,
    metadata: {},
    configuration: {},
    created_at: "2026-11-06T00:00:00Z",
    is_active: true,
    uid: `${workspaceId}/${id}`,
  };
}

/** Stubs JWKS plus the Honcho v3 API surface the tools touch. */
function stubBackend(): void {
  seedBackend();
  globalThis.fetch = (async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const path = new URL(url).pathname;
    const method = (
      init?.method ?? (input instanceof Request ? input.method : "GET")
    ).toUpperCase();

    if (url.startsWith(JWKS_URL)) {
      return json(200, { keys: [jwkFor(trusted.publicKey as KeyObject, TRUSTED_KID)] });
    }
    // Everything below is a Honcho backend call; JWKS fetches are not.
    backend.calls.push({ method, path });

    // Workspace ensure (the SDK's get-or-create round trip before any
    // workspace-scoped call).
    if (path === "/v3/workspaces" && method === "POST") {
      const body = JSON.parse(String(init?.body ?? "{}")) as { id?: string };
      return json(200, {
        id: body.id ?? "ws",
        metadata: {},
        configuration: {},
        created_at: "2026-11-06T00:00:00Z",
      });
    }

    const match = path.match(/^\/v3\/workspaces\/([^/]+)(\/.*)?$/);
    if (!match) return json(404, { detail: "not found" });
    const workspaceId = match[1]!;
    const rest = match[2] ?? "";
    const key = (sessionId: string) => `${workspaceId}/${sessionId}`;

    // sessions list
    if (rest === "/sessions/list" && method === "POST") {
      const items = [...backend.sessions.entries()]
        .filter(([k]) => k.startsWith(`${workspaceId}/`))
        .map(([, s]) => sessionResponse(s.id, workspaceId));
      return json(200, page(items));
    }
    // session get-or-create
    if (rest === "/sessions" && method === "POST") {
      const body = JSON.parse(String(init?.body ?? "{}")) as { id?: string };
      const id = body.id ?? "";
      const existing = backend.sessions.get(key(id));
      if (!existing) {
        backend.sessions.set(key(id), { id, peers: [], messages: [] });
        backend.created.push(id);
      }
      return json(200, sessionResponse(id, workspaceId));
    }
    const sessionMatch = rest.match(/^\/sessions\/([^/]+)(\/.*)?$/);
    if (sessionMatch) {
      const sessionId = sessionMatch[1]!;
      const tail = sessionMatch[2] ?? "";
      const session = backend.sessions.get(key(sessionId));
      if (tail === "" && method === "DELETE") {
        backend.deleted.push(sessionId);
        backend.sessions.delete(key(sessionId));
        return json(200, {});
      }
      if (tail === "/clone" && method === "POST") {
        const cloneId = `${sessionId}-clone`;
        backend.sessions.set(key(cloneId), {
          id: cloneId,
          peers: session ? [...session.peers] : [],
          messages: session ? [...session.messages] : [],
        });
        backend.created.push(cloneId);
        return json(200, sessionResponse(cloneId, workspaceId));
      }
      if (tail === "/peers" && method === "GET") {
        const items = (session?.peers ?? []).map((id) => ({
          id,
          metadata: {},
          configuration: {},
          created_at: "2026-11-06T00:00:00Z",
          uid: id,
        }));
        return json(200, page(items));
      }
      if (tail === "/peers" && (method === "POST" || method === "PUT")) {
        if (session) {
          const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
          for (const id of Object.keys(body)) {
            if (!session.peers.includes(id)) session.peers.push(id);
          }
        }
        return json(200, {});
      }
      if (tail === "/peers" && method === "DELETE") {
        return json(200, {});
      }
      if (tail === "/messages/list" && method === "POST") {
        return json(200, page(session?.messages ?? []));
      }
      if (tail === "/messages" && method === "POST") {
        const body = JSON.parse(String(init?.body ?? "{}")) as {
          messages?: { content: string; peer_id: string }[];
        };
        const created: MessageRow[] = [];
        for (const msg of body.messages ?? []) {
          backend.nextMessage += 1;
          const row = messageRow(
            `new-${backend.nextMessage}`,
            msg.content,
            msg.peer_id,
            sessionId,
            workspaceId,
          );
          created.push(row);
          if (session) {
            session.messages.push(row);
            if (!session.peers.includes(msg.peer_id)) session.peers.push(msg.peer_id);
          }
        }
        return json(201, created);
      }
      if (tail === "/context" && method === "GET") {
        return json(200, {
          messages: session?.messages ?? [],
          summary: null,
          peer_representation: null,
          peer_card: null,
        });
      }
      if (tail === "/summaries" && method === "GET") {
        return json(200, { id: sessionId, short_summary: null, long_summary: null });
      }
      if (tail === "" && method === "PUT") {
        return json(200, sessionResponse(sessionId, workspaceId));
      }
    }

    if (rest === "/peers/list" && method === "POST") {
      return json(200, page([{ id: "peer-demo", metadata: {}, configuration: {} }]));
    }
    if (rest === "/queue/status") {
      return json(200, { total: 1, completed: 1, in_progress: 0, pending: 0 });
    }
    // workspace get-or-create and anything else the SDK touches.
    return json(200, {
      id: workspaceId,
      metadata: {},
      configuration: {},
      created_at: "2026-11-06T00:00:00Z",
    });
  }) as typeof globalThis.fetch;
}

afterEach(() => {
  process.env = { ...originalEnv };
  globalThis.fetch = originalFetch;
  resetJwksCache();
});

// ── MCP helpers ───────────────────────────────────────────────────────
const initializeBody = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "edg15-policy-test", version: "0.0.0" },
  },
};

function mcpPost(headers: Record<string, string>, body: unknown): Promise<Response> {
  return fetch(
    new Request(`${origin}/mcp`, {
      method: "POST",
      headers: {
        Accept: "application/json, text/event-stream",
        "Content-Type": "application/json",
        ...headers,
      },
      body: JSON.stringify(body),
    }),
  );
}

async function openSession(
  token: string,
): Promise<{ sessionId: string; headers: Record<string, string> }> {
  const init = await mcpPost({ Authorization: `Bearer ${token}` }, initializeBody);
  const sessionId = init.headers.get("mcp-session-id");
  expect(sessionId).toBeTruthy();
  return { sessionId: sessionId!, headers: { Authorization: `Bearer ${token}` } };
}

async function callTool(
  session: { sessionId: string; headers: Record<string, string> },
  name: string,
  args: Record<string, unknown>,
  id = 99,
): Promise<Response> {
  return mcpPost(
    { ...session.headers, "mcp-session-id": session.sessionId },
    { jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } },
  );
}

async function listTools(
  session: { sessionId: string; headers: Record<string, string> },
): Promise<string[]> {
  const res = await mcpPost(
    { ...session.headers, "mcp-session-id": session.sessionId },
    { jsonrpc: "2.0", id: 2, method: "tools/list" },
  );
  expect(res.status).toBe(200);
  const body = (await res.json()) as { result: { tools: { name: string }[] } };
  return body.result.tools.map((t) => t.name);
}

/** A JSON-RPC error or a tool-level isError — either way the call did not run. */
function isDenied(payload: unknown): boolean {
  const body = payload as { error?: unknown; result?: { isError?: boolean } };
  if (body?.error) return true;
  return body?.result?.isError === true;
}

async function expectDenied(
  session: { sessionId: string; headers: Record<string, string> },
  name: string,
  args: Record<string, unknown>,
  id: number,
): Promise<void> {
  const res = await callTool(session, name, args, id);
  // A transport-level refusal (4xx/5xx) is a denial too.
  if (res.status >= 400) return;
  let payload: unknown;
  try {
    payload = await res.json();
  } catch {
    throw new Error(`denied call to '${name}' returned ${res.status} with a non-JSON body`);
  }
  expect(isDenied(payload)).toBe(true);
}

// ── mcp:read vs mcp:write ─────────────────────────────────────────────
test("mcp:read-only token: tools/list hides every mutating tool", async () => {
  setEnv(oauthEnv());
  stubBackend();
  const session = await openSession(mint({ sub: "ro-demo", scope: READ_SCOPE }));
  const names = await listTools(session);

  for (const write of [
    "delete_session",
    "set_metadata",
    "add_messages_to_session",
    "create_workspace",
    "create_peer",
    "set_peer_card",
    "create_conclusions",
    "delete_conclusion",
    "schedule_dream",
    "clone_session",
    "add_peers_to_session",
    "remove_peers_from_session",
    "create_session",
    "create_scope",
    "add_sessions_to_scope",
    "remove_session_from_scope",
  ]) {
    expect(names).not.toContain(write);
  }
  for (const read of [
    "get_queue_status",
    "get_session_messages",
    "list_workspaces",
    "chat",
    "get_peer_card",
    "list_conclusions",
  ]) {
    expect(names).toContain(read);
  }
});

test("mcp:read-only token: delete_session and other mutations are refused", async () => {
  setEnv(oauthEnv());
  stubBackend();
  const session = await openSession(mint({ sub: "ro-demo", scope: READ_SCOPE }));

  await expectDenied(session, "delete_session", { session_id: "s-mine" }, 3);
  await expectDenied(session, "set_metadata", { metadata: { probe: "x" } }, 4);
  await expectDenied(
    session,
    "add_messages_to_session",
    { session_id: "s-mine", messages: [{ peer_id: "peer-demo", content: "hi" }] },
    5,
  );
  await expectDenied(session, "create_workspace", { workspace_id: "ws-alpha" }, 6);
  await expectDenied(session, "schedule_dream", {}, 7);

  // Nothing reached the backend: the refusals happen before any call.
  expect(backend.deleted).toEqual([]);
  expect(backend.calls.length).toBe(0);

  // Reads on the same session still work.
  const read = await callTool(session, "get_queue_status", {}, 8);
  expect(read.status).toBe(200);
  expect(isDenied(await read.json())).toBe(false);
});

test("mcp:write token: an allowed write on the identity's own session runs", async () => {
  setEnv(oauthEnv());
  stubBackend();
  const session = await openSession(mint({ sub: "peer-demo", scope: FULL_SCOPE }));
  const names = await listTools(session);
  expect(names).toContain("delete_session");
  expect(names).toContain("add_messages_to_session");

  // Scoped mutation: the pinned peer writes into its own session.
  const write = await callTool(
    session,
    "add_messages_to_session",
    { session_id: "s-mine", messages: [{ peer_id: "peer-demo", content: "scoped write" }] },
    3,
  );
  expect(write.status).toBe(200);
  const payload = (await write.json()) as { result: { isError?: boolean; content: { text: string }[] } };
  expect(payload.result.isError).toBeFalsy();
  expect(payload.result.content[0]!.text).toContain("Messages added to session successfully");
  expect(backend.calls.some((c) => c.path.endsWith("/s-mine/messages"))).toBe(true);

  // ...and reads it back.
  const read = await callTool(session, "get_session_messages", { session_id: "s-mine" }, 4);
  expect(read.status).toBe(200);
  const body = (await read.json()) as { result: { content: { text: string }[] } };
  const data = JSON.parse(body.result.content[0]!.text) as {
    messages: { content: string }[];
  };
  expect(data.messages.map((m) => m.content)).toContain("scoped write");
});

test("unknown tool names are denied", async () => {
  setEnv(oauthEnv());
  stubBackend();
  const session = await openSession(mint({ sub: "peer-demo", scope: FULL_SCOPE }));
  await expectDenied(session, "delete_everything", {}, 3);
  await expectDenied(session, "list_sessions_v2", {}, 4);
  expect(backend.calls.length).toBe(0);
});

// ── single-peer mapping: no workspace-wide data ───────────────────────
test("peer-pinned identity: list_sessions and workspace-wide tools are refused", async () => {
  setEnv(oauthEnv());
  stubBackend();
  const session = await openSession(mint({ sub: "peer-demo", scope: FULL_SCOPE }));
  const names = await listTools(session);

  for (const wide of [
    "list_sessions",
    "list_peers",
    "inspect_workspace",
    "search",
    "workspace_chat",
    "list_scopes",
    "get_scope_sessions",
    "get_scope_status",
    "create_scope",
    "add_sessions_to_scope",
    "remove_session_from_scope",
    "get_conclusions",
    "get_derived_conclusions",
  ]) {
    expect(names).not.toContain(wide);
    await expectDenied(session, wide, wide.startsWith("get_scope") || wide === "get_scope_status" ? { scope_id: "s" } : {}, 50 + names.length);
  }
  // No workspace-wide route was ever called.
  expect(backend.calls.some((c) => c.path.endsWith("/sessions/list"))).toBe(false);
});

test("peer-pinned identity: session content of unrelated peers is refused", async () => {
  setEnv(oauthEnv());
  stubBackend();
  const session = await openSession(mint({ sub: "peer-demo", scope: FULL_SCOPE }));

  await expectDenied(session, "get_session_messages", { session_id: "s-foreign" }, 3);
  await expectDenied(session, "get_session_context", { session_id: "s-foreign" }, 4);
  await expectDenied(session, "get_session_peers", { session_id: "s-foreign" }, 5);
  await expectDenied(session, "inspect_session", { session_id: "s-foreign" }, 6);
  await expectDenied(session, "get_session_message", { session_id: "s-foreign", message_id: "m2" }, 7);
  // Destructive ops on an unrelated session are refused even with mcp:write.
  await expectDenied(session, "delete_session", { session_id: "s-foreign" }, 8);
  await expectDenied(session, "clone_session", { session_id: "s-foreign" }, 9);

  // The membership lookups happened; the content and destructive routes
  // for the foreign session never did.
  expect(backend.calls.some((c) => c.path.endsWith("/s-foreign/peers"))).toBe(true);
  expect(backend.calls.some((c) => c.path.includes("/s-foreign/messages"))).toBe(false);
  expect(backend.calls.some((c) => c.path.includes("/s-foreign/context"))).toBe(false);
  expect(backend.deleted).toEqual([]);

  // The peer's own session is readable.
  const read = await callTool(session, "get_session_messages", { session_id: "s-mine" }, 10);
  expect(read.status).toBe(200);
  const body = (await read.json()) as { result: { content: { text: string }[] } };
  const data = JSON.parse(body.result.content[0]!.text) as { messages: { content: string }[] };
  expect(data.messages.map((m) => m.content)).toEqual(["hello there"]);
});

test("peer-pinned identity: a session it creates itself is readable and deletable", async () => {
  setEnv(oauthEnv());
  stubBackend();
  const session = await openSession(mint({ sub: "peer-demo", scope: FULL_SCOPE }));

  const created = await callTool(session, "create_session", { session_id: "s-new" }, 3);
  expect(created.status).toBe(200);
  expect((await created.json() as { result: { isError?: boolean } }).result.isError).toBeFalsy();

  const wrote = await callTool(
    session,
    "add_messages_to_session",
    { session_id: "s-new", messages: [{ peer_id: "peer-demo", content: "first turn" }] },
    4,
  );
  expect((await wrote.json() as { result: { isError?: boolean } }).result.isError).toBeFalsy();

  const read = await callTool(session, "get_session_messages", { session_id: "s-new" }, 5);
  expect(read.status).toBe(200);
  const body = (await read.json()) as { result: { content: { text: string }[] } };
  const data = JSON.parse(body.result.content[0]!.text) as { messages: { content: string }[] };
  expect(data.messages.map((m) => m.content)).toEqual(["first turn"]);

  const deleted = await callTool(session, "delete_session", { session_id: "s-new" }, 6);
  expect(deleted.status).toBe(200);
  expect((await deleted.json() as { result: { isError?: boolean } }).result.isError).toBeFalsy();
  expect(backend.deleted).toEqual(["s-new"]);
});

// ── workspace mapping: workspace-wide tools stay available ────────────
test("workspace identity: list_sessions and session reads work inside the mapped workspace", async () => {
  setEnv(oauthEnv());
  stubBackend();
  const session = await openSession(mint({ sub: "ws-demo", scope: FULL_SCOPE }));
  const names = await listTools(session);
  expect(names).toContain("list_sessions");
  expect(names).toContain("delete_session");

  const list = await callTool(session, "list_sessions", {}, 3);
  expect(list.status).toBe(200);
  const listBody = (await list.json()) as {
    result: { isError?: boolean; content: { text: string }[] };
  };
  expect(listBody.result.isError).toBeFalsy();
  const listData = JSON.parse(listBody.result.content[0]!.text) as {
    sessions: { id: string }[];
  };
  expect(listData.sessions.map((s) => s.id)).toEqual(["s-gamma-1"]);

  const read = await callTool(session, "get_session_messages", { session_id: "s-gamma-1" }, 4);
  expect(read.status).toBe(200);
  expect((await read.json() as { result: { isError?: boolean } }).result.isError).toBeFalsy();

  // A workspace outside the mapping is still refused (pre-existing guard).
  await expectDenied(session, "list_sessions", { workspace_id: "ws-alpha" }, 5);
  expect(backend.calls.filter((c) => c.path.includes("ws-alpha")).length).toBe(0);
});

// ── native path unchanged when the adapter is off ─────────────────────
test("adapter disabled: every tool stays available and writes use the caller's key", async () => {
  setEnv({});
  stubBackend();
  const session = await openSession(NATIVE_KEY);
  const names = await listTools(session);
  expect(names).toContain("delete_session");
  expect(names).toContain("list_sessions");
  expect(names.length).toBe(40);

  const write = await callTool(
    session,
    "add_messages_to_session",
    {
      workspace_id: "ws-alpha",
      session_id: "s-mine",
      messages: [{ peer_id: "peer-demo", content: "native write" }],
    },
    3,
  );
  expect(write.status).toBe(200);
  expect((await write.json() as { result: { isError?: boolean } }).result.isError).toBeFalsy();
  const stored = backend.sessions.get("ws-alpha/s-mine");
  expect(stored?.messages.map((m) => m.content)).toContain("native write");
});
