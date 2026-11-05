/**
 * EDG-15 stage: opt-in OAuth (RS256/JWKS) adapter for the Streamable HTTP
 * server. RED-first tests for the EDGAR Auth Server integration:
 * token verification, fail-closed workspace/peer scoping, and unchanged
 * native Bearer behavior when the adapter is disabled.
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

// ── test keys ──────────────────────────────────────────────────────────
const trusted = generateKeyPairSync("rsa", { modulusLength: 2048 });
const foreign = generateKeyPairSync("rsa", { modulusLength: 2048 });

function b64url(input: Buffer | string): string {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function jwkFor(publicKey: KeyObject, kid: string): Record<string, string> {
  const j = publicKey.export({ format: "jwk" }) as {
    n: string;
    e: string;
  };
  return { kty: "RSA", n: j.n, e: j.e, alg: "RS256", use: "sig", kid };
}

const TRUSTED_KID = "edgar-as-test-kid";
const FOREIGN_KID = "not-the-as-kid";

interface MintOptions {
  kid?: string;
  key?: KeyObject;
  iss?: string;
  sub?: string;
  aud?: string;
  clientId?: string;
  scope?: string;
  exp?: number;
  nbf?: number;
  iat?: number;
  typ?: string;
  alg?: string;
  omit?: string[];
}

function mint(options: MintOptions = {}): string {
  const now = Math.floor(Date.now() / 1000);
  const header: Record<string, string> = {
    alg: options.alg ?? "RS256",
    typ: options.typ ?? "at+jwt",
    kid: options.kid ?? TRUSTED_KID,
  };
  const claims: Record<string, unknown> = {
    iss: options.iss ?? ISSUER,
    sub: options.sub ?? "native-demo",
    aud: options.aud ?? AUDIENCE,
    client_id: options.clientId ?? "honcho-console",
    scope: options.scope ?? "mcp",
    jti: randomUUID(),
    iat: options.iat ?? now,
    nbf: options.nbf ?? now,
    exp: options.exp ?? now + 600,
    ver: 1,
  };
  for (const key of options.omit ?? []) delete claims[key];
  const key = options.key ?? trusted.privateKey;
  const signer = createSign("RSA-SHA256");
  signer.update(`${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`);
  const signature = signer.sign(key);
  return `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}.${b64url(signature)}`;
}

// ── fixtures ───────────────────────────────────────────────────────────
const ISSUER = "https://auth.edgars.tools";
const AUDIENCE = "https://mcp.edgars.tools/mcp";
const SERVER_KEY = "server-side-honcho-key-never-exposed";
const JWKS_URL = "https://auth.edgars.tools/jwks.json";

const MAPPING = JSON.stringify({
  mappings: [
    {
      client_id: "honcho-console",
      sub: "native-demo",
      workspace_id: "ws-alpha",
      peer_id: "native-demo",
      scopes: ["mcp", "mcp:read", "mcp:write"],
    },
    {
      sub: "readonly-demo",
      workspace_id: "ws-beta",
    },
  ],
});

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

/** Serves the trusted JWKS and records Honcho API calls. */
function stubNetwork(): { calls: { url: string; auth: string | null; body: unknown }[] } {
  const calls: { url: string; auth: string | null; body: unknown }[] = [];
  const keys = [jwkFor(trusted.publicKey as KeyObject, TRUSTED_KID)];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url.startsWith(JWKS_URL)) {
      return json(200, { keys });
    }
    const headers = new Headers(
      (init?.headers ?? (input instanceof Request ? input.headers : undefined)) as
        | HeadersInit
        | undefined,
    );
    let body: unknown = init?.body;
    if (typeof body === "string") {
      try {
        body = JSON.parse(body);
      } catch {
        /* keep raw */
      }
    }
    calls.push({ url, auth: headers.get("authorization"), body });
    const path = new URL(url).pathname;
    if (path.endsWith("/queue/status")) {
      return json(200, { total: 1, completed: 1, in_progress: 0, pending: 0 });
    }
    if (path.endsWith("/workspaces/list")) {
      return json(200, {
        items: [
          { id: "ws-alpha", metadata: { purpose: "mapped" }, created_at: "2026-11-06T00:00:00Z" },
          { id: "ws-foreign", metadata: {}, created_at: "2026-11-06T00:00:00Z" },
        ],
        total: 2,
        page: 1,
        size: 10,
        pages: 1,
      });
    }
    if (path.endsWith("/peers/native-demo/chat")) {
      return json(200, "peer answer");
    }
    return json(200, {
      id: "ws-alpha",
      metadata: { probe: "value" },
      configuration: {},
      created_at: "2026-11-06T00:00:00Z",
    });
  }) as typeof globalThis.fetch;
  return { calls };
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => {
  process.env = { ...originalEnv };
  globalThis.fetch = originalFetch;
  resetJwksCache();
});

// ── MCP helpers ────────────────────────────────────────────────────────
const initializeBody = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "edg15-test", version: "0.0.0" },
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

// ── adapter disabled: native Bearer is untouched ───────────────────────
test("adapter disabled: a JWT-looking bearer is passed through as the native Honcho key", async () => {
  setEnv({});
  const { calls } = stubNetwork();
  const jwtLike = mint();
  const session = await openSession(jwtLike);
  const res = await callTool(session, "get_queue_status", { workspace_id: "ws-alpha" });
  expect(res.status).toBe(200);
  expect(calls.length).toBeGreaterThan(0);
  expect(calls[0]!.auth).toBe(`Bearer ${jwtLike}`);
});

// ── happy path ─────────────────────────────────────────────────────────
test("adapter enabled: valid RS256 token initializes and tool calls use the server key", async () => {
  setEnv(oauthEnv());
  const { calls } = stubNetwork();
  const token = mint();
  const session = await openSession(token);
  expect(session.sessionId).toBeTruthy();

  const list = await mcpPost(
    { ...session.headers, "mcp-session-id": session.sessionId },
    { jsonrpc: "2.0", id: 2, method: "tools/list" },
  );
  expect(list.status).toBe(200);

  const read = await callTool(session, "get_queue_status", {});
  expect(read.status).toBe(200);
  const payload = (await read.json()) as { result: { isError?: boolean } };
  expect(payload.result.isError).toBeFalsy();

  // The backend Honcho key is used upstream; the OAuth token never is.
  expect(calls.length).toBeGreaterThan(0);
  for (const call of calls) {
    expect(call.auth).toBe(`Bearer ${SERVER_KEY}`);
    expect(JSON.stringify(call)).not.toContain(token);
  }
  // Workspace comes from the server-side mapping, not the caller.
  const queueCall = calls.find((c) => c.url.includes("/queue/status"));
  expect(queueCall?.url).toContain("/workspaces/ws-alpha/");
});

test("adapter enabled: a self-declared workspace outside the mapping fails closed", async () => {
  setEnv(oauthEnv());
  const { calls } = stubNetwork();
  const session = await openSession(mint());

  const denied = await callTool(
    session,
    "set_metadata",
    { workspace_id: "ws-anything", metadata: { probe: "value" } },
    3,
  );
  expect(denied.status).toBe(200);
  expect((await denied.json()).result.isError).toBe(true);
  // Nothing reached the backend: the override is refused before any call.
  expect(calls.length).toBe(0);

  // The mapped workspace may be named explicitly.
  const allowed = await callTool(
    session,
    "set_metadata",
    { workspace_id: "ws-alpha", metadata: { probe: "value" } },
    31,
  );
  expect((await allowed.json()).result.isError).toBeFalsy();
  expect(calls.some((c) => c.url.includes("/workspaces/ws-alpha"))).toBe(true);
  expect(calls.some((c) => c.url.includes("ws-anything"))).toBe(false);

  // Omitting it entirely falls back to the mapped default.
  const implicit = await callTool(session, "set_metadata", { metadata: { probe: "value" } }, 32);
  expect((await implicit.json()).result.isError).toBeFalsy();
  expect(calls.filter((c) => c.url.includes("/workspaces/")).length).toBe(2);
});

test("adapter enabled: list_workspaces only reports permitted workspaces", async () => {
  setEnv(oauthEnv());
  stubNetwork();
  const session = await openSession(mint());
  const res = await callTool(session, "list_workspaces", {});
  expect(res.status).toBe(200);
  const body = (await res.json()) as {
    result: { content: { text: string }[]; isError?: boolean };
  };
  const data = JSON.parse(body.result.content[0]!.text) as {
    workspaces: { id: string }[];
  };
  expect(data.workspaces.map((w) => w.id)).toEqual(["ws-alpha"]);
});

test("adapter enabled: create_workspace refuses a workspace outside the mapping", async () => {
  setEnv(oauthEnv());
  const { calls } = stubNetwork();
  const session = await openSession(mint());

  const denied = await callTool(session, "create_workspace", { workspace_id: "ws-foreign" }, 4);
  expect(denied.status).toBe(200);
  expect((await denied.json()).result.isError).toBe(true);
  expect(calls.some((c) => c.url.includes("ws-foreign"))).toBe(false);

  const allowed = await callTool(session, "create_workspace", { workspace_id: "ws-alpha" }, 5);
  expect(allowed.status).toBe(200);
  expect((await allowed.json()).result.isError).toBeFalsy();
});

// ── negative: token verification ───────────────────────────────────────
test("adapter enabled: expired token is 401 invalid_token", async () => {
  setEnv(oauthEnv());
  stubNetwork();
  const res = await mcpPost(
    { Authorization: `Bearer ${mint({ exp: Math.floor(Date.now() / 1000) - 60 })}` },
    initializeBody,
  );
  expect(res.status).toBe(401);
  expect(res.headers.get("WWW-Authenticate")).toContain('error="invalid_token"');
});

test("adapter enabled: wrong issuer is 401", async () => {
  setEnv(oauthEnv());
  stubNetwork();
  const res = await mcpPost(
    { Authorization: `Bearer ${mint({ iss: "https://evil.example" })}` },
    initializeBody,
  );
  expect(res.status).toBe(401);
});

test("adapter enabled: token signed by a foreign key is 401", async () => {
  setEnv(oauthEnv());
  stubNetwork();
  const res = await mcpPost(
    { Authorization: `Bearer ${mint({ key: foreign.privateKey, kid: FOREIGN_KID })}` },
    initializeBody,
  );
  expect(res.status).toBe(401);
});

test("adapter enabled: wrong audience is 401", async () => {
  setEnv(oauthEnv());
  stubNetwork();
  const res = await mcpPost(
    { Authorization: `Bearer ${mint({ aud: "https://other.example/mcp" })}` },
    initializeBody,
  );
  expect(res.status).toBe(401);
});

test("adapter enabled: missing required scope is 403 insufficient_scope", async () => {
  setEnv(oauthEnv());
  stubNetwork();
  const res = await mcpPost(
    { Authorization: `Bearer ${mint({ scope: "openid profile" })}` },
    initializeBody,
  );
  expect(res.status).toBe(403);
});

test("adapter enabled: alg none is rejected even with a trusted kid", async () => {
  setEnv(oauthEnv());
  stubNetwork();
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "none", typ: "at+jwt", kid: TRUSTED_KID };
  const claims = {
    iss: ISSUER,
    sub: "native-demo",
    aud: AUDIENCE,
    client_id: "honcho-console",
    scope: "mcp",
    jti: randomUUID(),
    iat: now,
    exp: now + 600,
  };
  const token = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}.`;
  const res = await mcpPost({ Authorization: `Bearer ${token}` }, initializeBody);
  expect(res.status).toBe(401);
});

test("adapter enabled: token without a server-side mapping is 403", async () => {
  setEnv(oauthEnv());
  stubNetwork();
  const res = await mcpPost(
    { Authorization: `Bearer ${mint({ sub: "unmapped-demo" })}` },
    initializeBody,
  );
  expect(res.status).toBe(403);
});

test("adapter enabled: a token expiring mid-session fails closed on the next call", async () => {
  setEnv(oauthEnv());
  stubNetwork();
  const now = Math.floor(Date.now() / 1000);
  const session = await openSession(mint({ exp: now + 2 }));
  await new Promise((resolve) => setTimeout(resolve, 2200));
  const res = await callTool(session, "get_queue_status", {}, 7);
  expect(res.status).toBe(401);
});

// ── session binding ────────────────────────────────────────────────────
test("adapter enabled: an established session rejects a different token", async () => {
  setEnv(oauthEnv());
  stubNetwork();
  const session = await openSession(mint());
  const other = await mcpPost(
    { Authorization: `Bearer ${mint({ sub: "readonly-demo" })}`, "mcp-session-id": session.sessionId },
    { jsonrpc: "2.0", id: 8, method: "ping" },
  );
  expect(other.status).toBe(401);
});

// ── peer pinning ───────────────────────────────────────────────────────
test("adapter enabled: a mapped peer_id rejects a self-declared observer peer", async () => {
  setEnv(oauthEnv());
  const { calls } = stubNetwork();
  const session = await openSession(mint());

  const denied = await callTool(session, "chat", { peer_id: "someone-else", query: "hi" }, 9);
  expect(denied.status).toBe(200);
  const payload = (await denied.json()) as {
    result: { isError?: boolean; content: { text: string }[] };
  };
  expect(payload.result.isError).toBe(true);
  expect(calls.some((c) => c.url.includes("/peers/"))).toBe(false);

  // The mapped observer peer itself works.
  const allowed = await callTool(session, "chat", { peer_id: "native-demo", query: "hi" }, 91);
  expect((await allowed.json()).result.isError).toBeFalsy();
  const chatCall = calls.find((c) => c.url.includes("/peers/"));
  expect(chatCall?.url).toContain("/peers/native-demo/chat");
  expect(chatCall?.url).not.toContain("someone-else");
});

test("adapter enabled: schedule_dream refuses a foreign observer and pins the mapped one", async () => {
  setEnv(oauthEnv());
  const { calls } = stubNetwork();
  const session = await openSession(mint());

  const denied = await callTool(session, "schedule_dream", { peer_id: "someone-else" }, 10);
  expect((await denied.json()).result.isError).toBe(true);
  expect(calls.some((c) => c.url.includes("schedule_dream"))).toBe(false);

  const allowed = await callTool(session, "schedule_dream", { peer_id: "native-demo" }, 101);
  expect((await allowed.json()).result.isError).toBeFalsy();
  const dreamCall = calls.find((c) => c.url.includes("schedule_dream"));
  expect(dreamCall).toBeTruthy();
  expect(JSON.stringify(dreamCall!.body)).toContain("native-demo");
  expect(JSON.stringify(dreamCall!.body)).not.toContain("someone-else");
});

// ── native bearer policy when the adapter is on ────────────────────────
test("adapter enabled: a non-JWT bearer is refused unless native passthrough is allowed", async () => {
  setEnv(oauthEnv());
  stubNetwork();
  const res = await mcpPost(
    { Authorization: "Bearer hch-plain-api-key" },
    initializeBody,
  );
  expect(res.status).toBe(401);

  setEnv(oauthEnv({ MCP_OAUTH_ALLOW_NATIVE_BEARER: "1" }));
  const { calls } = stubNetwork();
  const ok = await mcpPost(
    { Authorization: "Bearer hch-plain-api-key" },
    initializeBody,
  );
  expect(ok.status).toBe(200);
  const sessionId = ok.headers.get("mcp-session-id")!;
  const call = await mcpPost(
    { Authorization: "Bearer hch-plain-api-key", "mcp-session-id": sessionId },
    {
      jsonrpc: "2.0",
      id: 11,
      method: "tools/call",
      params: { name: "get_queue_status", arguments: { workspace_id: "ws-native" } },
    },
  );
  expect(call.status).toBe(200);
  // Native passthrough still sends the caller's own key, and honors the
  // caller's workspace choice — the OAuth mapping does not apply to it.
  expect(calls[0]!.auth).toBe("Bearer hch-plain-api-key");
  expect(calls.some((c) => c.url.includes("/workspaces/ws-native/"))).toBe(true);
});

// ── protected resource metadata ────────────────────────────────────────
test("protected resource metadata points at the EDGAR auth server when enabled", async () => {
  setEnv(oauthEnv());
  stubNetwork();
  const res = await fetch(new Request(`${origin}/.well-known/oauth-protected-resource`));
  expect(res.status).toBe(200);
  const body = (await res.json()) as { authorization_servers: string[] };
  expect(body.authorization_servers).toEqual([ISSUER]);
});

// ── RFC 9728 path-aware discovery (EDG-15 release) ──────────────────────
// ChatGPT resolves the MCP server at https://honcho.edgars.tools/mcp, so it
// asks for the path-aware well-known URL first. A 404 there is exactly the
// live iOS failure「無法自動偵測 OAuth 設定」.
test("path-aware /.well-known/oauth-protected-resource/mcp answers 200 with the configured audience as resource", async () => {
  setEnv(oauthEnv());
  stubNetwork();
  const res = await fetch(
    new Request(`${origin}/.well-known/oauth-protected-resource/mcp`),
  );
  expect(res.status).toBe(200);
  const body = (await res.json()) as {
    resource: string;
    authorization_servers: string[];
    bearer_methods_supported: string[];
    scopes_supported: string[];
  };
  // The advertised resource identifier MUST be the exact string the AS
  // stamps into the token's aud and verifyAccessToken() compares against.
  // The origin without the /mcp path does not match MCP_OAUTH_AUDIENCE.
  expect(body.resource).toBe(AUDIENCE);
  expect(body.authorization_servers).toEqual([ISSUER]);
  expect(body.bearer_methods_supported).toEqual(["header"]);
  expect(body.scopes_supported).toContain("mcp:read");
  expect(body.scopes_supported).toContain("mcp:write");
});

test("the root metadata document advertises the same canonical resource", async () => {
  setEnv(oauthEnv());
  const pathAware = await fetch(
    new Request(`${origin}/.well-known/oauth-protected-resource/mcp`),
  );
  const root = await fetch(
    new Request(`${origin}/.well-known/oauth-protected-resource`),
  );
  expect(root.status).toBe(200);
  const body = (await root.json()) as { resource: string };
  expect(body.resource).toBe(AUDIENCE);
  expect(body.resource).toBe((await (await pathAware).json() as { resource: string }).resource);
});

test("OAuth disabled: metadata keeps the canonical /mcp resource and does not advertise the EDGAR AS", async () => {
  setEnv({});
  const res = await fetch(
    new Request(`${origin}/.well-known/oauth-protected-resource/mcp`),
  );
  expect(res.status).toBe(200);
  const body = (await res.json()) as {
    resource: string;
    authorization_servers: string[];
  };
  expect(body.resource).toBe(`${origin}/mcp`);
  // Defensive rule: with the adapter off the server takes raw Honcho keys,
  // so discovery must not point clients at the self-hosted EDGAR AS.
  expect(body.authorization_servers).not.toContain(ISSUER);
});

test("unknown protected-resource suffixes are 404, not wildcard matches", async () => {
  setEnv(oauthEnv());
  const res = await fetch(
    new Request(`${origin}/.well-known/oauth-protected-resource/some/other/path`),
  );
  expect(res.status).toBe(404);
});

test("a 401 challenge on /mcp points resource_metadata at the path-aware URL", async () => {
  setEnv(oauthEnv());
  const res = await mcpPost({}, initializeBody); // no bearer token
  expect(res.status).toBe(401);
  const challenge = res.headers.get("WWW-Authenticate") ?? "";
  expect(challenge).toContain(
    `resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp"`,
  );
});
