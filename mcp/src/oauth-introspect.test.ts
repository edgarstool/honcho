/**
 * EDG-15 P0 closure — revocation (gap 1).
 *
 * A correctly signed, unexpired RS256 token can still have been revoked
 * at the authorization server. JWKS verification alone cannot see that,
 * so the adapter must interrogate the AS's RFC 7662 /introspect endpoint
 * about THIS token on every request — no positive-result cache — and
 * fail closed on timeout or a malformed reply.
 *
 * These tests drive the real Streamable HTTP handler (src/http.ts) with
 * the real MCP SDK transport against a synthetic AS: a JWKS endpoint and
 * an /introspect endpoint whose answers the test controls. The Honcho
 * backend is likewise synthetic (in-process fetch stub), so nothing here
 * talks to a real Honcho database.
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

function decodeSegment(segment: string): Record<string, unknown> {
  const padded = segment.replace(/-/g, "+").replace(/_/g, "/");
  return JSON.parse(Buffer.from(padded, "base64").toString("utf8")) as Record<
    string,
    unknown
  >;
}

interface MintOptions {
  sub?: string;
  clientId?: string;
  scope?: string;
  exp?: number;
  iat?: number;
}

function mint(options: MintOptions = {}): string {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "at+jwt", kid: TRUSTED_KID };
  const claims: Record<string, unknown> = {
    iss: ISSUER,
    sub: options.sub ?? "native-demo",
    aud: AUDIENCE,
    client_id: options.clientId ?? CLIENT_ID,
    scope: options.scope ?? "mcp",
    jti: randomUUID(),
    iat: options.iat ?? now,
    nbf: now,
    exp: options.exp ?? now + 600,
    ver: 1,
  };
  const signer = createSign("RSA-SHA256");
  signer.update(`${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`);
  const signature = signer.sign(trusted.privateKey);
  return `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}.${b64url(signature)}`;
}

// ── fixtures ──────────────────────────────────────────────────────────
const ISSUER = "https://auth.edgars.tools";
const AUDIENCE = "https://mcp.edgars.tools/mcp";
const JWKS_URL = "https://auth.edgars.tools/jwks.json";
const INTROSPECT_URL = "https://auth.edgars.tools/introspect";
const CLIENT_ID = "honcho-console";
const CLIENT_SECRET = "confidential-secret-value";
const SERVER_KEY = "server-side-honcho-key-never-exposed";

const MAPPING = JSON.stringify({
  mappings: [
    {
      client_id: CLIENT_ID,
      sub: "native-demo",
      workspace_id: "ws-alpha",
      peer_id: "native-demo",
      scopes: ["mcp", "mcp:read", "mcp:write"],
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
    MCP_OAUTH_INTROSPECT_URL: INTROSPECT_URL,
    MCP_OAUTH_INTROSPECT_CLIENT_ID: CLIENT_ID,
    MCP_OAUTH_INTROSPECT_CLIENT_SECRET: CLIENT_SECRET,
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

// ── synthetic authorization server ────────────────────────────────────
interface IntrospectCall {
  url: string;
  auth: string | null;
  contentType: string | null;
  body: string;
}

interface IntrospectBehavior {
  /** Force `active` regardless of the revoked set. */
  active?: boolean;
  /** Claim overrides for the reply, to simulate a disagreeing AS. */
  override?: Record<string, unknown>;
  /** Claims to omit from an otherwise valid reply. */
  omit?: string[];
  /** Raw (non-JSON) body to answer with. */
  rawBody?: string;
  /** HTTP status to answer with. */
  httpStatus?: number;
  /** Delay before answering, to exercise the timeout path. */
  delayMs?: number;
}

const introspectCalls: IntrospectCall[] = [];
/** jtis the synthetic AS reports as revoked. */
const revokedJtis = new Set<string>();
let behavior: IntrospectBehavior = {};

function expectedBasic(): string {
  const bytes = new TextEncoder().encode(`${CLIENT_ID}:${CLIENT_SECRET}`);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return `Basic ${btoa(binary)}`;
}

/** Stubs JWKS, /introspect and the (unused) Honcho backend. */
function stubAuthServer(): void {
  introspectCalls.length = 0;
  revokedJtis.clear();
  behavior = {};
  globalThis.fetch = (async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url.startsWith(JWKS_URL)) {
      return json(200, { keys: [jwkFor(trusted.publicKey as KeyObject, TRUSTED_KID)] });
    }
    if (url === INTROSPECT_URL) {
      const headers = new Headers(
        (init?.headers ?? (input instanceof Request ? input.headers : undefined)) as
          | HeadersInit
          | undefined,
      );
      const body = typeof init?.body === "string" ? init.body : "";
      introspectCalls.push({
        url,
        auth: headers.get("authorization"),
        contentType: headers.get("content-type"),
        body,
      });
      if (behavior.delayMs) {
        await new Promise<void>((resolve, reject) => {
          const timer = setTimeout(resolve, behavior.delayMs);
          init?.signal?.addEventListener("abort", () => {
            clearTimeout(timer);
            reject(new DOMException("The operation was aborted.", "AbortError"));
          });
        });
      }
      if (behavior.httpStatus !== undefined && behavior.httpStatus !== 200) {
        return json(behavior.httpStatus, { error: "introspection unavailable" });
      }
      if (behavior.rawBody !== undefined) {
        return new Response(behavior.rawBody, {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      const token = new URLSearchParams(body).get("token") ?? "";
      const claims = decodeSegment(token.split(".")[1] ?? "");
      const active =
        behavior.active ?? !revokedJtis.has(String(claims["jti"]));
      const reply: Record<string, unknown> = {
        active,
        sub: behavior.override?.sub ?? claims["sub"],
        client_id: behavior.override?.client_id ?? claims["client_id"],
        iss: behavior.override?.iss ?? claims["iss"],
        aud: behavior.override?.aud ?? claims["aud"],
        exp: behavior.override?.exp ?? claims["exp"],
        iat: behavior.override?.iat ?? claims["iat"],
        scope: behavior.override?.scope ?? claims["scope"],
      };
      for (const key of behavior.omit ?? []) delete reply[key];
      return json(200, reply);
    }
    // Honcho backend (synthetic): only queue status is exercised here.
    const path = new URL(url).pathname;
    if (path.endsWith("/queue/status")) {
      return json(200, { total: 1, completed: 1, in_progress: 0, pending: 0 });
    }
    return json(200, {
      id: "ws-alpha",
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
    clientInfo: { name: "edg15-introspect-test", version: "0.0.0" },
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

// ── good tokens continue ──────────────────────────────────────────────
test("adapter enabled: every request interrogates the AS and a good token continues to work", async () => {
  setEnv(oauthEnv());
  stubAuthServer();
  const token = mint();
  const session = await openSession(token);

  const list = await mcpPost(
    { ...session.headers, "mcp-session-id": session.sessionId },
    { jsonrpc: "2.0", id: 2, method: "tools/list" },
  );
  expect(list.status).toBe(200);

  const read = await callTool(session, "get_queue_status", {}, 3);
  expect(read.status).toBe(200);
  const payload = (await read.json()) as { result: { isError?: boolean } };
  expect(payload.result.isError).toBeFalsy();

  // initialize + tools/list + tools/call: one fresh interrogation each,
  // no positive cache anywhere in between.
  expect(introspectCalls.length).toBe(3);
  for (const call of introspectCalls) {
    // Confidential client: HTTP Basic, form-encoded token, HTTPS endpoint.
    expect(call.auth).toBe(expectedBasic());
    expect(call.contentType).toBe("application/x-www-form-urlencoded");
    expect(call.url).toBe(INTROSPECT_URL);
    expect(new URLSearchParams(call.body).get("token")).toBe(token);
    expect(new URLSearchParams(call.body).get("token_type_hint")).toBe("access_token");
  }
});

// ── revocation ────────────────────────────────────────────────────────
test("adapter enabled: an unexpired but revoked token is 401 at the next initialize", async () => {
  setEnv(oauthEnv());
  stubAuthServer();
  const token = mint();
  revokedJtis.add(decodeSegment(token.split(".")[1]!)["jti"] as string);

  const res = await mcpPost({ Authorization: `Bearer ${token}` }, initializeBody);
  expect(res.status).toBe(401);
  expect(res.headers.get("WWW-Authenticate")).toContain('error="invalid_token"');
  // The AS was actually asked; this is not a local-signature rejection.
  expect(introspectCalls.length).toBe(1);
});

test("adapter enabled: revocation mid-session is 401 on tools/list and tools/call", async () => {
  setEnv(oauthEnv());
  stubAuthServer();
  const token = mint();
  const session = await openSession(token);
  expect(introspectCalls.length).toBe(1);

  // The AS revokes the token while the session is established.
  revokedJtis.add(decodeSegment(token.split(".")[1]!)["jti"] as string);

  const list = await mcpPost(
    { ...session.headers, "mcp-session-id": session.sessionId },
    { jsonrpc: "2.0", id: 2, method: "tools/list" },
  );
  expect(list.status).toBe(401);

  const call = await callTool(session, "get_queue_status", {}, 3);
  expect(call.status).toBe(401);
  expect(call.headers.get("WWW-Authenticate")).toContain('error="invalid_token"');

  // A fresh token on a NEW session works again: the denial is per token.
  const fresh = mint();
  const freshSession = await openSession(fresh);
  const ok = await callTool(freshSession, "get_queue_status", {}, 4);
  expect(ok.status).toBe(200);
});

// ── fail-closed on the introspection channel ──────────────────────────
test("adapter enabled: an introspection timeout is 401 invalid_token", async () => {
  setEnv(oauthEnv({ MCP_OAUTH_INTROSPECT_TIMEOUT_MS: "80" }));
  stubAuthServer();
  behavior = { delayMs: 500 };

  const res = await mcpPost({ Authorization: `Bearer ${mint()}` }, initializeBody);
  expect(res.status).toBe(401);
  expect(res.headers.get("WWW-Authenticate")).toContain('error="invalid_token"');
});

test("adapter enabled: a 500 from the introspection endpoint is 401", async () => {
  setEnv(oauthEnv());
  stubAuthServer();
  behavior = { httpStatus: 500 };

  const res = await mcpPost({ Authorization: `Bearer ${mint()}` }, initializeBody);
  expect(res.status).toBe(401);
});

test("adapter enabled: a non-JSON introspection reply is 401", async () => {
  setEnv(oauthEnv());
  stubAuthServer();
  behavior = { rawBody: "<html>gateway error</html>" };

  const res = await mcpPost({ Authorization: `Bearer ${mint()}` }, initializeBody);
  expect(res.status).toBe(401);
});

test("adapter enabled: an introspection reply without `active` is 401", async () => {
  setEnv(oauthEnv());
  stubAuthServer();
  behavior = { omit: ["active"] };

  const res = await mcpPost({ Authorization: `Bearer ${mint()}` }, initializeBody);
  expect(res.status).toBe(401);
});

// ── claim crosscheck ──────────────────────────────────────────────────
test("adapter enabled: an introspection reply that disagrees with the token is 401", async () => {
  const cases: { name: string; behavior: IntrospectBehavior }[] = [
    { name: "sub", behavior: { override: { sub: "someone-else" } } },
    { name: "client_id", behavior: { override: { client_id: "other-client" } } },
    { name: "iss", behavior: { override: { iss: "https://evil.example" } } },
    { name: "aud", behavior: { override: { aud: "https://other.example/mcp" } } },
    { name: "exp", behavior: { override: { exp: 9999999999 } } },
    { name: "iat", behavior: { override: { iat: 1 } } },
    { name: "scope", behavior: { override: { scope: "openid profile" } } },
  ];
  for (const { name, behavior: b } of cases) {
    setEnv(oauthEnv());
    stubAuthServer();
    behavior = b;
    const res = await mcpPost({ Authorization: `Bearer ${mint()}` }, initializeBody);
    expect(res.status).toBe(401);
  }
});

test("adapter enabled: a reply that omits exp/iat/scope is accepted when active", async () => {
  // RFC 7662 marks those fields optional; absence is not a disagreement.
  setEnv(oauthEnv());
  stubAuthServer();
  behavior = { omit: ["exp", "iat", "scope", "iss", "aud"] };
  const res = await mcpPost({ Authorization: `Bearer ${mint()}` }, initializeBody);
  expect(res.status).toBe(200);
});

// ── configuration ─────────────────────────────────────────────────────
test("adapter enabled: an http:// introspection URL is refused at configuration time", async () => {
  setEnv(oauthEnv({ MCP_OAUTH_INTROSPECT_URL: "http://auth.edgars.tools/introspect" }));
  stubAuthServer();
  const res = await mcpPost({ Authorization: `Bearer ${mint()}` }, initializeBody);
  // Fail loudly: a half-configured gate must not silently degrade.
  expect(res.status).toBe(500);
  expect(await res.text()).toContain("https");
});

test("adapter enabled: introspection without client credentials is refused at configuration time", async () => {
  const env = oauthEnv();
  delete env.MCP_OAUTH_INTROSPECT_CLIENT_SECRET;
  setEnv(env);
  stubAuthServer();
  const res = await mcpPost({ Authorization: `Bearer ${mint()}` }, initializeBody);
  expect(res.status).toBe(500);
});

test("adapter enabled: without introspection configuration the JWKS-only path still works", async () => {
  const env = oauthEnv();
  delete env.MCP_OAUTH_INTROSPECT_URL;
  delete env.MCP_OAUTH_INTROSPECT_CLIENT_ID;
  delete env.MCP_OAUTH_INTROSPECT_CLIENT_SECRET;
  setEnv(env);
  stubAuthServer();

  const session = await openSession(mint());
  const read = await callTool(session, "get_queue_status", {}, 2);
  expect(read.status).toBe(200);
  // No /introspect traffic at all when the endpoint is not configured.
  expect(introspectCalls.length).toBe(0);
});
