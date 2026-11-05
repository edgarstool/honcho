import { AsyncLocalStorage } from "node:async_hooks";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import * as Sentry from "@sentry/bun";
import {
  HEADER_PLUGIN,
  honchoClients,
  identityHeaders,
  parseConfig,
  type Env,
  type HonchoConfig,
  sentryOptions,
} from "./config.js";
import {
  guardToolContext,
  looksLikeJwt,
  oauthHonchoConfig,
  OAuthError,
  parseOAuthSettings,
  toolAllowed,
  verifyAccessToken,
  type OAuthIdentity,
  type OAuthSettings,
} from "./oauth.js";
import { createServer } from "./server.js";
import { invalidTokenResponse, type ToolContext } from "./types.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

declare const process: {
  env: Record<string, string | undefined>;
};

type BunServer = { timeout(request: Request, seconds: number): void };

declare const Bun: {
  serve(options: {
    hostname: string;
    port: number;
    fetch(request: Request, server: BunServer): Response | Promise<Response>;
  }): { hostname: string; port: number };
};

const CORS_ORIGIN = "*";
const CORS_METHODS = "GET, POST, DELETE, OPTIONS";
const CORS_ALLOWED_HEADERS =
  "Content-Type, Authorization, X-Honcho-Workspace-ID, X-Honcho-Plugin, mcp-session-id, mcp-protocol-version, last-event-id";

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": CORS_ORIGIN,
  "Access-Control-Allow-Methods": CORS_METHODS,
  "Access-Control-Allow-Headers": CORS_ALLOWED_HEADERS,
  "Access-Control-Expose-Headers": "WWW-Authenticate, mcp-session-id",
};

const PROTECTED_RESOURCE_PATH = "/.well-known/oauth-protected-resource";
const MCP_PATHS = new Set(["/", "/mcp"]);

type Session = {
  transport: WebStandardStreamableHTTPServerTransport;
  server: McpServer;
  lastSeen: number;
  apiKey: string;
  /**
   * The raw bearer token this session was opened with. Compared on every
   * request: a session may not be reused with different credentials, whether
   * that is a different Honcho key or a different OAuth access token (in
   * OAuth mode `apiKey` is the shared server-side key, so it cannot serve
   * this purpose).
   */
  credential: string;
  /**
   * Set by a tool once the Honcho API rejects this session's access token.
   * A session is bound to one token, so it stays set.
   */
  auth: { rejected: boolean };
  /** Requests on this session that are still being handled. */
  inFlight: number;
};

const sessions = new Map<string, Session>();
/** Set on the request whose own tool call saw the token refused. */
const requestAuth = new AsyncLocalStorage<{ rejected: boolean }>();
const DEFAULT_SESSION_IDLE_MS = 30 * 60 * 1000;
const DEFAULT_SESSION_MAX = 128;

function envInt(name: string, fallback: number): number {
  const n = Number(process.env[name]);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function closeSession(session: Session): void {
  void session.transport.close();
  void session.server.close();
}

function dropSession(id: string): void {
  const session = sessions.get(id);
  if (!session) return;
  sessions.delete(id);
  closeSession(session);
}

function sweepSessions(): void {
  const idleMs = envInt("MCP_SESSION_IDLE_MS", DEFAULT_SESSION_IDLE_MS);
  const now = Date.now();
  for (const [id, session] of sessions) {
    if (now - session.lastSeen > idleMs) dropSession(id);
  }
}

function envBindings(): Env {
  return {
    HONCHO_API_URL: process.env.HONCHO_API_URL,
    HONCHO_TIMEOUT_MS: process.env.HONCHO_TIMEOUT_MS,
  };
}

function authorizationServer(): string {
  try {
    const settings = parseOAuthSettings();
    if (settings.enabled) return settings.issuer;
  } catch {
    // Fall through to the Honcho-hosted default below.
  }
  return process.env.HONCHO_API_URL?.trim() || "https://api.honcho.dev";
}

function withCors(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(CORS_HEADERS)) {
    headers.set(key, value);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function jsonResponse(
  body: unknown,
  status: number,
  extraHeaders?: Record<string, string>,
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...CORS_HEADERS,
      ...extraHeaders,
    },
  });
}

function configForRequest(request: Request) {
  return parseConfig(request, envBindings());
}

function configOrUnauthorized(request: Request): HonchoConfig | Response {
  try {
    return configForRequest(request);
  } catch (e) {
    const message = e instanceof Error ? e.message : "Invalid request";
    return unauthorized(request, message);
  }
}

/** What one request's bearer token resolved to. */
type RequestAuth =
  | { kind: "native"; config: HonchoConfig; credential: string }
  | {
      kind: "oauth";
      config: HonchoConfig;
      identity: OAuthIdentity;
      credential: string;
    };

function bearerToken(request: Request): string | null {
  const match = request.headers.get("Authorization")?.trim().match(/^Bearer\s+(.*)$/i);
  const token = match?.[1]?.trim();
  return token ? token : null;
}

/**
 * Resolve one request's credentials. With the OAuth adapter off this is the
 * untouched native path (the bearer token is the caller's Honcho key). With
 * it on, a JWT bearer is verified against the EDGAR auth server's JWKS and
 * mapped server-side; anything that fails verification is a 401/403, never
 * a silent fallback to the native key path.
 */
async function resolveRequestAuth(
  request: Request,
  env: Env,
): Promise<RequestAuth | Response> {
  let settings: OAuthSettings;
  try {
    settings = parseOAuthSettings();
  } catch (e) {
    const message = e instanceof Error ? e.message : "Invalid request";
    return jsonResponse({ error: `OAuth adapter misconfigured: ${message}` }, 500);
  }
  const token = bearerToken(request);
  if (!token) {
    return unauthorized(
      request,
      "Missing Authorization header. Provide 'Authorization: Bearer <token>'.",
    );
  }

  if (!settings.enabled) {
    const config = configOrUnauthorized(request);
    if (config instanceof Response) return config;
    return { kind: "native", config, credential: token };
  }

  if (!looksLikeJwt(token)) {
    if (!settings.allowNativeBearer) {
      return unauthorized(
        request,
        "This server accepts OAuth access tokens only; a raw API key is not a valid credential here.",
      );
    }
    const config = configOrUnauthorized(request);
    if (config instanceof Response) return config;
    return { kind: "native", config, credential: token };
  }

  try {
    const identity = await verifyAccessToken(token, settings);
    return {
      kind: "oauth",
      config: oauthHonchoConfig(
        settings,
        env.HONCHO_API_URL?.trim() || "https://api.honcho.dev",
      ),
      identity,
      credential: token,
    };
  } catch (e) {
    const resourceMetadata = `${new URL(request.url).origin}${PROTECTED_RESOURCE_PATH}`;
    if (e instanceof OAuthError && e.kind === "invalid_token") {
      // RFC 6750 §3 + RFC 9728 §5.1: invalid_token tells the client to
      // refresh rather than re-authenticate from scratch.
      return jsonResponse(
        { error: "invalid_token", error_description: e.message },
        401,
        {
          "WWW-Authenticate": `Bearer error="invalid_token", error_description="${e.message}", resource_metadata="${resourceMetadata}"`,
        },
      );
    }
    if (e instanceof OAuthError) {
      // insufficient_scope / forbidden: authenticated, but not allowed.
      return jsonResponse({ error: e.kind, error_description: e.message }, 403, {
        "WWW-Authenticate": `Bearer error="${e.kind}" resource_metadata="${resourceMetadata}"`,
      });
    }
    throw e;
  }
}

function rejectedToken(request: Request): Response {
  const resourceMetadata = `${new URL(request.url).origin}${PROTECTED_RESOURCE_PATH}`;
  return invalidTokenResponse(resourceMetadata, CORS_HEADERS);
}

function unauthorized(request: Request, message: string): Response {
  const resourceMetadata = `${new URL(request.url).origin}${PROTECTED_RESOURCE_PATH}`;
  return jsonResponse(
    { error: message },
    401,
    {
      "WWW-Authenticate": `Bearer resource_metadata="${resourceMetadata}"`,
    },
  );
}

async function handleMcp(request: Request): Promise<Response> {
  sweepSessions();
  const sessionId = request.headers.get("mcp-session-id");
  if (sessionId) {
    const existing = sessions.get(sessionId);
    if (existing) {
      const auth = await resolveRequestAuth(request, envBindings());
      if (auth instanceof Response) return auth;
      if (auth.credential !== existing.credential) {
        return unauthorized(
          request,
          "Authorization does not match this session.",
        );
      }
      existing.lastSeen = Date.now();
      existing.inFlight++;
      const mine = { rejected: false };
      let response: Response;
      try {
        response = await requestAuth.run(mine, () =>
          existing.transport.handleRequest(request),
        );
      } finally {
        existing.inFlight--;
      }
      if (existing.auth.rejected) {
        // The Honcho API refused this session's OAuth access token. Retire
        // the session id so the next request starts a new session with the
        // refreshed token. Close the session only after its last running
        // call: closing it earlier drops their pending replies.
        sessions.delete(sessionId);
        if (existing.inFlight === 0) closeSession(existing);
      }
      // Only the request whose own call was refused is answered 401, so the
      // client refreshes. A call that passed before the token died keeps
      // its result; a write it already made must not look like a failure.
      if (mine.rejected) return rejectedToken(request);
      return withCors(response);
    }
  }

  // A Mcp-Session-Id header was sent but no matching session exists, so it was
  // terminated (idle sweep, container restart). The Streamable HTTP spec
  // requires the server to answer requests carrying a terminated session ID
  // with HTTP 404 so the client starts a new session by reinitializing; a
  // request with no session header at all falls through to the 400 path below.
  if (sessionId) {
    return jsonResponse(
      {
        jsonrpc: "2.0",
        error: {
          code: -32000,
          message: "Session not found",
        },
        id: null,
      },
      404,
    );
  }

  if (request.method !== "POST") {
    return jsonResponse(
      {
        jsonrpc: "2.0",
        error: {
          code: -32000,
          message: "Bad Request: No valid session ID provided",
        },
        id: null,
      },
      400,
    );
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return jsonResponse(
      {
        jsonrpc: "2.0",
        error: { code: -32700, message: "Parse error: Invalid JSON" },
        id: null,
      },
      400,
    );
  }

  const messages = Array.isArray(body) ? body : [body];
  if (!messages.some((message) => isInitializeRequest(message))) {
    return jsonResponse(
      {
        jsonrpc: "2.0",
        error: {
          code: -32000,
          message: "Bad Request: No valid session ID provided",
        },
        id: null,
      },
      400,
    );
  }

  const auth = await resolveRequestAuth(request, envBindings());
  if (auth instanceof Response) return auth;

  const rejected = { rejected: false };
  const headers = identityHeaders(
    request.headers.get("User-Agent"),
    request.headers.get(HEADER_PLUGIN),
  );
  const onUnauthorized = () => {
    rejected.rejected = true;
    const mine = requestAuth.getStore();
    if (mine) mine.rejected = true;
  };
  const base: ToolContext = {
    config: auth.config,
    ...honchoClients(auth.config, headers),
    onUnauthorized,
  };
  // OAuth sessions run inside the token's server-side grant: workspace and
  // peer scope are enforced on every tool call, and the tool set itself is
  // filtered per identity (mcp:read vs mcp:write, workspace-wide tools for
  // single-peer mappings), not just at initialize.
  const identity = auth.kind === "oauth" ? auth.identity : undefined;
  const ctx: ToolContext = identity ? guardToolContext(base, identity) : base;
  const server = createServer(
    ctx,
    identity
      ? { allows: (name, tool) => toolAllowed(name, tool.readOnly, identity) }
      : undefined,
  );

  const maxSessions = envInt("MCP_SESSION_MAX", DEFAULT_SESSION_MAX);
  if (sessions.size >= maxSessions) {
    return jsonResponse(
      {
        jsonrpc: "2.0",
        error: {
          code: -32000,
          message: "Too many active sessions",
        },
        id: null,
      },
      503,
    );
  }

  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: () => crypto.randomUUID(),
    // Tool results come back as one JSON body, so the status line is decided
    // after the tool ran and a rejected token can be a real 401.
    enableJsonResponse: true,
    onsessioninitialized: (id) => {
      sessions.set(id, {
        transport,
        server,
        lastSeen: Date.now(),
        apiKey: auth.config.apiKey,
        credential: auth.credential,
        auth: rejected,
        inFlight: 0,
      });
    },
  });
  transport.onclose = () => {
    const id = transport.sessionId;
    if (id) sessions.delete(id);
  };

  await server.connect(transport);
  return withCors(
    await transport.handleRequest(request, { parsedBody: body }),
  );
}

export async function fetch(
  request: Request,
  server?: BunServer,
): Promise<Response> {
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  const pathname = new URL(request.url).pathname;

  if (pathname === "/health") {
    return jsonResponse({ status: "ok" }, 200);
  }

  if (pathname === PROTECTED_RESOURCE_PATH) {
    return jsonResponse(
      {
        resource: new URL(request.url).origin,
        authorization_servers: [authorizationServer()],
        bearer_methods_supported: ["header"],
        scopes_supported: ["mcp", "mcp:read", "mcp:write"],
      },
      200,
    );
  }

  if (!MCP_PATHS.has(pathname)) {
    return jsonResponse({ error: "Not Found" }, 404);
  }

  // A tool call writes nothing until it finishes, so Bun's 10s idle timeout
  // would drop any call slower than that.
  server?.timeout(request, 0);

  try {
    return await handleMcp(request);
  } catch (e) {
    Sentry.captureException(e);
    const message =
      e instanceof Error ? e.message : "Internal server error";
    return jsonResponse({ error: message }, 500);
  }
}

const isMain = Boolean((import.meta as { main?: boolean }).main);
if (isMain) {
  Sentry.init(sentryOptions({ SENTRY_DSN: process.env.SENTRY_DSN }));
  const hostname = process.env.HOST?.trim() || "0.0.0.0";
  const port = Number(process.env.PORT) || 3000;
  Bun.serve({ hostname, port, fetch });
  console.error(`honcho-mcp listening on http://${hostname}:${port}`);
}
