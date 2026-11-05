/**
 * EDG-15 stage: opt-in OAuth 2.1 resource-server adapter for the Streamable
 * HTTP transport. When enabled, callers present an EDGAR Auth Server access
 * token (RS256, verified against the issuer's JWKS) instead of a raw Honcho
 * API key. The backend Honcho key stays server-side and is never exposed.
 *
 * Identity is mapped server-side: a token's (client_id, sub) resolves to a
 * permitted workspace set and an optional pinned peer. Self-declared
 * workspace/peer arguments can never widen that grant — enforcement runs on
 * every tool call, not just at initialize.
 *
 * Disabled by default: with no MCP_OAUTH_* configuration the native
 * `Authorization: Bearer <honcho-key>` path is byte-for-byte unchanged.
 */
import type { Honcho } from "@honcho-ai/sdk";
import type { HonchoConfig } from "./config.js";
import type { ToolContext } from "./types.js";

declare const process: {
  env: Record<string, string | undefined>;
};

/** Distinguishes a 401 (re-authenticate) from a 403 (authenticated but denied). */
export type OAuthErrorKind = "invalid_token" | "insufficient_scope" | "forbidden";

export class OAuthError extends Error {
  readonly kind: OAuthErrorKind;
  constructor(kind: OAuthErrorKind, message: string) {
    super(message);
    this.name = "OAuthError";
    this.kind = kind;
  }
}

export interface OAuthSettings {
  enabled: boolean;
  issuer: string;
  audience: string;
  jwksUrl: string;
  requiredScope: string;
  mappingJson: string;
  /** Backend Honcho key used for upstream calls; never sent to clients. */
  serverApiKey: string;
  /** When true, non-JWT bearers fall through to the native key path. */
  allowNativeBearer: boolean;
}

export interface OAuthIdentity {
  sub: string;
  clientId: string;
  scopes: string[];
  jti: string;
  /** Workspaces this identity may touch; the first is the default. */
  workspaceIds: string[];
  /** When set, all peer-scoped operations are pinned to this peer. */
  peerId?: string;
}

interface Mapping {
  client_id?: string;
  sub: string;
  workspace_id?: string;
  workspace_ids?: string[];
  peer_id?: string;
  scopes?: string[];
}

const DEFAULT_REQUIRED_SCOPE = "mcp";
const JWKS_TTL_MS = 10 * 60 * 1000;
const JWKS_TIMEOUT_MS = 5_000;

function truthy(value: string | undefined): boolean {
  return value === "1" || value?.toLowerCase() === "true";
}

/**
 * Parse the adapter configuration. Throws when the adapter is switched on
 * but incomplete: a half-configured OAuth gate must fail loudly instead of
 * silently degrading to native keys.
 */
export function parseOAuthSettings(
  env: Record<string, string | undefined> = process.env,
): OAuthSettings {
  const settings: OAuthSettings = {
    enabled: truthy(env.MCP_OAUTH_ENABLED),
    issuer: env.MCP_OAUTH_ISSUER?.trim() ?? "",
    audience: env.MCP_OAUTH_AUDIENCE?.trim() ?? "",
    jwksUrl: env.MCP_OAUTH_JWKS_URL?.trim() ?? "",
    requiredScope: env.MCP_OAUTH_REQUIRED_SCOPE?.trim() || DEFAULT_REQUIRED_SCOPE,
    mappingJson: env.MCP_OAUTH_MAPPING?.trim() ?? "",
    serverApiKey: env.HONCHO_API_KEY?.trim() ?? "",
    allowNativeBearer: truthy(env.MCP_OAUTH_ALLOW_NATIVE_BEARER),
  };
  if (!settings.enabled) return settings;
  const missing = (["issuer", "audience", "jwksUrl", "mappingJson", "serverApiKey"] as const)
    .filter((key) => !settings[key]);
  if (missing.length > 0) {
    throw new Error(
      `OAuth adapter enabled but missing configuration: ${missing.join(", ")}`,
    );
  }
  return settings;
}

/** Honcho config for OAuth mode: server-side key, no caller-chosen workspace. */
export function oauthHonchoConfig(settings: OAuthSettings, baseUrl: string): HonchoConfig {
  return { apiKey: settings.serverApiKey, baseUrl };
}

/** A JWT is three base64url segments; Honcho API keys are opaque strings. */
export function looksLikeJwt(token: string): boolean {
  return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(token);
}

function b64urlDecode(segment: string): Uint8Array {
  const padded = segment.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function decodeJson(segment: string): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(b64urlDecode(segment))) as Record<string, unknown>;
}

// ── JWKS cache ─────────────────────────────────────────────────────────
interface JwksEntry {
  keys: Map<string, CryptoKey>;
  expires: number;
}
const jwksCache = new Map<string, JwksEntry>();

/** Test seam: drop cached JWKS keys so a fresh fetch is forced. */
export function resetJwksCache(): void {
  jwksCache.clear();
}

async function remoteJwks(
  url: string,
  fetchImpl: typeof fetch,
): Promise<{ keys: unknown[] }> {
  const response = await fetchImpl(url, { signal: AbortSignal.timeout(JWKS_TIMEOUT_MS) });
  if (!response.ok) {
    throw new OAuthError("invalid_token", `JWKS fetch failed with ${response.status}`);
  }
  return (await response.json()) as { keys: unknown[] };
}

async function jwksKeys(
  settings: OAuthSettings,
  fetchImpl: typeof fetch,
): Promise<Map<string, CryptoKey>> {
  const cached = jwksCache.get(settings.jwksUrl);
  if (cached && cached.expires > Date.now()) return cached.keys;

  const document = await remoteJwks(settings.jwksUrl, fetchImpl);

  const keys = new Map<string, CryptoKey>();
  for (const jwk of document.keys ?? []) {
    const key = jwk as JsonWebKey & { kid?: string; alg?: string };
    if (!key.kid || (key.alg && key.alg !== "RS256")) continue;
    if (key.kty !== "RSA") continue;
    const cryptoKey = await crypto.subtle.importKey(
      "jwk",
      key,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
    keys.set(key.kid, cryptoKey);
  }
  if (keys.size === 0) {
    throw new OAuthError("invalid_token", "JWKS contains no usable RS256 keys");
  }
  jwksCache.set(settings.jwksUrl, { keys, expires: Date.now() + JWKS_TTL_MS });
  return keys;
}

function claimsIncludeAudience(aud: unknown, audience: string): boolean {
  if (typeof aud === "string") return aud === audience;
  if (Array.isArray(aud)) return aud.includes(audience);
  return false;
}

function parseMappings(mappingJson: string): Mapping[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(mappingJson);
  } catch {
    throw new Error("MCP_OAUTH_MAPPING is not valid JSON");
  }
  const mappings = (parsed as { mappings?: unknown }).mappings;
  if (!Array.isArray(mappings)) {
    throw new Error('MCP_OAUTH_MAPPING must be {"mappings": [...]}');
  }
  return mappings as Mapping[];
}

/** Server-side (client_id, sub) → permitted workspace/peer resolution. */
export function resolveIdentity(
  settings: OAuthSettings,
  claims: Record<string, unknown>,
): OAuthIdentity {
  const sub = claims["sub"];
  const clientId = claims["client_id"];
  const scope = claims["scope"];
  const jti = claims["jti"];
  if (typeof sub !== "string" || !sub) throw new OAuthError("invalid_token", "missing sub");
  if (typeof clientId !== "string" || !clientId) {
    throw new OAuthError("invalid_token", "missing client_id");
  }
  if (typeof scope !== "string" || !scope) {
    throw new OAuthError("invalid_token", "missing scope");
  }
  if (typeof jti !== "string" || !jti) throw new OAuthError("invalid_token", "missing jti");

  const scopes = scope.split(/\s+/).filter(Boolean);
  if (!scopes.includes(settings.requiredScope)) {
    throw new OAuthError(
      "insufficient_scope",
      `token scope '${scope}' lacks required scope '${settings.requiredScope}'`,
    );
  }

  const mappings = parseMappings(settings.mappingJson);
  const exact = mappings.find((m) => m.sub === sub && m.client_id === clientId);
  const bySubject = mappings.find((m) => m.sub === sub && !m.client_id);
  const mapping = exact ?? bySubject;
  if (!mapping) {
    throw new OAuthError("forbidden", `no workspace mapping for subject '${sub}'`);
  }
  if (mapping.scopes && !scopes.every((s) => mapping.scopes!.includes(s))) {
    throw new OAuthError("insufficient_scope", "token scope exceeds the mapping's grant");
  }

  const workspaceIds = [
    ...(mapping.workspace_id ? [mapping.workspace_id] : []),
    ...(mapping.workspace_ids ?? []),
  ].filter((id, index, all) => typeof id === "string" && id.length > 0 && all.indexOf(id) === index);
  if (workspaceIds.length === 0) {
    throw new OAuthError("forbidden", `mapping for subject '${sub}' has no workspace`);
  }

  return {
    sub,
    clientId,
    scopes,
    jti,
    workspaceIds,
    peerId: mapping.peer_id || undefined,
  };
}

/**
 * Verify an RS256 access token against the issuer's JWKS and resolve the
 * server-side identity mapping. Fail-closed: any doubt is invalid_token.
 */
export async function verifyAccessToken(
  token: string,
  settings: OAuthSettings,
  fetchImpl: typeof fetch = globalThis.fetch,
): Promise<OAuthIdentity> {
  const parts = token.split(".");
  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) {
    throw new OAuthError("invalid_token", "malformed token");
  }
  const [headerSegment, claimsSegment, signatureSegment] = parts as [string, string, string];

  let header: Record<string, unknown>;
  let claims: Record<string, unknown>;
  try {
    header = decodeJson(headerSegment);
    claims = decodeJson(claimsSegment);
  } catch {
    throw new OAuthError("invalid_token", "token is not decodable JSON");
  }
  if (header["alg"] !== "RS256") {
    throw new OAuthError("invalid_token", `unsupported alg '${String(header["alg"])}'`);
  }
  const typ = header["typ"];
  if (typ !== undefined && typ !== "at+jwt") {
    throw new OAuthError("invalid_token", `unexpected typ '${String(typ)}'`);
  }
  const kid = header["kid"];
  if (typeof kid !== "string" || !kid) {
    throw new OAuthError("invalid_token", "missing kid");
  }

  const keys = await jwksKeys(settings, fetchImpl);
  const key = keys.get(kid);
  if (!key) {
    throw new OAuthError("invalid_token", `unknown kid '${kid}'`);
  }
  const verified = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    b64urlDecode(signatureSegment) as unknown as ArrayBuffer,
    new TextEncoder().encode(`${headerSegment}.${claimsSegment}`) as unknown as ArrayBuffer,
  );
  if (!verified) {
    throw new OAuthError("invalid_token", "signature verification failed");
  }

  if (claims["iss"] !== settings.issuer) {
    throw new OAuthError("invalid_token", "issuer mismatch");
  }
  if (!claimsIncludeAudience(claims["aud"], settings.audience)) {
    throw new OAuthError("invalid_token", "audience mismatch");
  }
  const now = Math.floor(Date.now() / 1000);
  const exp = claims["exp"];
  if (typeof exp !== "number" || exp <= now) {
    throw new OAuthError("invalid_token", "token expired");
  }
  const nbf = claims["nbf"];
  if (nbf !== undefined && (typeof nbf !== "number" || nbf > now + 1)) {
    throw new OAuthError("invalid_token", "token not yet valid");
  }

  return resolveIdentity(settings, claims);
}

// ── fail-closed tool context ───────────────────────────────────────────
/** Instances already patched by the guards (each is patched at most once). */
const guardedClients = new WeakSet<object>();
const guardedSessions = new WeakSet<object>();
const guardedUnscopedClients = new WeakSet<object>();

/** Workspace the identity may use: the mapped default, or a permitted pick. */
export function effectiveWorkspace(identity: OAuthIdentity, requested?: string): string {
  if (!requested) return identity.workspaceIds[0]!;
  if (!identity.workspaceIds.includes(requested)) {
    throw new OAuthError(
      "forbidden",
      `workspace '${requested}' is not permitted for this identity`,
    );
  }
  return requested;
}

function guardPeer(identity: OAuthIdentity, requested?: string): string {
  if (requested && requested !== identity.peerId) {
    throw new OAuthError(
      "forbidden",
      `peer '${requested}' is not permitted for this identity`,
    );
  }
  return identity.peerId!;
}

/** Mutable view of SDK objects whose methods this module pins. */
type Mutable = Record<string, unknown>;

/**
 * Patch one Honcho client so every peer-scoped call this identity makes is
 * pinned to the mapped observer peer. Applied once per cached instance.
 */
function guardClient(client: Honcho, identity: OAuthIdentity): Honcho {
  if (!identity.peerId || guardedClients.has(client)) {
    return client;
  }
  guardedClients.add(client);
  const originalPeer = client.peer.bind(client);
  client.peer = ((peerId?: string) =>
    originalPeer(guardPeer(identity, peerId) as never)) as typeof client.peer;

  const originalDream = client.scheduleDream?.bind(client);
  if (originalDream) {
    client.scheduleDream = (async (params: { observer?: string } = {}) => {
      const observer = params.observer;
      if (observer && observer !== identity.peerId) {
        throw new OAuthError(
          "forbidden",
          `peer '${observer}' is not permitted for this identity`,
        );
      }
      return originalDream({ ...params, observer: identity.peerId } as never);
    }) as typeof client.scheduleDream;
  }

  const originalSession = client.session.bind(client);
  client.session = (async (sessionId: string) => {
    const session = await originalSession(sessionId);
    if (guardedSessions.has(session)) return session;
    guardedSessions.add(session);

    // Message authorship is already pinned at the source: the MCP tools
    // build MessageInput objects from `client.peer(...)`, which the guard
    // above pins. Session membership is the remaining peer-scoped surface.
    const originalAddPeers = session.addPeers?.bind(session);
    if (originalAddPeers) {
      session.addPeers = (async (peers: unknown) => {
        const list = (Array.isArray(peers) ? peers : [peers]) as unknown[];
        for (const peer of list) {
          const entry = Array.isArray(peer) ? peer[0] : peer;
          const id = typeof entry === "string" ? entry : String((entry as { id?: string })?.id ?? "");
          if (id !== identity.peerId) {
            throw new OAuthError(
              "forbidden",
              `peer '${id}' is not permitted for this identity`,
            );
          }
        }
        return originalAddPeers(peers as never);
      }) as typeof session.addPeers;
    }
    return session;
  }) as typeof client.session;
  return client;
}

/**
 * The credential-scoped client is the escape hatch around workspace scoping
 * (`list_workspaces` sees every workspace the backend key can reach). In
 * OAuth mode it may only list permitted workspaces and get-or-create
 * permitted ones; every other unscoped route is refused.
 */
function guardUnscoped(client: Honcho, identity: OAuthIdentity): Honcho {
  if (guardedUnscopedClients.has(client)) return client;
  guardedUnscopedClients.add(client);
  const originalPost = client.http.post.bind(client.http);
  client.http.post = (async (path: string, options?: { body?: { id?: string } }) => {
    if (path.endsWith("/workspaces/list")) {
      const page = (await originalPost(path, options)) as Mutable;
      const items = ((page["items"] as { id?: string }[] | undefined) ?? []).filter((item) =>
        identity.workspaceIds.includes(item.id ?? ""),
      );
      return { ...page, items, total: items.length };
    }
    if (path.endsWith("/workspaces") || path.endsWith("/workspaces/")) {
      const requested = options?.body?.id;
      if (typeof requested !== "string" || !identity.workspaceIds.includes(requested)) {
        throw new OAuthError(
          "forbidden",
          `workspace '${String(requested)}' is not permitted for this identity`,
        );
      }
      return originalPost(path, options);
    }
    throw new OAuthError("forbidden", `route '${path}' is not available to OAuth identities`);
  }) as typeof client.http.post;
  return client;
}

/**
 * Wrap the native tool context so every tool call runs inside the token's
 * server-side grant: the workspace comes from the mapping (a self-declared
 * workspace can only pick among permitted ones, never widen), and peer
 * operations are pinned when the mapping names a peer.
 */
export function guardToolContext(base: ToolContext, identity: OAuthIdentity): ToolContext {
  return {
    config: base.config,
    clientFor: (workspaceId?: string) =>
      guardClient(base.clientFor(effectiveWorkspace(identity, workspaceId)), identity),
    unscoped: guardUnscoped(base.unscoped, identity),
    onUnauthorized: base.onUnauthorized,
  };
}
