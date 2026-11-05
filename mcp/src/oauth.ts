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
  /**
   * RFC 7662 introspection endpoint of the authorization server. When set,
   * every request asks the AS whether THIS token is still active — a
   * correctly signed, unexpired token is still refused with 401 once the
   * AS reports it inactive (revoked). Empty leaves JWKS-only verification,
   * which structurally cannot see revocation.
   */
  introspectUrl: string;
  /** Confidential client credentials for the introspection call (HTTP Basic). */
  introspectClientId: string;
  introspectClientSecret: string;
  /** Per-request cap on the introspection round trip. */
  introspectTimeoutMs: number;
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
const INTROSPECT_TIMEOUT_MS = 5_000;
/** Fine-grained scopes: `mcp:read` narrows a token to reads, `mcp:write` grants mutations. */
const READ_SCOPE = "mcp:read";
const WRITE_SCOPE = "mcp:write";

function truthy(value: string | undefined): boolean {
  return value === "1" || value?.toLowerCase() === "true";
}

function positiveInt(value: string | undefined, fallback: number): number {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
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
    introspectUrl: env.MCP_OAUTH_INTROSPECT_URL?.trim() ?? "",
    introspectClientId: env.MCP_OAUTH_INTROSPECT_CLIENT_ID?.trim() ?? "",
    introspectClientSecret: env.MCP_OAUTH_INTROSPECT_CLIENT_SECRET?.trim() ?? "",
    introspectTimeoutMs: positiveInt(
      env.MCP_OAUTH_INTROSPECT_TIMEOUT_MS,
      INTROSPECT_TIMEOUT_MS,
    ),
  };
  if (!settings.enabled) return settings;
  const missing = (["issuer", "audience", "jwksUrl", "mappingJson", "serverApiKey"] as const)
    .filter((key) => !settings[key]);
  if (missing.length > 0) {
    throw new Error(
      `OAuth adapter enabled but missing configuration: ${missing.join(", ")}`,
    );
  }
  if (settings.introspectUrl) {
    // Revocation interrogation is a confidential-client call: without
    // credentials, or over plain HTTP, the endpoint is unusable — and a
    // silently skipped check is exactly the gap this stage closes.
    if (!settings.introspectClientId || !settings.introspectClientSecret) {
      throw new Error(
        "MCP_OAUTH_INTROSPECT_URL requires MCP_OAUTH_INTROSPECT_CLIENT_ID and MCP_OAUTH_INTROSPECT_CLIENT_SECRET (confidential client)",
      );
    }
    let parsed: URL;
    try {
      parsed = new URL(settings.introspectUrl);
    } catch {
      throw new Error(
        `MCP_OAUTH_INTROSPECT_URL is not a valid URL: ${settings.introspectUrl}`,
      );
    }
    if (parsed.protocol !== "https:") {
      throw new Error(
        "MCP_OAUTH_INTROSPECT_URL must use https:// — the introspection request carries client credentials",
      );
    }
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

// ── revocation: RFC 7662 introspection ────────────────────────────────
function basicAuth(clientId: string, clientSecret: string): string {
  const bytes = new TextEncoder().encode(`${clientId}:${clientSecret}`);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return `Basic ${btoa(binary)}`;
}

/**
 * Ask the authorization server whether this exact token is still active
 * (RFC 7662). Fail-closed: a timeout, an unreachable endpoint, a non-200,
 * or a reply that is not the expected JSON shape is invalid_token — none
 * of those is a grant.
 */
async function introspectToken(
  token: string,
  settings: OAuthSettings,
  fetchImpl: typeof fetch,
): Promise<Record<string, unknown>> {
  let response: Response;
  try {
    response = await fetchImpl(settings.introspectUrl, {
      method: "POST",
      headers: {
        Authorization: basicAuth(
          settings.introspectClientId,
          settings.introspectClientSecret,
        ),
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: new URLSearchParams({
        token,
        token_type_hint: "access_token",
      }).toString(),
      signal: AbortSignal.timeout(settings.introspectTimeoutMs),
    });
  } catch {
    throw new OAuthError(
      "invalid_token",
      "token introspection failed (endpoint unreachable or timed out)",
    );
  }
  if (!response.ok) {
    throw new OAuthError(
      "invalid_token",
      `token introspection returned ${response.status}`,
    );
  }
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new OAuthError("invalid_token", "token introspection reply is not JSON");
  }
  if (typeof body !== "object" || body === null) {
    throw new OAuthError(
      "invalid_token",
      "token introspection reply is not an object",
    );
  }
  return body as Record<string, unknown>;
}

/**
 * Crosscheck the AS's introspection reply against the verified token's own
 * claims. An AS that reports "active" for a different subject, or whose
 * view of exp/scope has drifted from the signed token, is not evidence
 * that THIS token is good. Optional RFC 7662 fields are skipped when the
 * AS omits them; present ones must agree.
 */
function crosscheckIntrospection(
  settings: OAuthSettings,
  claims: Record<string, unknown>,
  introspected: Record<string, unknown>,
): void {
  const disagree = (field: string): never => {
    throw new OAuthError(
      "invalid_token",
      `introspection reply disagrees with the token on '${field}'`,
    );
  };
  if (introspected["sub"] !== claims["sub"]) disagree("sub");
  if (introspected["client_id"] !== claims["client_id"]) disagree("client_id");
  if (
    introspected["iss"] !== undefined &&
    introspected["iss"] !== settings.issuer
  ) {
    disagree("iss");
  }
  if (
    introspected["aud"] !== undefined &&
    !claimsIncludeAudience(introspected["aud"], settings.audience)
  ) {
    disagree("aud");
  }
  const exp = introspected["exp"];
  if (exp !== undefined && (typeof exp !== "number" || exp !== claims["exp"])) {
    disagree("exp");
  }
  const iat = introspected["iat"];
  if (iat !== undefined && (typeof iat !== "number" || iat !== claims["iat"])) {
    disagree("iat");
  }
  const scope = introspected["scope"];
  if (scope !== undefined) {
    if (typeof scope !== "string") {
      throw new OAuthError(
        "invalid_token",
        "introspection reply disagrees with the token on 'scope'",
      );
    }
    const granted = scope.split(/\s+/).filter(Boolean);
    const carried = String(claims["scope"] ?? "").split(/\s+/).filter(Boolean);
    if (!granted.includes(settings.requiredScope)) disagree("scope");
    if (!carried.every((s) => granted.includes(s))) disagree("scope");
  }
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

  // Revocation is not a claim: a correctly signed, unexpired token can
  // still have been revoked at the AS. When an introspection endpoint is
  // configured it is asked about THIS token on every verification — no
  // positive result is cached, because "active" a minute ago is not
  // "active" now. Anything but an unambiguous, agreeing "active" fails
  // closed as invalid_token.
  if (settings.introspectUrl) {
    const introspected = await introspectToken(token, settings, fetchImpl);
    if (introspected["active"] !== true) {
      throw new OAuthError(
        "invalid_token",
        "token is revoked or inactive at the authorization server",
      );
    }
    crosscheckIntrospection(settings, claims, introspected);
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
    // A single-peer mapping is a per-peer grant: the session's content,
    // membership and destructive ops are only available when the mapped
    // peer actually takes part in it (checked against the live member
    // list, never cached across sessions).
    guardSessionForPeer(session as unknown as Mutable, identity.peerId!);
    return session;
  }) as typeof client.session;
  return client;
}

/**
 * Pin one session object to `peerId`. Every read — and every destructive
 * op — first checks, against the live member list, that the peer takes
 * part in the session; content of an unrelated session is workspace-wide
 * data the grant does not include. Fail-closed: a member list that cannot
 * be read is not a grant. Applied once per session object.
 */
function guardSessionForPeer(session: Mutable, peerId: string): void {
  const originalPeers = session["peers"];
  if (typeof originalPeers !== "function") return;
  const listPeers = (originalPeers as () => Promise<{ id: string }[]>).bind(session);

  let membership: Promise<boolean> | null = null;
  const isMember = (): Promise<boolean> => {
    membership ??= listPeers()
      .then((members) => members.some((member) => member.id === peerId))
      .catch(() => false);
    return membership;
  };
  const requireMember = async (what: string): Promise<void> => {
    if (!(await isMember())) {
      throw new OAuthError(
        "forbidden",
        `peer '${peerId}' is not a member of this session; ${what} is not available to it`,
      );
    }
  };

  const guard = (name: string, what: string): void => {
    const original = session[name];
    if (typeof original !== "function") return;
    session[name] = async (...args: unknown[]) => {
      await requireMember(what);
      return (original as (...a: unknown[]) => Promise<unknown>).apply(session, args);
    };
  };

  for (const name of [
    "peers",
    "messages",
    "summaries",
    "getMessage",
    "getMetadata",
    "setMetadata",
    "delete",
    "clone",
    "removePeers",
  ]) {
    guard(name, "session data");
  }

  // Context can be asked for another peer's representation; that stays
  // pinned to the mapped peer even when the session itself is shared.
  const originalContext = session["context"];
  if (typeof originalContext === "function") {
    session["context"] = async (params: Mutable = {}) => {
      await requireMember("session context");
      for (const key of ["peerTarget", "peerPerspective"]) {
        const value = params[key];
        if (value !== undefined && value !== null && value !== peerId) {
          throw new OAuthError(
            "forbidden",
            `peer '${String(value)}' is not permitted for this identity`,
          );
        }
      }
      return (originalContext as (p: unknown) => Promise<unknown>).call(session, params);
    };
  }
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

// ── per-tool authorization ────────────────────────────────────────────
/**
 * Tools whose result spans the whole workspace: they enumerate or
 * aggregate across every peer and session in it. A mapping that pins a
 * single peer is a per-peer grant, so these stay unavailable to it —
 * listing, searching or aggregating workspace-wide data is not part of
 * the grant. Scope membership is likewise a workspace-wide construct.
 */
const WORKSPACE_WIDE_TOOLS: ReadonlySet<string> = new Set([
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
]);

/**
 * Whether this identity may invoke mutating tools. The coarse `mcp` scope
 * stays full access (backward compatible with tokens issued before the
 * fine-grained scopes existed); the fine-grained `mcp:read` narrows a
 * token to reads unless `mcp:write` is granted alongside it.
 */
export function identityMayWrite(identity: OAuthIdentity): boolean {
  return (
    identity.scopes.includes(WRITE_SCOPE) || !identity.scopes.includes(READ_SCOPE)
  );
}

/**
 * Per-tool allow decision for one OAuth identity. Reads need the base
 * grant; mutations need `mcp:write`; workspace-wide tools need a
 * workspace (not single-peer) mapping. A tool name that is not
 * registered at all never reaches a handler — the server refuses it
 * before this runs, so unknown tools are denied by default.
 */
export function toolAllowed(
  name: string,
  readOnly: boolean,
  identity: OAuthIdentity,
): boolean {
  if (!readOnly && !identityMayWrite(identity)) return false;
  if (identity.peerId && WORKSPACE_WIDE_TOOLS.has(name)) return false;
  return true;
}

/**
 * Wrap the native tool context so every tool call runs inside the token's
 * server-side grant: the workspace comes from the mapping (a self-declared
 * workspace can only pick among permitted ones, never widen), peer
 * operations are pinned when the mapping names a peer, and the tool set
 * itself is filtered per identity (mcp:read vs mcp:write, workspace-wide
 * tools for single-peer mappings).
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
