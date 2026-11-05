import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ToolContext } from "./types.js";
import { register as registerWorkspaceTools } from "./tools/workspace.js";
import { register as registerPeerTools } from "./tools/peers.js";
import { register as registerSessionTools } from "./tools/sessions.js";
import { register as registerScopeTools } from "./tools/scopes.js";
import { register as registerConclusionTools } from "./tools/conclusions.js";
import { register as registerSystemTools } from "./tools/system.js";
import instructions from "../instructions.md";
import pkg from "../package.json";

/**
 * Per-caller tool visibility policy. A denied tool is registered disabled:
 * it disappears from `tools/list` (tool-level filtering) and a direct
 * `tools/call` is refused by the SDK instead of executing (server-side
 * validation). Without a policy every tool registers as before.
 */
export interface ToolPolicy {
  allows: (name: string, tool: { readOnly: boolean }) => boolean;
}

export function createServer(ctx: ToolContext, policy?: ToolPolicy): McpServer {
  const server = new McpServer(
    {
      name: "Honcho MCP Server",
      version: pkg.version,
    },
    { instructions },
  );

  if (policy) {
    // The read/write class of each tool comes from its own annotations,
    // so the policy cannot drift from what the tool declares.
    const register = server.registerTool.bind(server) as (
      name: string,
      config: { annotations?: { readOnlyHint?: boolean } },
      cb: unknown,
    ) => { disable(): void };
    server.registerTool = ((
      name: string,
      config: { annotations?: { readOnlyHint?: boolean } },
      cb: never,
    ) => {
      const registered = register(name, config, cb);
      if (!policy.allows(name, { readOnly: config?.annotations?.readOnlyHint === true })) {
        registered.disable();
      }
      return registered;
    }) as typeof server.registerTool;
  }

  registerWorkspaceTools(server, ctx);
  registerPeerTools(server, ctx);
  registerSessionTools(server, ctx);
  registerScopeTools(server, ctx);
  registerConclusionTools(server, ctx);
  registerSystemTools(server, ctx);

  return server;
}
