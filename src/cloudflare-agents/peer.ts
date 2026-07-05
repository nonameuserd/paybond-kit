import { createRequire } from "node:module";

type CloudflareAgentsModule = typeof import("agents");

let cachedAgents: CloudflareAgentsModule | undefined;

/**
 * Lazily resolve the optional `agents` peer dependency (Cloudflare Agents SDK).
 *
 * Importing `@paybond/kit/cloudflare-agents` must not require the SDK installed —
 * the peer is only needed when adapter functions or the sandbox demo actually run.
 */
export function loadCloudflareAgentsSdk(): CloudflareAgentsModule {
  if (cachedAgents === undefined) {
    try {
      const require = createRequire(import.meta.url);
      cachedAgents = require("agents") as CloudflareAgentsModule;
    } catch (err) {
      throw new Error(
        'The Cloudflare Agents integration requires the optional peer dependency "agents"; install it with: npm install agents',
        { cause: err },
      );
    }
  }
  return cachedAgents;
}
