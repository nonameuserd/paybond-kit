import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

/**
 * `server.json` is the MCP registry listing. Its scope catalog is a *published*
 * mirror of `kit/mcp-scopes/catalog.json`, so a scope added or re-levelled in the
 * canonical catalog must show up here too: a registry entry that advertises a
 * stale grant surface teaches hosts to request scopes the gateway will refuse.
 */
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

type CanonicalCatalog = {
  version: number;
  levels: ReadonlyArray<string>;
  scopes: ReadonlyArray<{ id: string; title: string; max_level: string; description: string }>;
  presets: ReadonlyArray<{ id: string; title: string; scopes: ReadonlyArray<{ scope: string; level: string }> }>;
};

type RegistryScopeCatalog = {
  version: number;
  levels: ReadonlyArray<string>;
  scopes: ReadonlyArray<{ id: string; title: string; maxLevel: string; description: string }>;
  presets: ReadonlyArray<{ id: string; title: string; scopes: ReadonlyArray<string> }>;
};

type RegistryPaybondMeta = {
  authorization: {
    type: string;
    grantTypes: ReadonlyArray<string>;
    pkce: string;
    authorizationUrl: string;
    tokenUrl: string;
    revocationUrl: string;
    consentUrl: string;
    sessionManagementUrl: string;
  };
  hostedEndpoint: { url: string; transport: string; credentials: ReadonlyArray<string> };
  scopeCatalog: RegistryScopeCatalog;
};

function loadCanonicalCatalog(): CanonicalCatalog {
  return JSON.parse(readFileSync(join(REPO_ROOT, "kit", "mcp-scopes", "catalog.json"), "utf8")) as CanonicalCatalog;
}

const PUBLISHER_EXTENSION_KEY = "io.modelcontextprotocol.registry/publisher-provided";

/** The registry rejects a publish whose publisher-provided extension exceeds 4KB minified. */
const PUBLISHER_EXTENSION_LIMIT_BYTES = 4096;

function loadPublisherExtension(): { paybond: RegistryPaybondMeta } {
  const server = JSON.parse(readFileSync(join(REPO_ROOT, "server.json"), "utf8")) as {
    _meta: Record<string, { paybond: RegistryPaybondMeta }>;
  };
  const publisher = server._meta[PUBLISHER_EXTENSION_KEY];
  if (!publisher?.paybond) {
    throw new Error("server.json is missing publisher-provided paybond metadata");
  }
  return publisher;
}

function loadRegistryMeta(): RegistryPaybondMeta {
  return loadPublisherExtension().paybond;
}

describe("server.json registry metadata", () => {
  const canonical = loadCanonicalCatalog();
  const meta = loadRegistryMeta();

  // The registry measures the minified extension, so growth here (a new scope,
  // a longer description) fails the publish rather than any local build.
  it("keeps the publisher-provided extension under the registry 4KB limit", () => {
    const bytes = Buffer.byteLength(JSON.stringify(loadPublisherExtension()), "utf8");
    expect(bytes).toBeLessThanOrEqual(PUBLISHER_EXTENSION_LIMIT_BYTES);
  });

  it("documents the MCP OAuth endpoints the gateway actually serves", () => {
    expect(meta.authorization.type).toBe("oauth2");
    expect(meta.authorization.pkce).toBe("S256");
    expect([...meta.authorization.grantTypes]).toEqual(["authorization_code", "refresh_token"]);
    expect(meta.authorization.authorizationUrl).toBe("https://api.paybond.ai/v1/oauth/authorize");
    expect(meta.authorization.tokenUrl).toBe("https://api.paybond.ai/v1/oauth/token");
    expect(meta.authorization.revocationUrl).toBe("https://api.paybond.ai/v1/oauth/revoke");
    expect(meta.authorization.consentUrl).toBe("https://paybond.ai/console/authorize/mcp");
  });

  it("documents the hosted endpoint and every credential kind it accepts", () => {
    expect(meta.hostedEndpoint.url).toBe("https://mcp.paybond.ai/mcp");
    const credentials = meta.hostedEndpoint.credentials.join(" ");
    for (const prefix of ["paybond_rk_", "paybond_sk_", "paybond_oat_"]) {
      expect(credentials).toContain(prefix);
    }
  });

  it("mirrors the canonical scope catalog version, levels, and scopes", () => {
    expect(meta.scopeCatalog.version).toBe(canonical.version);
    expect([...meta.scopeCatalog.levels]).toEqual([...canonical.levels]);
    expect(
      meta.scopeCatalog.scopes.map((scope) => ({
        id: scope.id,
        title: scope.title,
        max_level: scope.maxLevel,
        description: scope.description,
      })),
    ).toEqual([...canonical.scopes]);
  });

  it("mirrors the canonical presets as canonical scope tokens", () => {
    expect(
      meta.scopeCatalog.presets.map((preset) => ({
        id: preset.id,
        title: preset.title,
        scopes: [...preset.scopes],
      })),
    ).toEqual(
      canonical.presets.map((preset) => ({
        id: preset.id,
        title: preset.title,
        scopes: preset.scopes.map((grant) => `${grant.scope}:${grant.level}`),
      })),
    );
  });

  // Settlement moves real money, so it must never ride along in a preset a host
  // can request without the operator choosing it deliberately.
  it("keeps mcp.settlement out of every published preset", () => {
    for (const preset of meta.scopeCatalog.presets) {
      expect(preset.scopes.some((scope) => scope.startsWith("mcp.settlement"))).toBe(false);
    }
  });
});
