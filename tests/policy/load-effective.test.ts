import { describe, expect, it } from "vitest";

import { parsePolicyEffectiveResolveResponse } from "../../src/policy/load-effective.js";

describe("parsePolicyEffectiveResolveResponse", () => {
  it("parses full effective policy responses with version metadata", () => {
    const parsed = parsePolicyEffectiveResolveResponse({
      effective_policy: { version: 1, name: "tenant-overlay", default_deny: true, tools: {} },
      effective_policy_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      effective_policy_version: "tenant-overlay@aaaaaaaa",
      merge_report: {
        org_policy_id: "acme-agent-spend-v1",
        org_id: "org_acme_corp",
        base_policy_name: "acme-agent-spend-v1",
        overlay_policy_name: "tenant-overlay",
        overrides_applied: [],
        denied_widenings: [],
      },
      org_base_version_seq: 3,
      org_base_content_digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    });

    expect(parsed.effective_policy_version).toBe("tenant-overlay@aaaaaaaa");
    expect(parsed.org_base_version_seq).toBe(3);
    expect(parsed.unchanged).toBeUndefined();
  });

  it("parses unchanged digest poll responses without effective_policy body", () => {
    const parsed = parsePolicyEffectiveResolveResponse({
      unchanged: true,
      effective_policy_digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      effective_policy_version: "tenant-overlay@cccccccc",
      org_base_version_seq: 4,
      org_base_content_digest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    });

    expect(parsed.unchanged).toBe(true);
    expect(parsed.effective_policy).toEqual({});
    expect(parsed.effective_policy_version).toBe("tenant-overlay@cccccccc");
  });
});
