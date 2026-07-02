import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { parsePaybondPolicyDocument } from "../../src/policy/schema.js";
import { parsePolicyDocumentText } from "../../src/policy/parse-text.js";
import {
  parsePolicyExtendsRef,
  scaffoldOrgBasePolicy,
  scaffoldTenantOverlayPolicy,
} from "../../src/policy/init.js";
import { PolicyValidator } from "../../src/policy/validate.js";

describe("policy inheritance scaffolds", () => {
  it("parsePolicyExtendsRef splits org_id and org_policy_id", () => {
    expect(parsePolicyExtendsRef("org_acme_corp/acme-agent-spend-v1")).toEqual({
      orgId: "org_acme_corp",
      orgPolicyId: "acme-agent-spend-v1",
    });
  });

  it("scaffoldOrgBasePolicy writes a valid v2 org base", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-init-org-"));
    const out = join(cwd, "org-base.yaml");
    const result = await scaffoldOrgBasePolicy({
      out,
      policyId: "acme-agent-spend-v1",
      operation: "travel.book_hotel",
      evidencePreset: "cost_and_completion",
      maxSpendCents: 20000,
    });
    expect(result.policy_id).toBe("acme-agent-spend-v1");
    const text = await readFile(out, "utf8");
    expect(text).toContain("version: 2");
    expect(text).toContain("max_spend_cents: 20000");
    const report = await PolicyValidator.validate(out);
    expect(report.valid).toBe(true);
  });

  it("scaffoldTenantOverlayPolicy writes a valid v2 overlay", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-extend-"));
    const out = join(cwd, "paybond.policy.yaml");
    const result = await scaffoldTenantOverlayPolicy({
      out,
      extendsRef: "org_acme_corp/acme-agent-spend-v1",
      operation: "acme.internal.approve_po",
      evidencePreset: "cost_and_completion",
    });
    expect(result.org_id).toBe("org_acme_corp");
    expect(result.org_policy_id).toBe("acme-agent-spend-v1");
    expect(result.name).toBe("acme-agent-spend-v1-overlay-v1");
    const text = await readFile(out, "utf8");
    expect(text).toContain("extends:");
    expect(text).toContain("acme.internal.approve_po");
    const doc = parsePaybondPolicyDocument(parsePolicyDocumentText(text, out));
    expect(doc.version).toBe(2);
  });
});
