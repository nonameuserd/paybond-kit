import { describe, expect, it } from "vitest";
import {
  buildSignedCreateIntentBody,
  intentCreationSignBytesRaw,
  intentCreationSignBytesWithPolicyBinding,
} from "../src/principal-intent.js";

const GOLDEN_PAYEE_PUBKEY = new Uint8Array(32).fill(0x42);

describe("intentCreationSignBytesRaw", () => {
  it("matches harbor-intent-escrow signing v6 golden", () => {
    const bytes = intentCreationSignBytesRaw({
      tenantId: "tenant-golden",
      intentId: "7f2a9b1e-2f66-4f4f-9c6e-8f4b8e85c401",
      principalDid: "did:principal:1",
      payeeDid: "did:payee:1",
      payeePubkeyBytes: GOLDEN_PAYEE_PUBKEY,
      amountCents: 100,
      currency: "usd",
      deadlineRfc3339: "2030-01-02T15:04:05Z",
      budget: { max: 100, a: 1 },
      evidenceSchema: { type: "object" },
      predicate: { version: 1, root: { op: "true" } },
      predicateRef: "",
      allowedTools: ["Harbor.Evidence_Submit", "harbor.describe"],
      settlementRail: "stripe_connect",
    });
    const golden =
      "060d74656e616e742d676f6c64656e107f2a9b1e2f664f4f9c6e8f4b8e85c4010f6469643a7072696e636970616c3a310b6469643a70617965653a31c80375736414323033302d30312d30325431353a30343a30355afe9931de397b3817d06aeeb9877163cea9964adc4609fd0f1d715542a7f9c65769b254eacefe89c7b9b29305b06ec5983871a03cc20db0b4747905ecdddd7f29c366a1c38aad99370b12e7197e0fe5590e2d20763c9b4550a738313f484757e5006ba1f5bfb6266e05ed626dd8a1a318e8f9a38272186eb855bf717cede2c5b1040e7374726970655f636f6e6e6563744242424242424242424242424242424242424242424242424242424242424242";
    const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
    expect(hex).toBe(golden);
  });

  it("matches harbor-intent-escrow completion contract sign v1 golden", () => {
    const bytes = intentCreationSignBytesRaw({
      tenantId: "tenant-golden",
      intentId: "7f2a9b1e-2f66-4f4f-9c6e-8f4b8e85c401",
      principalDid: "did:principal:1",
      payeeDid: "did:payee:1",
      payeePubkeyBytes: GOLDEN_PAYEE_PUBKEY,
      amountCents: 100,
      currency: "usd",
      deadlineRfc3339: "2030-01-02T15:04:05Z",
      budget: { max: 100, a: 1 },
      evidenceSchema: { type: "object" },
      predicate: { version: 1, root: { op: "true" } },
      predicateRef: "",
      allowedTools: ["Harbor.Evidence_Submit", "harbor.describe"],
      settlementRail: "stripe_connect",
      completionContract: {
        completionPresetId: "stripe_charge",
        vendorContractProvider: "stripe",
        vendorApiVersion: "2024-10-28.acacia",
        vendorSchemaDigestHex: "ed987475f2756ad37dd04e6a9fe6ab6e0ca77fa974d9e142306dcb665c481dd0",
        canonicalSchemaDigestHex: "95a6b806adf78cab5fbb4f7bb871d1114268620c0d12cf61cfa8405558ea2577",
      },
    });
    const base =
      "060d74656e616e742d676f6c64656e107f2a9b1e2f664f4f9c6e8f4b8e85c4010f6469643a7072696e636970616c3a310b6469643a70617965653a31c80375736414323033302d30312d30325431353a30343a30355afe9931de397b3817d06aeeb9877163cea9964adc4609fd0f1d715542a7f9c65769b254eacefe89c7b9b29305b06ec5983871a03cc20db0b4747905ecdddd7f29c366a1c38aad99370b12e7197e0fe5590e2d20763c9b4550a738313f484757e5006ba1f5bfb6266e05ed626dd8a1a318e8f9a38272186eb855bf717cede2c5b1040e7374726970655f636f6e6e6563744242424242424242424242424242424242424242424242424242424242424242";
    const tail =
      "020d7374726970655f6368617267650673747269706511323032342d31302d32382e616361636961ed987475f2756ad37dd04e6a9fe6ab6e0ca77fa974d9e142306dcb665c481dd095a6b806adf78cab5fbb4f7bb871d1114268620c0d12cf61cfa8405558ea2577";
    const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
    expect(hex).toBe(base + tail);
  });
});

describe("intentCreationSignBytesWithPolicyBinding", () => {
  it("matches harbor-intent-escrow signing v7 golden", () => {
    const digestHex = "ab".repeat(32);
    const bytes = intentCreationSignBytesWithPolicyBinding({
      tenantId: "tenant-golden",
      intentId: "7f2a9b1e-2f66-4f4f-9c6e-8f4b8e85c401",
      principalDid: "did:principal:1",
      payeeDid: "did:payee:1",
      payeePubkeyBytes: GOLDEN_PAYEE_PUBKEY,
      amountCents: 100,
      currency: "usd",
      deadlineRfc3339: "2030-01-02T15:04:05Z",
      budget: { max: 100, a: 1 },
      evidenceSchema: { type: "object" },
      materializedPredicate: { version: 1, root: { op: "true" } },
      predicateRef: "",
      allowedTools: ["Harbor.Evidence_Submit", "harbor.describe"],
      settlementRail: "stripe_connect",
      policyBinding: { templateId: "completion_v1", versionSeq: 3 },
      policyContentDigestHex: digestHex,
    });
    const golden =
      "070d74656e616e742d676f6c64656e107f2a9b1e2f664f4f9c6e8f4b8e85c4010f6469643a7072696e636970616c3a310b6469643a70617965653a31c80375736414323033302d30312d30325431353a30343a30355afe9931de397b3817d06aeeb9877163cea9964adc4609fd0f1d715542a7f9c65769b254eacefe89c7b9b29305b06ec5983871a03cc20db0b4747905ecdddd7f29c366a1c38aad99370b12e7197e0fe5590e2d20763c9b4550a738313f484757e5006ba1f5bfb6266e05ed626dd8a1a318e8f9a38272186eb855bf717cede2c5b1040e7374726970655f636f6e6e6563740d636f6d706c6574696f6e5f763103abababababababababababababababababababababababababababababababab4242424242424242424242424242424242424242424242424242424242424242";
    const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
    expect(hex).toBe(golden);
  });
});

describe("buildSignedCreateIntentBody", () => {
  it("rejects unknown settlement rails", () => {
    expect(() =>
      buildSignedCreateIntentBody({
        tenantId: "tenant-golden",
        intentId: "7f2a9b1e-2f66-4f4f-9c6e-8f4b8e85c401",
        principalDid: "did:principal:1",
        principalSigningSeed: new Uint8Array(32),
        payeeDid: "did:payee:1",
        payeeSigningSeed: new Uint8Array(32),
        budget: { max: 100 },
        predicate: { version: 1, root: { op: "true" } },
        currency: "usd",
        amountCents: 100,
        evidenceSchema: { type: "object" },
        deadlineRfc3339: "2030-01-02T15:04:05Z",
        allowedTools: ["payments.capture"],
        settlementRail: "bogus" as never,
      }),
    ).toThrow(/settlementRail must be one of/);
  });

  it("rejects non-USD currency for stripe_mpp", () => {
    expect(() =>
      buildSignedCreateIntentBody({
        tenantId: "tenant-mpp",
        intentId: "7f2a9b1e-2f66-4f4f-9c6e-8f4b8e85c401",
        principalDid: "did:principal:1",
        principalSigningSeed: new Uint8Array(32),
        payeeDid: "did:payee:1",
        payeeSigningSeed: new Uint8Array(32),
        budget: { max: 100 },
        predicate: { version: 1, root: { op: "true" } },
        currency: "eur",
        amountCents: 100,
        evidenceSchema: { type: "object" },
        deadlineRfc3339: "2030-01-02T15:04:05Z",
        allowedTools: ["payments.capture"],
        settlementRail: "stripe_mpp",
      }),
    ).toThrow(/currency must be usd when settlementRail is stripe_mpp/);
  });

  it("accepts stripe_mpp settlement rail", () => {
    const body = buildSignedCreateIntentBody({
      intentId: "7f2a9b1e-2f66-4f4f-9c6e-8f4b8e85c401",
      principalDid: "did:principal:1",
      principalSigningSeed: new Uint8Array(32),
      payeeDid: "did:payee:1",
      payeeSigningSeed: new Uint8Array(32),
      budget: { max: 100 },
      predicate: { version: 1, root: { op: "true" } },
      currency: "usd",
      amountCents: 100,
      evidenceSchema: { type: "object" },
      deadlineRfc3339: "2030-01-02T15:04:05Z",
      allowedTools: ["payments.capture"],
      settlementRail: "stripe_mpp",
    });
    expect(body.settlement_rail).toBe("stripe_mpp");
  });

  it("accepts adyen_manual_capture settlement rail", () => {
    const body = buildSignedCreateIntentBody({
      intentId: "7f2a9b1e-2f66-4f4f-9c6e-8f4b8e85c401",
      principalDid: "did:principal:1",
      principalSigningSeed: new Uint8Array(32),
      payeeDid: "did:payee:1",
      payeeSigningSeed: new Uint8Array(32),
      budget: { max: 100 },
      predicate: { version: 1, root: { op: "true" } },
      currency: "usd",
      amountCents: 100,
      evidenceSchema: { type: "object" },
      deadlineRfc3339: "2030-01-02T15:04:05Z",
      allowedTools: ["payments.capture"],
      settlementRail: "adyen_manual_capture",
    });
    expect(body.settlement_rail).toBe("adyen_manual_capture");
  });
});
