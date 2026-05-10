import { describe, expect, it } from "vitest";
import { buildSignedCreateIntentBody, intentCreationSignBytesRaw } from "./principal-intent.js";

describe("intentCreationSignBytesRaw", () => {
  it("matches harbor-intent-escrow signing golden", () => {
    const bytes = intentCreationSignBytesRaw({
      tenantId: "tenant-golden",
      intentId: "7f2a9b1e-2f66-4f4f-9c6e-8f4b8e85c401",
      principalDid: "did:principal:1",
      payeeDid: "did:payee:1",
      amountCents: 100,
      currency: "usd",
      deadlineRfc3339: "2030-01-02T15:04:05Z",
      budget: { max: 100, a: 1 },
      evidenceSchema: { type: "object" },
      predicate: { version: 1, root: { op: "true" } },
      predicateRef: "",
      allowedTools: ["Harbor.Evidence_Submit", "harbor.describe"],
    });
    const golden =
      "020d0000000000000074656e616e742d676f6c64656e10000000000000007f2a9b1e2f664f4f9c6e8f4b8e85c4010f000000000000006469643a7072696e636970616c3a310b000000000000006469643a70617965653a31640000000000000003000000000000007573641400000000000000323033302d30312d30325431353a30343a30355afe9931de397b3817d06aeeb9877163cea9964adc4609fd0f1d715542a7f9c65769b254eacefe89c7b9b29305b06ec5983871a03cc20db0b4747905ecdddd7f29c366a1c38aad99370b12e7197e0fe5590e2d20763c9b4550a738313f484757e500000000000000006ba1f5bfb6266e05ed626dd8a1a318e8f9a38272186eb855bf717cede2c5b104";
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
});
