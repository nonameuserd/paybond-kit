import { describe, expect, it, vi } from "vitest";
import {
  HarborClient,
  paybondRuntimeToolCallAdapter,
  type PaybondSpendGuardInit,
  type VerifyCapabilityResult,
} from "../../src/index.js";

function makeSource(
  verifyResult: VerifyCapabilityResult,
  completeSpendDecision = vi.fn(async () => {}),
): PaybondSpendGuardInit {
  const harbor = new HarborClient("https://harbor.test", "tenant-a");
  vi.spyOn(harbor, "verifyCapability").mockResolvedValue(verifyResult);
  harbor.completeSpendDecision = completeSpendDecision;
  return {
    harbor,
    intentId: verifyResult.intentId,
    capabilityToken: "cap-token",
  };
}

describe("paybondRuntimeToolCallAdapter", () => {
  it("completes spend as consumed after successful execute", async () => {
    const intentId = "550e8400-e29b-41d4-a716-446655440000";
    const completeSpendDecision = vi.fn(async () => {});
    const source = makeSource(
      {
        allow: true,
        auditId: "550e8400-e29b-41d4-a716-446655440001",
        tenant: "tenant-a",
        intentId,
        decisionId: "decision-1",
      },
      completeSpendDecision,
    );
    const execute = vi.fn(async () => ({ status: "ok" }));
    const run = paybondRuntimeToolCallAdapter({
      source,
      operation: "travel.book_hotel",
      execute,
    });

    await expect(run({})).resolves.toEqual({ status: "ok" });
    expect(execute).toHaveBeenCalledOnce();
    expect(completeSpendDecision).toHaveBeenCalledWith({
      decisionId: "decision-1",
      outcome: "consumed",
    });
  });

  it("releases spend when execute fails", async () => {
    const intentId = "550e8400-e29b-41d4-a716-446655440000";
    const completeSpendDecision = vi.fn(async () => {});
    const source = makeSource(
      {
        allow: true,
        auditId: "550e8400-e29b-41d4-a716-446655440001",
        tenant: "tenant-a",
        intentId,
        decisionId: "decision-1",
      },
      completeSpendDecision,
    );
    const execute = vi.fn(async () => {
      throw new Error("vendor down");
    });
    const run = paybondRuntimeToolCallAdapter({
      source,
      operation: "travel.book_hotel",
      execute,
    });

    await expect(run({})).rejects.toThrow("vendor down");
    expect(completeSpendDecision).toHaveBeenCalledWith({
      decisionId: "decision-1",
      outcome: "released",
    });
    expect(completeSpendDecision).not.toHaveBeenCalledWith({
      decisionId: "decision-1",
      outcome: "consumed",
    });
  });

  it("does not complete spend when authorization is denied", async () => {
    const intentId = "550e8400-e29b-41d4-a716-446655440000";
    const completeSpendDecision = vi.fn(async () => {});
    const source = makeSource(
      {
        allow: false,
        auditId: "550e8400-e29b-41d4-a716-446655440001",
        tenant: "tenant-a",
        intentId,
        code: "denied",
        message: "blocked",
      },
      completeSpendDecision,
    );
    const execute = vi.fn(async () => ({ status: "ok" }));
    const run = paybondRuntimeToolCallAdapter({
      source,
      operation: "travel.book_hotel",
      execute,
      onDeny: async () => ({ status: "blocked" }),
    });

    await expect(run({})).resolves.toEqual({ status: "blocked" });
    expect(execute).not.toHaveBeenCalled();
    expect(completeSpendDecision).not.toHaveBeenCalled();
  });
});
