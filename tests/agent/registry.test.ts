import { describe, expect, it } from "vitest";
import {
  PaybondToolRegistry,
  PaybondToolRegistryValidationError,
  createPaybondToolRegistry,
} from "../../src/agent/index.js";

describe("PaybondToolRegistry", () => {
  it("registers side-effecting tools with spend and evidence preset", () => {
    const registry = createPaybondToolRegistry({
      sideEffecting: {
        "travel.book_hotel": {
          spendCents: (args: { estimatedPriceCents: number }) => args.estimatedPriceCents,
          evidencePreset: "cost_and_completion",
        },
      },
      defaultDeny: true,
    });

    expect(registry.isSideEffecting("travel.book_hotel")).toBe(true);
    expect(registry.resolveOperation("travel.book_hotel")).toBe("travel.book_hotel");
    expect(
      registry.resolveSpendCents("travel.book_hotel", { estimatedPriceCents: 18_700 }),
    ).toBe(18_700);

    const resolution = registry.resolveTool("travel.book_hotel", {
      allowedTools: ["travel.book_hotel"],
    });
    expect(resolution.kind).toBe("side_effecting");
    if (resolution.kind === "side_effecting") {
      expect(resolution.entry.evidencePreset).toBe("cost_and_completion");
    }
  });

  it("passes through read-only tools without Harbor involvement", () => {
    const registry = createPaybondToolRegistry({
      sideEffecting: {
        "travel.book_hotel": {
          spendCents: 100,
          evidencePreset: "cost_and_completion",
        },
      },
      defaultDeny: true,
    });

    const resolution = registry.resolveTool("search.web", {
      allowedTools: ["travel.book_hotel"],
    });
    expect(resolution).toEqual({ kind: "passthrough", toolName: "search.web" });
    expect(registry.isSideEffecting("search.web")).toBe(false);
  });

  it("denies unregistered tools in allowedTools when defaultDeny is true", () => {
    const registry = createPaybondToolRegistry({
      sideEffecting: {
        "travel.book_hotel": {
          spendCents: 100,
          evidencePreset: "cost_and_completion",
        },
      },
      defaultDeny: true,
    });

    const resolution = registry.resolveTool("travel.book_hotel", {
      allowedTools: ["travel.book_hotel", "travel.book_flight"],
    });
    expect(resolution.kind).toBe("side_effecting");

    const denied = registry.resolveTool("travel.book_flight", {
      allowedTools: ["travel.book_hotel", "travel.book_flight"],
    });
    expect(denied).toEqual({
      kind: "denied",
      toolName: "travel.book_flight",
      operation: "travel.book_flight",
      reason: "unregistered_side_effecting",
    });
  });

  it("allows unregistered tools when defaultDeny is false", () => {
    const registry = createPaybondToolRegistry({
      defaultDeny: false,
    });

    const resolution = registry.resolveTool("travel.book_flight", {
      allowedTools: ["travel.book_flight"],
    });
    expect(resolution).toEqual({ kind: "passthrough", toolName: "travel.book_flight" });
  });

  it("supports operation override separate from tool name", () => {
    const registry = createPaybondToolRegistry({
      sideEffecting: {
        bookHotel: {
          operation: "travel.book_hotel",
          spendCents: 500,
          evidencePreset: "cost_and_completion",
        },
      },
    });

    expect(registry.resolveOperation("bookHotel")).toBe("travel.book_hotel");
    expect(registry.sideEffectingOperations()).toEqual(["travel.book_hotel"]);
  });

  it("requires evidencePreset on side-effecting tools", () => {
    expect(() =>
      createPaybondToolRegistry({
        sideEffecting: {
          "travel.book_hotel": {
            spendCents: 100,
          } as { evidencePreset: string },
        },
      }),
    ).toThrow(PaybondToolRegistryValidationError);
  });

  it("rejects unknown evidence presets", () => {
    expect(() =>
      createPaybondToolRegistry({
        sideEffecting: {
          "travel.book_hotel": {
            spendCents: 100,
            evidencePreset: "not_a_real_preset",
          },
        },
      }),
    ).toThrow(/unknown evidencePreset/);
  });

  it("rejects duplicate operations across tools", () => {
    expect(() =>
      createPaybondToolRegistry({
        sideEffecting: {
          bookHotelA: {
            operation: "travel.book_hotel",
            evidencePreset: "cost_and_completion",
          },
          bookHotelB: {
            operation: "travel.book_hotel",
            evidencePreset: "cost_and_completion",
          },
        },
      }),
    ).toThrow(/duplicate side-effecting operation/);
  });

  it("validateForBind fails when defaultDeny and allowedTools are uncovered", () => {
    const registry = new PaybondToolRegistry({
      sideEffecting: {
        "travel.book_hotel": {
          evidencePreset: "cost_and_completion",
        },
      },
      defaultDeny: true,
    });

    expect(() => registry.validateForBind(["travel.book_hotel"])).not.toThrow();
    expect(() =>
      registry.validateForBind(["travel.book_hotel", "travel.book_flight"]),
    ).toThrow(/defaultDeny/);
  });
});
