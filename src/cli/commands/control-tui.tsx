import React, { useState } from "react";
import { Box, Text, useApp, useInput } from "ink";

import { shouldUseColor } from "../color.js";
import type { GlobalOptions } from "../types.js";
import {
  CONTROL_PANELS,
  type ControlPanel,
  type ControlPlaneSnapshot,
} from "./control-snapshot.js";

export type ControlTuiProps = {
  initialSnapshot: ControlPlaneSnapshot;
  globals: GlobalOptions;
  refresh: () => Promise<ControlPlaneSnapshot>;
};

function truncate(value: string, max: number): string {
  if (value.length <= max) {
    return value;
  }
  return `${value.slice(0, Math.max(0, max - 1))}…`;
}

function panelLabel(panel: ControlPanel, active: ControlPanel): string {
  const label = panel.toUpperCase();
  return panel === active ? `[${label}]` : ` ${label} `;
}

function renderRows(panel: ControlPanel, snapshot: ControlPlaneSnapshot): string[] {
  switch (panel) {
    case "intents": {
      const rows = snapshot.panels.intents;
      if (rows.length === 0) {
        return ["(no intents)"];
      }
      return rows.map(
        (row) =>
          `${truncate(String(row.intent_id ?? ""), 36)}  ${String(row.status ?? "-")}  ${String(row.amount_cents ?? "-")}`,
      );
    }
    case "receipts": {
      const rows = snapshot.panels.receipts;
      if (rows.length === 0) {
        return ["(no receipts)"];
      }
      return rows.map(
        (row) =>
          `${truncate(String(row.receipt_id ?? ""), 28)}  ${String(row.scope ?? "-")}  intent=${truncate(String(row.intent_id ?? ""), 36)}`,
      );
    }
    case "policy": {
      const policy = snapshot.panels.policy;
      const lines = [
        `path: ${String(policy.path)}`,
        `present: ${String(policy.present)}`,
        `source: ${String(policy.source ?? "local_file")}`,
      ];
      if (policy.name) {
        lines.push(`name: ${String(policy.name)}`);
      }
      if (policy.operation) {
        lines.push(`operation: ${String(policy.operation)}`);
      }
      return lines;
    }
    case "spend": {
      const spend = snapshot.panels.spend;
      const source = String(spend.source ?? "unavailable");
      const lines = [
        `source: ${source}`,
        `latest_remaining_cents: ${String(spend.latest_remaining_cents ?? "-")}`,
      ];
      if (source === "unavailable") {
        lines.push(`next: ${String(spend.next ?? "paybond login")}`);
        return lines;
      }
      const decisions = Array.isArray(spend.decisions) ? spend.decisions : [];
      if (decisions.length === 0) {
        lines.push("(no recent spend decisions)");
      } else {
        for (const row of decisions.slice(0, 12)) {
          if (!row || typeof row !== "object") {
            continue;
          }
          const item = row as Record<string, unknown>;
          lines.push(
            `${String(item.created_at ?? "-")}  ${String(item.outcome ?? "-")}  ${String(item.operation ?? "-")}  ${String(item.amount_cents ?? "-")}¢  rem=${String(item.remaining_cents ?? "-")}`,
          );
        }
      }
      return lines;
    }
    case "denials": {
      const rows = snapshot.panels.denials;
      if (rows.length === 0) {
        return ["(no recent denials from gateway spend decisions)"];
      }
      return rows.map(
        (row) =>
          `${String(row.created_at ?? "-")}  ${String(row.operation ?? "-")}  ${String(row.outcome ?? "-")}  ${String(Array.isArray(row.reason_codes) ? row.reason_codes.join(",") : "-")}`,
      );
    }
    default:
      return [];
  }
}

/**
 * Interactive Ink control-plane TUI. Only mount when stdin/stdout are TTYs.
 */
export function ControlTuiApp(props: ControlTuiProps): React.ReactElement {
  const { exit } = useApp();
  const [active, setActive] = useState<ControlPanel>("intents");
  const [snapshot, setSnapshot] = useState(props.initialSnapshot);
  const [busy, setBusy] = useState(false);
  const useColor = shouldUseColor(props.globals);

  useInput((input, key) => {
    if (busy) {
      return;
    }
    if (input === "q" || (key.ctrl && input === "c")) {
      exit();
      return;
    }
    if (input === "r") {
      setBusy(true);
      void props
        .refresh()
        .then((next) => {
          setSnapshot(next);
        })
        .finally(() => {
          setBusy(false);
        });
      return;
    }
    if (key.leftArrow || input === "h") {
      const idx = CONTROL_PANELS.indexOf(active);
      setActive(CONTROL_PANELS[(idx - 1 + CONTROL_PANELS.length) % CONTROL_PANELS.length]!);
      return;
    }
    if (key.rightArrow || key.tab || input === "l") {
      const idx = CONTROL_PANELS.indexOf(active);
      setActive(CONTROL_PANELS[(idx + 1) % CONTROL_PANELS.length]!);
      return;
    }
    const digitMap: Record<string, ControlPanel> = {
      "1": "intents",
      "2": "receipts",
      "3": "policy",
      "4": "spend",
      "5": "denials",
    };
    if (digitMap[input]) {
      setActive(digitMap[input]!);
    }
  });

  const rows = renderRows(active, snapshot);
  const tabLine = CONTROL_PANELS.map((panel) => panelLabel(panel, active)).join(" ");

  return (
    <Box flexDirection="column">
      <Text color={useColor ? "cyan" : undefined} bold={useColor}>
        Paybond control · {active}
      </Text>
      <Text dimColor={useColor}>
        tenant={snapshot.tenant_id ?? "unknown"} env={snapshot.environment ?? "unknown"}
      </Text>
      <Text dimColor={useColor}>gateway={snapshot.gateway}</Text>
      <Text>{tabLine}</Text>
      <Text> </Text>
      {rows.map((line, index) => (
        <Text key={`${active}-${index}`}>{line}</Text>
      ))}
      {snapshot.limitations.length > 0 ? (
        <Box flexDirection="column" marginTop={1}>
          <Text color={useColor ? "yellow" : undefined}>notes:</Text>
          {snapshot.limitations.slice(0, 6).map((note, index) => (
            <Text key={`note-${index}`}>- {note}</Text>
          ))}
        </Box>
      ) : null}
      <Text> </Text>
      <Text dimColor={useColor}>
        ←/→ tabs · 1-5 panel · r refresh{busy ? "…" : ""} · q quit
      </Text>
    </Box>
  );
}
