"use client";

import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";

export type PipelinePhase = "idle" | "recon" | "exploit" | "lateral";

type KnownEventName =
  | "cycle_started"
  | "recon_complete"
  | "exploit_complete"
  | "demo_seeded"
  | "lateral_complete"
  | "github_issues_created"
  | "cycle_complete"
  | "recon_agent_started"
  | "recon_step_started"
  | "recon_tool_result"
  | "recon_step_complete"
  | "recon_agent_complete"
  | "exploit_agent_started"
  | "exploit_target_scan_started"
  | "exploit_target_scan_complete"
  | "exploit_finding_classified"
  | "exploit_borderline_filter_started"
  | "exploit_borderline_filter_error_kept"
  | "exploit_borderline_confirmed_by_gemini"
  | "exploit_borderline_dropped_by_gemini"
  | "exploit_agent_complete"
  | "lateral_agent_started"
  | "lateral_finding_started"
  | "lateral_round_started"
  | "lateral_tool_call_started"
  | "lateral_tool_call_complete"
  | "lateral_model_finished"
  | "lateral_max_rounds_reached"
  | "lateral_structured_repair_requested"
  | "lateral_structured_output_failed"
  | "lateral_chain_built"
  | "lateral_agent_complete"
  | "mock_recon_generated_assets"
  | "mock_exploit_generated_findings"
  | "mock_lateral_generated_chains";

type EventEnvelope = {
  event?: string;
  engagement_id?: string;
  [key: string]: unknown;
};

type PingEnvelope = {
  ping: string;
};

type ParsedWsMessage = EventEnvelope | PingEnvelope;

type PhaseEvent = {
  id: string;
  timestamp: string;
  summary: string;
};

type PhaseBuckets = {
  recon: PhaseEvent[];
  exploit: PhaseEvent[];
  lateral: PhaseEvent[];
};

export type WebSocketPipelineTrackerProps = {
  ws: WebSocket | null;
  maxEventsPerPhase?: number;
  className?: string;
};

const PHASE_ORDER: PipelinePhase[] = ["recon", "exploit", "lateral"];

const PHASE_LABELS: Record<PipelinePhase, string> = {
  idle: "IDLE",
  recon: "RECONNAISSANCE",
  exploit: "EXPLOITATION",
  lateral: "LATERAL MOVEMENT",
};

function nowIso(): string {
  return new Date().toISOString();
}

function parseWsMessage(raw: string): ParsedWsMessage | null {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed === "object" && parsed !== null) {
      return parsed as ParsedWsMessage;
    }
    return null;
  } catch {
    return null;
  }
}

function isPingMessage(msg: ParsedWsMessage): msg is PingEnvelope {
  return typeof (msg as PingEnvelope).ping === "string";
}

function isEventEnvelope(msg: ParsedWsMessage): msg is EventEnvelope {
  return typeof (msg as EventEnvelope).event === "string";
}

function classifyEventPhase(name: string): PipelinePhase | null {
  if (name === "cycle_complete") return "idle";
  if (name === "cycle_started") return "recon";

  if (
    name.startsWith("recon_") ||
    name === "mock_recon_generated_assets" ||
    name === "recon_complete"
  ) {
    return "recon";
  }
  if (
    name.startsWith("exploit_") ||
    name === "mock_exploit_generated_findings" ||
    name === "exploit_complete" ||
    name === "demo_seeded"
  ) {
    return "exploit";
  }
  if (
    name.startsWith("lateral_") ||
    name === "mock_lateral_generated_chains" ||
    name === "lateral_complete" ||
    name === "github_issues_created"
  ) {
    return "lateral";
  }
  return null;
}

function summarizeEvent(
  name: string,
  payload: Record<string, unknown>,
): string {
  switch (name as KnownEventName) {
    case "cycle_started":
      return "Scan cycle started";
    case "recon_step_started":
      return `Recon step started: ${String(payload.step ?? "unknown")}`;
    case "recon_complete":
      return `Reconnaissance complete (${String(payload.asset_count ?? 0)} assets)`;
    case "exploit_target_scan_started":
      return `Exploit scan started: ${String(payload.target ?? "unknown target")}`;
    case "exploit_target_scan_complete":
      return `Exploit scan complete: ${String(payload.target ?? "unknown target")} (${String(payload.raw_finding_count ?? 0)} findings)`;
    case "exploit_finding_classified":
      return `Finding ${String(payload.decision ?? "classified")}: ${String(payload.title ?? "unknown finding")}`;
    case "exploit_complete":
      return `Exploitation complete (${String(payload.finding_count ?? 0)} findings)`;
    case "demo_seeded":
      return "Demo finding injected";
    case "lateral_round_started":
      return `Lateral movement round ${String(payload.round ?? "?")} started`;
    case "lateral_tool_call_started":
      return `Lateral tool call: ${String(payload.tool ?? "unknown tool")} (start)`;
    case "lateral_tool_call_complete":
      return `Lateral tool call: ${String(payload.tool ?? "unknown tool")} (complete)`;
    case "lateral_chain_built":
      return `Lateral chain built for finding ${String(payload.finding_id ?? "unknown")}`;
    case "lateral_complete":
      return `Lateral movement complete (${String(payload.chain_count ?? 0)} chains)`;
    case "github_issues_created": {
      const urls = payload.issue_urls;
      const count = Array.isArray(urls) ? urls.length : 0;
      return `GitHub issues created: ${count}`;
    }
    case "cycle_complete": {
      if (typeof payload.skipped === "string")
        return `Cycle complete (skipped ${payload.skipped})`;
      return "Cycle complete";
    }
    default:
      return "";
  }
}

function trimPhaseEvents(events: PhaseEvent[], max: number): PhaseEvent[] {
  if (events.length <= max) return events;
  return events.slice(0, max);
}

export default function WebSocketPipelineTracker({
  ws,
  maxEventsPerPhase = 50,
  className = "",
}: WebSocketPipelineTrackerProps) {
  const [phase, setPhase] = useState<PipelinePhase>("idle");
  const [lastNonIdlePhase, setLastNonIdlePhase] =
    useState<Exclude<PipelinePhase, "idle">>("recon");
  const [buckets, setBuckets] = useState<PhaseBuckets>({
    recon: [],
    exploit: [],
    lateral: [],
  });

  useEffect(() => {
    if (!ws) return;

    const onMessage = (evt: MessageEvent<string>) => {
      if (typeof evt.data !== "string") return;
      const msg = parseWsMessage(evt.data);
      if (!msg) return;

      if (isPingMessage(msg)) {
        return;
      }
      if (!isEventEnvelope(msg) || !msg.event) return;

      const eventName = msg.event;
      const nextPhase = classifyEventPhase(eventName);
      const timestamp = nowIso();

      if (nextPhase) {
        setPhase(nextPhase);
        if (nextPhase !== "idle") {
          setLastNonIdlePhase(nextPhase);
        }
      }

      if (!nextPhase || nextPhase === "idle") return;

      const payload = msg as Record<string, unknown>;
      const summary = summarizeEvent(eventName, payload);
      if (!summary) return;
      const phaseEvent: PhaseEvent = {
        id: `${timestamp}-${eventName}-${Math.random().toString(36).slice(2, 8)}`,
        timestamp,
        summary,
      };

      setBuckets((prev) => {
        const updated = { ...prev };
        updated[nextPhase] = trimPhaseEvents(
          [phaseEvent, ...updated[nextPhase]],
          maxEventsPerPhase,
        );
        return updated;
      });
    };

    ws.addEventListener("message", onMessage as EventListener);
    return () => {
      ws.removeEventListener("message", onMessage as EventListener);
    };
  }, [maxEventsPerPhase, ws]);

  const activePhase: Exclude<PipelinePhase, "idle"> =
    phase === "idle" ? lastNonIdlePhase : phase;
  const activeEvents = buckets[activePhase];

  return (
    <section className={className}>
      <header className="pb-3">
        <p className="font-mono text-xs text-primary/70 uppercase tracking-widest">
          ── pipeline activity ──
        </p>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          {PHASE_ORDER.map((p) => {
            const isActive = p === activePhase;
            return (
              <span
                key={p}
                className={[
                  "px-2 py-1 text-[10px] font-bold uppercase tracking-wider border",
                  isActive
                    ? "border-primary/50 bg-primary/20 text-primary"
                    : "border-primary/20 bg-transparent text-primary/50",
                ].join(" ")}
              >
                {PHASE_LABELS[p]}
              </span>
            );
          })}
        </div>
      </header>

      <div>
        <motion.ul layout className="space-y-2">
          {activeEvents.length === 0 ? (
            <li className="text-[11px] italic text-primary/40 font-mono">
              No events yet for {activePhase}
            </li>
          ) : (
            <AnimatePresence initial={false}>
              {activeEvents.map((item) => (
                <motion.li
                  key={item.id}
                  layout
                  initial={{ opacity: 0, y: 8, scale: 0.98 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, y: -8, scale: 0.98 }}
                  transition={{ duration: 0.2, ease: "easeOut" }}
                  className="border border-primary/20 bg-black/30 p-2 rounded"
                >
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-xs text-foreground/80 font-mono">
                      {item.summary}
                    </p>
                    <span className="text-[10px] font-mono text-primary/50">
                      {new Date(item.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                </motion.li>
              ))}
            </AnimatePresence>
          )}
        </motion.ul>
      </div>
    </section>
  );
}
