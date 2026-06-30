// BehavioralMonitor — runs every detector over the same boundary-event stream
// and aggregates. FLAG if any detector flags. Slots into the Span: feed each
// observed event to monitor.observe alongside the receipt write, and on a FLAG at
// finalize the Span revokes with the aggregated reason.
import type { Detector, BoundaryEvent, MonitorVerdict } from "./types";
import type { Baseline } from "./baseline";
import { DistributionDetector } from "./distribution";
import { SequenceDetector } from "./sequence";
import { CapabilityBudgetDetector } from "./budget";

export class BehavioralMonitor {
  constructor(private detectors: Detector[]) {}

  observe(event: BoundaryEvent): void {
    for (const d of this.detectors) d.observe(event);
  }

  finalize(): MonitorVerdict {
    const signals = this.detectors.map((d) => d.finalize());
    const status = signals.some((s) => s.status === "FLAG") ? "FLAG" : "OK";
    return { status, signals };
  }

  reset(): void {
    for (const d of this.detectors) d.reset();
  }
}

export function buildMonitor(base: Baseline): BehavioralMonitor {
  return new BehavioralMonitor([
    new DistributionDetector(base),
    new SequenceDetector(base),
    new CapabilityBudgetDetector(base),
  ]);
}
