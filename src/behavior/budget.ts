// Capability/host budget detector. Enforces per-key count and byte ceilings, so
// an app that stays in-envelope and on-distribution but hammers one endpoint or
// exfiltrates volume through an allowed host is still caught — the mimicry case
// that distribution and order both miss.
import type { Detector, DetectorSignal, BoundaryEvent } from "./types";
import { keyOf, type Baseline } from "./baseline";

export class CapabilityBudgetDetector implements Detector {
  readonly name = "budget";
  private agg = new Map<string, { count: number; bytes: number }>();
  constructor(private base: Baseline) {}

  observe(e: BoundaryEvent): void {
    const k = keyOf(e);
    const a = this.agg.get(k) ?? { count: 0, bytes: 0 };
    a.count++;
    a.bytes += e.bytes;
    this.agg.set(k, a);
  }
  reset(): void {
    this.agg.clear();
  }

  finalize(): DetectorSignal {
    const reasons: string[] = [];
    let worst = 0;
    for (const [k, a] of this.agg) {
      const b = this.base.budgets[k];
      if (!b) continue; // unknown keys are the envelope's job, not the budget's
      if (a.count > b.maxCount) {
        reasons.push(`${k}: ${a.count} events exceed budget ${b.maxCount}`);
        worst = Math.max(worst, Math.min(1, a.count / b.maxCount - 1));
      }
      if (a.bytes > b.maxBytes) {
        reasons.push(`${k}: ${a.bytes} bytes exceed budget ${b.maxBytes}`);
        worst = Math.max(worst, Math.min(1, a.bytes / b.maxBytes - 1));
      }
    }
    const flag = reasons.length > 0;
    return {
      detector: this.name,
      status: flag ? "FLAG" : "OK",
      score: flag ? Math.max(0.5, worst) : 0,
      reason: reasons.join("; ") || "all capability budgets within limits",
    };
  }
}
