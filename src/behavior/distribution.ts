// Distribution detector — the existing kind-frequency divergence, now one signal
// among several. Blunt by design: it cannot see order, timing, or volume.
import type { Detector, DetectorSignal, BoundaryEvent, BoundaryKind } from "./types";
import type { Baseline } from "./baseline";

const KINDS: BoundaryKind[] = ["egress", "script", "host-message", "storage"];

export class DistributionDetector implements Detector {
  readonly name = "distribution";
  private events: BoundaryEvent[] = [];
  constructor(private base: Baseline) {}

  observe(e: BoundaryEvent): void {
    this.events.push(e);
  }
  reset(): void {
    this.events = [];
  }

  finalize(): DetectorSignal {
    const counts: Record<BoundaryKind, number> = { egress: 0, script: 0, "host-message": 0, storage: 0 };
    for (const e of this.events) counts[e.kind]++;
    const total = this.events.length || 1;
    let l1 = 0;
    for (const k of KINDS) l1 += Math.abs(counts[k] / total - (this.base.kindFreq[k] || 0));
    const score = 0.5 * l1;
    const flag = score > this.base.distBudget;
    return {
      detector: this.name,
      status: flag ? "FLAG" : "OK",
      score,
      reason: flag
        ? `kind distribution divergence ${score.toFixed(3)} exceeds ${this.base.distBudget}`
        : "kind distribution within budget",
    };
  }
}
