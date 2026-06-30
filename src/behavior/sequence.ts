// Sequence + timing detector. Catches sessions that keep the kind-distribution
// intact but reorder events into a pathological shape, or fire them in an
// abnormal time pattern (bursts). Three sub-signals: unexpected-transition
// fraction, max consecutive run, and median inter-event interval.
import type { Detector, DetectorSignal, BoundaryEvent } from "./types";
import type { Baseline } from "./baseline";

function median(xs: number[]): number {
  if (xs.length === 0) return 0;
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

export class SequenceDetector implements Detector {
  readonly name = "sequence";
  private events: BoundaryEvent[] = [];
  constructor(private base: Baseline) {}

  observe(e: BoundaryEvent): void {
    this.events.push(e);
  }
  reset(): void {
    this.events = [];
  }

  finalize(): DetectorSignal {
    const ev = this.events;
    const n = ev.length;

    let unexpected = 0;
    let transitions = 0;
    let maxRun = n ? 1 : 0;
    let run = 1;
    for (let i = 1; i < n; i++) {
      transitions++;
      if (!this.base.bigrams.has(ev[i - 1].kind + ">" + ev[i].kind)) unexpected++;
      if (ev[i].kind === ev[i - 1].kind) {
        run++;
        if (run > maxRun) maxRun = run;
      } else {
        run = 1;
      }
    }
    const unexpectedFrac = transitions ? unexpected / transitions : 0;

    const intervals: number[] = [];
    for (let i = 1; i < n; i++) intervals.push(Date.parse(ev[i].ts) - Date.parse(ev[i - 1].ts));
    const med = median(intervals);

    const reasons: string[] = [];
    if (unexpectedFrac > this.base.unexpectedFracBudget) {
      reasons.push(`unexpected-transition fraction ${unexpectedFrac.toFixed(2)} exceeds ${this.base.unexpectedFracBudget}`);
    }
    if (maxRun > this.base.maxRun) {
      reasons.push(`max consecutive run ${maxRun} exceeds ${this.base.maxRun}`);
    }
    const burst = intervals.length > 0 && med < this.base.minIntervalMs;
    if (burst) {
      reasons.push(`median interval ${med}ms below ${this.base.minIntervalMs}ms floor (burst)`);
    }

    const flag = reasons.length > 0;
    const score = Math.max(
      unexpectedFrac > this.base.unexpectedFracBudget ? unexpectedFrac : 0,
      maxRun > this.base.maxRun ? 1 : 0,
      burst ? 1 : 0,
    );
    return {
      detector: this.name,
      status: flag ? "FLAG" : "OK",
      score,
      reason: reasons.join("; ") || "sequence and timing nominal",
    };
  }
}
