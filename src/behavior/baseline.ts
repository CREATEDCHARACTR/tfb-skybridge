// The attested behavioral baseline, derived from a clean reference session (in
// production, from the Proof Bay battery's observed runs). Detectors are
// configured from it. Budgets get a margin so legitimate variation passes.
import type { BoundaryEvent, BoundaryKind } from "./types";

const KINDS: BoundaryKind[] = ["egress", "script", "host-message", "storage"];

export interface Baseline {
  kindFreq: Record<BoundaryKind, number>;
  distBudget: number;
  bigrams: Set<string>;          // expected kind->kind transitions, "egress>script"
  unexpectedFracBudget: number;
  maxRun: number;                // max allowed consecutive same-kind run
  minIntervalMs: number;         // floor on median inter-event interval (burst guard)
  budgets: Record<string, { maxCount: number; maxBytes: number }>;
}

// The budget/identity key for an event: host for network, capability for
// storage, else the kind.
export function keyOf(e: BoundaryEvent): string {
  return e.host ?? e.capability ?? e.kind;
}

function median(xs: number[]): number {
  if (xs.length === 0) return 0;
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

export interface BaselineOptions {
  distBudget?: number;
  unexpectedFracBudget?: number;
  runSlack?: number;       // added to observed max run
  intervalFactor?: number; // floor = median * factor
  countMargin?: number;    // budget count = ceil(observed * margin) + 1
  byteMargin?: number;     // budget bytes = observed * margin + 1024
}

export function deriveBaseline(ref: BoundaryEvent[], opts: BaselineOptions = {}): Baseline {
  const {
    distBudget = 0.25,
    unexpectedFracBudget = 0.2,
    runSlack = 1,
    intervalFactor = 0.5,
    countMargin = 3,
    byteMargin = 3,
  } = opts;

  // distribution
  const counts: Record<BoundaryKind, number> = { egress: 0, script: 0, "host-message": 0, storage: 0 };
  for (const e of ref) counts[e.kind]++;
  const total = ref.length || 1;
  const kindFreq = {} as Record<BoundaryKind, number>;
  for (const k of KINDS) kindFreq[k] = counts[k] / total;

  // transitions + run length
  const bigrams = new Set<string>();
  let maxRun = ref.length ? 1 : 0;
  let run = 1;
  for (let i = 1; i < ref.length; i++) {
    bigrams.add(ref[i - 1].kind + ">" + ref[i].kind);
    if (ref[i].kind === ref[i - 1].kind) {
      run++;
      if (run > maxRun) maxRun = run;
    } else {
      run = 1;
    }
  }

  // timing
  const intervals: number[] = [];
  for (let i = 1; i < ref.length; i++) {
    intervals.push(Date.parse(ref[i].ts) - Date.parse(ref[i - 1].ts));
  }
  const minIntervalMs = Math.floor(median(intervals) * intervalFactor);

  // per-key budgets
  const agg = new Map<string, { count: number; bytes: number }>();
  for (const e of ref) {
    const k = keyOf(e);
    const a = agg.get(k) ?? { count: 0, bytes: 0 };
    a.count++;
    a.bytes += e.bytes;
    agg.set(k, a);
  }
  const budgets: Record<string, { maxCount: number; maxBytes: number }> = {};
  for (const [k, a] of agg) {
    budgets[k] = {
      maxCount: Math.ceil(a.count * countMargin) + 1,
      maxBytes: a.bytes * byteMargin + 1024,
    };
  }

  return {
    kindFreq,
    distBudget,
    bigrams,
    unexpectedFracBudget,
    maxRun: maxRun + runSlack,
    minIntervalMs,
    budgets,
  };
}
