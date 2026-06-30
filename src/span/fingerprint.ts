// Behavioral fingerprinting for drift detection.
//   profileOf      — normalized event-kind distribution of a session
//   divergence     — 0..1 distance between live and attested profiles
//   fingerprintHash— order-sensitive structural signature of the event sequence
import { sha256Hex } from "../crypto";
import type { BehaviorProfile, BoundaryEvent, BoundaryKind } from "./types";

const KINDS: BoundaryKind[] = ["egress", "script", "host-message", "storage"];

export function profileOf(events: BoundaryEvent[]): BehaviorProfile {
  const counts: Record<BoundaryKind, number> = {
    egress: 0,
    script: 0,
    "host-message": 0,
    storage: 0,
  };
  for (const e of events) counts[e.kind]++;
  const total = events.length || 1;
  const kindFreq = {} as Record<BoundaryKind, number>;
  for (const k of KINDS) kindFreq[k] = counts[k] / total;
  return { kindFreq, eventCount: events.length };
}

// 0.5 * L1 distance over normalized frequency vectors, range 0..1.
export function divergence(live: BehaviorProfile, attested: BehaviorProfile): number {
  let l1 = 0;
  for (const k of KINDS) l1 += Math.abs((live.kindFreq[k] || 0) - (attested.kindFreq[k] || 0));
  return 0.5 * l1;
}

export function fingerprintHash(events: BoundaryEvent[]): string {
  const seq = events
    .map((e) => `${e.kind}:${e.host ?? ""}:${e.directive ?? ""}:${e.capability ?? ""}`)
    .join("|");
  return sha256Hex(seq).slice(0, 32);
}
