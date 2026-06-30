// Span runtime sessions for the suite demo. The benign run mirrors the sequence
// the battery attested for the well-behaved app, so it sits inside the attested
// baseline. The drift run collapses the kind-mix; the exfil run keeps the exact
// shape and timing but ships a 100 KB payload through an allowed host.
import type { BoundaryEvent } from "./span/types";

const at = (seq: number) => new Date(1_700_000_000_000 + seq * 1000).toISOString();
const hm = (seq: number, bytes: number): BoundaryEvent => ({ seq, kind: "host-message", bytes, ts: at(seq) });
const script = (seq: number): BoundaryEvent => ({ seq, kind: "script", host: "js.stripe.com", directive: "script-src", bytes: 0, ts: at(seq) });
const eg = (seq: number, host: string, bytes: number): BoundaryEvent => ({ seq, kind: "egress", host, directive: "connect-src", bytes, ts: at(seq) });
const store = (seq: number, bytes: number): BoundaryEvent => ({ seq, kind: "storage", capability: "storage:scoped", bytes, ts: at(seq) });

// Mirrors wellBehavedApp under the benign payload: hm, script, fetch, connect,
// send, beacon, storage, hm — exactly the sequence the battery baselines on.
export function benignRun(): BoundaryEvent[] {
  return [
    hm(0, 4),
    script(1),
    eg(2, "api.stripe.com", 14),
    eg(3, "realtime.acme.io", 0),
    eg(4, "realtime.acme.io", 9),
    eg(5, "metrics.acme.io", 2),
    store(6, 6),
    hm(7, 4),
  ];
}

// In-CSP, but the kind-distribution collapses toward host-message.
export function driftRun(): BoundaryEvent[] {
  return [eg(0, "api.stripe.com", 14), hm(1, 4), hm(2, 4), hm(3, 4), hm(4, 4), hm(5, 4), hm(6, 4), hm(7, 4)];
}

// Identical shape and timing to the benign run, but the fetch carries 100 KB.
export function exfilRun(): BoundaryEvent[] {
  const r = benignRun();
  r[2] = eg(2, "api.stripe.com", 100_000);
  return r;
}
