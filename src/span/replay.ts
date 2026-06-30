// Time-travel replay. Given a session's receipt chain and signed head, verify
// that the record is intact and reconstruct exactly what crossed the boundary.
// Any tampering — a flipped payload, a forged signature, a reordered link —
// fails verification.
import type { Receipt, SessionHead, BoundaryEvent } from "./types";
import { canonicalBytes } from "../canonical";
import { verifyBytes } from "../crypto";
import { GENESIS, receiptHash, receiptCore } from "./chain";
import { fingerprintHash } from "./fingerprint";

export interface ReplayResult {
  ok: boolean;
  reason?: string;
  timeline?: BoundaryEvent[];
}

export function verifyChain(
  receipts: Receipt[],
  head: SessionHead,
  spanPublicKeyPem: string,
): ReplayResult {
  let prev = GENESIS;
  for (const r of receipts) {
    if (r.prevHash !== prev) {
      return { ok: false, reason: `broken chain link at seq ${r.seq}` };
    }
    if (!verifyBytes(canonicalBytes(receiptCore(r)), r.signature, spanPublicKeyPem)) {
      return { ok: false, reason: `bad receipt signature at seq ${r.seq}` };
    }
    prev = receiptHash(r);
  }
  if (prev !== head.headHash) {
    return { ok: false, reason: "head hash does not match chain tail" };
  }
  if (!verifyBytes(canonicalBytes({ ...head, signature: "" }), head.signature, spanPublicKeyPem)) {
    return { ok: false, reason: "bad session head signature" };
  }
  const timeline = reconstructTimeline(receipts);
  if (fingerprintHash(timeline) !== head.liveFingerprint) {
    return { ok: false, reason: "fingerprint does not match reconstructed timeline" };
  }
  return { ok: true, timeline };
}

export function reconstructTimeline(receipts: Receipt[]): BoundaryEvent[] {
  return receipts
    .filter((r) => r.kind === "event" && r.event)
    .map((r) => r.event!);
}
