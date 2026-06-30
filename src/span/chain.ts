// Per-session receipt chain helpers. Each receipt is hash-chained to the
// previous via prevHash, so any tampering with an earlier receipt breaks every
// link after it.
import { sha256Hex } from "../crypto";
import { canonicalBytes } from "../canonical";
import type { Receipt } from "./types";

export const GENESIS = "0".repeat(64);

// Chain link target: hash over the full signed receipt.
export function receiptHash(r: Receipt): string {
  return sha256Hex(canonicalBytes(r));
}

// What the Span signs: the receipt with an empty signature field. Both signer
// and verifier compute this identically, so bytes match without field deletion.
export function receiptCore(r: Receipt): Receipt {
  const c = JSON.parse(JSON.stringify(r)) as Receipt;
  c.signature = "";
  return c;
}
