// RFC 6962-style Merkle tree: the structure a Certificate-Transparency-style log
// needs. Beyond inclusion ("entry e is in the tree"), it produces *consistency*
// proofs ("the tree of size m is an unmodified prefix of the tree of size n") —
// the property that makes the log auditable: a monitor can prove the operator
// only ever appended and never rewrote history.
//
// Hashes are hex strings. leafHash domain-separates from nodeHash (0x00 vs 0x01)
// so no internal node can be forged to collide with a leaf.
import { sha256 } from "./crypto";

const LEAF = Buffer.from([0x00]);
const NODE = Buffer.from([0x01]);

export function leafHash(data: Buffer): string {
  return sha256(Buffer.concat([LEAF, data])).toString("hex");
}

export function nodeHash(left: string, right: string): string {
  return sha256(Buffer.concat([NODE, Buffer.from(left, "hex"), Buffer.from(right, "hex")])).toString("hex");
}

// Largest power of two strictly less than count (count >= 2).
export function pow2lt(count: number): number {
  let k = 1;
  while (k * 2 < count) k *= 2;
  return k;
}

// Merkle Tree Hash over leaves[lo, hi). RFC splits at the largest power of two.
export function mthRange(leaves: string[], lo: number, hi: number): string {
  const count = hi - lo;
  if (count === 1) return leaves[lo];
  const k = pow2lt(count);
  return nodeHash(mthRange(leaves, lo, lo + k), mthRange(leaves, lo + k, hi));
}

export function merkleRoot(leaves: string[]): string {
  if (leaves.length === 0) return sha256(Buffer.alloc(0)).toString("hex");
  return mthRange(leaves, 0, leaves.length);
}

// ---- inclusion ----
export function inclusionProof(leaves: string[], m: number, lo = 0, hi = leaves.length): string[] {
  const count = hi - lo;
  if (count === 1) return [];
  const k = pow2lt(count);
  if (m - lo < k) return [...inclusionProof(leaves, m, lo, lo + k), mthRange(leaves, lo + k, hi)];
  return [...inclusionProof(leaves, m, lo + k, hi), mthRange(leaves, lo, lo + k)];
}

// Result type for the detailed verify variants. The boolean variants are thin
// wrappers; verifyInclusion(...) === verifyInclusionDetailed(...).ok.
export type VerifyResult = { ok: true } | { ok: false; reason: string };

// Recompute the root from a leaf + proof, mirroring the generator's recursion.
// Sentinel-returning: never throws. `null` means "malformed proof — couldn't
// produce a root from this input." Public surface treats null as "not verified."
function tryRootFromInclusion(leaf: string, m: number, n: number, proof: string[]): { root: string; reason?: string } {
  let p = 0;
  let badReason: string | null = null;
  function rec(idx: number, lo: number, hi: number): string {
    const count = hi - lo;
    if (count === 1) return leaf;
    const k = pow2lt(count);
    if (idx - lo < k) {
      const left = rec(idx, lo, lo + k);
      const right = proof[p++];
      if (right === undefined) {
        badReason ??= `audit path exhausted at index ${p - 1} (right sibling for [${lo + k}, ${hi}))`;
        return ""; // sentinel; nodeHash will produce garbage but we'll reject via badReason
      }
      return nodeHash(left, right);
    }
    const right = rec(idx, lo + k, hi);
    const left = proof[p++];
    if (left === undefined) {
      badReason ??= `audit path exhausted at index ${p - 1} (left sibling for [${lo}, ${lo + k}))`;
      return "";
    }
    return nodeHash(left, right);
  }
  const root = rec(m, 0, n);
  if (badReason !== null) return { root: "", reason: badReason };
  if (p !== proof.length) return { root: "", reason: `audit path has ${proof.length - p} unused nodes` };
  return { root };
}

// LEGACY: existing callers (and tests of the underlying recursion) keep this
// non-throwing string-returning surface. Returns "" on malformed input.
export function rootFromInclusion(leaf: string, m: number, n: number, proof: string[]): string {
  return tryRootFromInclusion(leaf, m, n, proof).root;
}

// Fail-closed boolean: never throws, never returns true for malformed input.
// No try/catch and no throw in the control flow (Dev §1): the underlying
// helper returns a sentinel, this function lifts it to a boolean by comparison.
export function verifyInclusion(leaf: string, m: number, n: number, proof: string[], root: string): boolean {
  const r = tryRootFromInclusion(leaf, m, n, proof);
  if (r.reason !== undefined) return false;
  return r.root === root;
}

// Non-throwing detailed variant for diagnostics / operators / tests. The boolean
// surface (verifyInclusion) is unchanged; this one names *why* a proof was rejected.
export function verifyInclusionDetailed(leaf: string, m: number, n: number, proof: string[], root: string): VerifyResult {
  const r = tryRootFromInclusion(leaf, m, n, proof);
  if (r.reason !== undefined) return { ok: false, reason: r.reason };
  if (r.root !== root) return { ok: false, reason: `rebuilt root ${r.root.slice(0, 12)}… != claimed root ${root.slice(0, 12)}…` };
  return { ok: true };
}

// ---- consistency (RFC 6962 SUBPROOF) ----
export function consistencyProof(leaves: string[], m: number, n: number): string[] {
  if (m <= 0 || m >= n) return [];
  return subproof(leaves, m, 0, n, true);
}

function subproof(leaves: string[], m: number, lo: number, hi: number, b: boolean): string[] {
  const count = hi - lo;
  if (m === count) return b ? [] : [mthRange(leaves, lo, hi)];
  const k = pow2lt(count);
  if (m <= k) return [...subproof(leaves, m, lo, lo + k, b), mthRange(leaves, lo + k, hi)];
  return [...subproof(leaves, m - k, lo + k, hi, false), mthRange(leaves, lo, lo + k)];
}

// Verify by reconstructing BOTH roots from the proof, mirroring SUBPROOF. The
// b=true base case is the seed: it is the old root, present unchanged in the new
// tree, and consumes no proof node (exactly as the generator emits nothing there).
// Sentinel-returning internal. No throws, no try/catch — every malformed-input
// path is a `return { ok: false, reason }` at the guard site (Dev §1).
function tryVerifyConsistency(
  m: number,
  n: number,
  oldRoot: string,
  newRoot: string,
  proof: string[],
): VerifyResult {
  if (m === n) {
    if (proof.length !== 0) return { ok: false, reason: `m === n but proof has ${proof.length} nodes` };
    if (oldRoot !== newRoot) return { ok: false, reason: "m === n but oldRoot !== newRoot" };
    return { ok: true };
  }
  if (m <= 0 || m > n) {
    return proof.length === 0
      ? { ok: true }
      : { ok: false, reason: `out-of-range (m=${m}, n=${n}) but proof has ${proof.length} nodes` };
  }
  let p = 0;
  let badReason: string | null = null;
  function rebuild(mm: number, lo: number, hi: number, b: boolean): { old: string; new: string } {
    const count = hi - lo;
    if (mm === count) {
      if (b) return { old: oldRoot, new: oldRoot };
      const x = proof[p++];
      if (x === undefined) {
        badReason ??= `proof exhausted at base case (index ${p - 1})`;
        return { old: "", new: "" };
      }
      return { old: x, new: x };
    }
    const k = pow2lt(count);
    if (mm <= k) {
      const sub = rebuild(mm, lo, lo + k, b);
      const sib = proof[p++];
      if (sib === undefined) {
        badReason ??= `proof exhausted at left-branch sibling (index ${p - 1})`;
        return { old: sub.old, new: "" };
      }
      return { old: sub.old, new: nodeHash(sub.new, sib) };
    }
    const sub = rebuild(mm - k, lo + k, hi, false);
    const sib = proof[p++];
    if (sib === undefined) {
      badReason ??= `proof exhausted at right-branch sibling (index ${p - 1})`;
      return { old: "", new: "" };
    }
    return { old: nodeHash(sib, sub.old), new: nodeHash(sib, sub.new) };
  }
  const { old, new: nw } = rebuild(m, 0, n, true);
  if (badReason !== null) return { ok: false, reason: badReason };
  if (p !== proof.length) return { ok: false, reason: `consistency proof has ${proof.length - p} unused nodes` };
  if (old !== oldRoot) return { ok: false, reason: `rebuilt old root ${old.slice(0, 12)}… != claimed ${oldRoot.slice(0, 12)}…` };
  if (nw !== newRoot) return { ok: false, reason: `rebuilt new root ${nw.slice(0, 12)}… != claimed ${newRoot.slice(0, 12)}…` };
  return { ok: true };
}

export function verifyConsistency(
  m: number,
  n: number,
  oldRoot: string,
  newRoot: string,
  proof: string[],
): boolean {
  return tryVerifyConsistency(m, n, oldRoot, newRoot, proof).ok;
}

// Non-throwing detailed variant for diagnostics. Names which guard tripped.
export function verifyConsistencyDetailed(
  m: number,
  n: number,
  oldRoot: string,
  newRoot: string,
  proof: string[],
): VerifyResult {
  return tryVerifyConsistency(m, n, oldRoot, newRoot, proof);
}

// ---- log service ----
// An append-only log over the RFC 6962 tree. Same append/inclusion surface the
// Proof Bay already consumes, now backed by a consistency-provable structure and
// exposing consistency proofs for a monitor.
export interface AppendResult {
  leafIndex: number;
  treeSize: number;
  auditPath: string[];
  rootHash: string;
}

export class TransparencyLog {
  readonly id: string;
  private leaves: string[] = [];

  constructor(id: string) {
    this.id = id;
  }

  get size(): number {
    return this.leaves.length;
  }

  append(data: Buffer): AppendResult {
    this.leaves.push(leafHash(data));
    const leafIndex = this.leaves.length - 1;
    return {
      leafIndex,
      treeSize: this.leaves.length,
      auditPath: inclusionProof(this.leaves, leafIndex),
      rootHash: merkleRoot(this.leaves),
    };
  }

  rootAt(treeSize: number = this.leaves.length): string {
    return merkleRoot(this.leaves.slice(0, treeSize));
  }

  inclusionProofAt(index: number, treeSize: number = this.leaves.length): string[] {
    return inclusionProof(this.leaves.slice(0, treeSize), index);
  }

  consistency(first: number, second: number = this.leaves.length): string[] {
    return consistencyProof(this.leaves.slice(0, second), first, second);
  }
}
