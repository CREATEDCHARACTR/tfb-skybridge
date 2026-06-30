// Signed Tree Heads and the host-side Monitor. The Proof Bay's TransparencyLog
// holds admissions and revocations; a host (or any auditor) runs a Monitor that
// accepts a new STH only if it is signed and append-only-consistent with the last
// one accepted. A rewritten history or a split-view fails and is rejected — the
// guarantee the consistency-proof upgrade buys.
import { signBytes, verifyBytes } from "./crypto";
import { canonicalBytes } from "./canonical";
import { verifyConsistency } from "./merkle";
import type { TransparencyLog } from "./merkle";

export interface SignedTreeHead {
  logId: string;
  treeSize: number;
  rootHash: string;
  timestamp: string;
  signature: string;
}

function sthCore(sth: SignedTreeHead) {
  const { signature, ...core } = sth;
  return core;
}

// Sign an STH for the log's current (or a given) size.
export function issueSTH(
  log: TransparencyLog,
  logPrivateKeyPem: string,
  treeSize: number = log.size,
  timestamp: string = new Date().toISOString(),
): SignedTreeHead {
  const core = { logId: log.id, treeSize, rootHash: log.rootAt(treeSize), timestamp };
  return { ...core, signature: signBytes(canonicalBytes(core), logPrivateKeyPem) };
}

// Sign an arbitrary (logId, size, root) — used to forge attacker STHs in tests.
export function signTreeHead(
  logId: string,
  treeSize: number,
  rootHash: string,
  logPrivateKeyPem: string,
  timestamp: string = new Date().toISOString(),
): SignedTreeHead {
  const core = { logId, treeSize, rootHash, timestamp };
  return { ...core, signature: signBytes(canonicalBytes(core), logPrivateKeyPem) };
}

export class Monitor {
  private latest: SignedTreeHead | null = null;

  constructor(
    private logId: string,
    private logPublicKeyPem: string,
  ) {}

  get head(): SignedTreeHead | null {
    return this.latest;
  }

  verifySTH(sth: SignedTreeHead): boolean {
    if (sth.logId !== this.logId) return false;
    return verifyBytes(canonicalBytes(sthCore(sth)), sth.signature, this.logPublicKeyPem);
  }

  // Accept iff signed and append-only-consistent with the last accepted head.
  update(next: SignedTreeHead, consistency: string[] | null): boolean {
    if (!this.verifySTH(next)) return false;
    if (this.latest === null) {
      this.latest = next;
      return true;
    }
    if (next.treeSize === this.latest.treeSize) {
      if (next.rootHash !== this.latest.rootHash) return false; // split-view
      this.latest = next;
      return true;
    }
    if (next.treeSize < this.latest.treeSize) return false;
    if (consistency === null) return false;
    if (!verifyConsistency(this.latest.treeSize, next.treeSize, this.latest.rootHash, next.rootHash, consistency)) {
      return false; // rewrite caught here
    }
    this.latest = next;
    return true;
  }
}
