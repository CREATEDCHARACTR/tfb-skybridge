// TFB Span — type definitions.
// The Span is the runtime provenance membrane. Where the Proof Bay admits an
// app once (a signed certificate of what it MAY do), the Span watches what the
// app ACTUALLY does at the boundary, writes a tamper-evident signed receipt per
// event, and revokes admission if live behavior leaves the admitted envelope or
// drifts from the attested fingerprint.

export type BoundaryKind = "egress" | "script" | "host-message" | "storage";

import type { Baseline } from "../behavior/baseline";

// A single observed crossing of the iframe boundary.
export interface BoundaryEvent {
  seq: number;            // app-side event index (0-based)
  kind: BoundaryKind;
  host?: string;          // for egress / script
  directive?: string;     // CSP directive that governs it, e.g. "connect-src"
  capability?: string;    // for storage / capability use, e.g. "storage:scoped"
  bytes: number;
  ts: string;             // ISO timestamp
}

export interface SignedIdentity {
  name: string;
  publicKeyPem: string;   // Ed25519 SPKI PEM
}

export interface RevocationBody {
  reason: "VIOLATION" | "DRIFT";
  atSeq: number;
  detail: string;
  driftDistance?: number;
}

// One link in the per-session receipt chain. Each receipt is hash-chained to the
// previous and individually signed by the Span. Revocations are themselves
// receipts, so the decision to revoke is inside the tamper-evident record.
export interface Receipt {
  sessionId: string;
  seq: number;            // position in the chain
  prevHash: string;       // hash of previous receipt; genesis = 64 zeros
  kind: "event" | "revocation";
  event?: BoundaryEvent;
  revocation?: RevocationBody;
  ts: string;
  signature: string;      // Ed25519 over canonical(receipt with signature="")
}

// Normalized behavioral profile used for drift detection.
export interface BehaviorProfile {
  kindFreq: Record<BoundaryKind, number>; // normalized 0..1 per kind
  eventCount: number;
}

// The minimal slice of a Proof Bay AdmissionBundle the Span consumes.
// In the integrated system this is the real bundle; `behaviorProfile` is the
// structured profile the battery emits alongside its fingerprint.
export interface AdmissionBundleLike {
  subject: { artifactHash: string };
  staticProof: { cspPolicy: string[]; capabilityManifest: string[] };
  dynamicAttestation: {
    observedEgress: string[];
    fingerprint: string;
    fingerprintVariance: number;
    behaviorProfile?: BehaviorProfile;
    baseline?: Baseline;
  };
}

// The admitted envelope: the hard boundary the app must stay inside, plus the
// soft baseline it must not drift from.
export interface AdmissionEnvelope {
  artifactHash: string;
  hosts: Set<string>;
  directives: Set<string>;
  capabilities: Set<string>;
  attestedProfile: BehaviorProfile;
  baseline: Baseline;
  varianceBudget: number; // max behavioral divergence before DRIFT
}

export type EventVerdict = "ADMIT_CONTINUE" | "VIOLATION";
export type SessionVerdict = "ADMITTED" | "VIOLATION" | "DRIFT";

// Signed tail of a session — the equivalent of a signed tree head.
export interface SessionHead {
  sessionId: string;
  artifactHash: string;
  count: number;          // total receipts (events + revocation)
  headHash: string;       // hash of the last receipt
  liveFingerprint: string;
  verdict: SessionVerdict;
  signature: string;
}

// Portable revocation a host checks before continuing to render.
export interface RevocationRecord {
  sessionId: string;
  artifactHash: string;
  reason: "VIOLATION" | "DRIFT";
  atSeq: number;
  detail: string;
  ts: string;
  signature: string;
}
