// TFB Proof Bay — type definitions
// The AdmissionBundle is the entire deliverable: a proof-carrying certificate
// of exactly what an agent-native app does at the host boundary.

export type HostTarget = "chatgpt" | "claude" | (string & {});

import type { Baseline } from "../behavior/baseline";

export interface SignedIdentity {
  name: string;
  publicKeyPem: string; // Ed25519 SPKI PEM
}

export type EgressKind =
  | "fetch" | "import" | "connect" | "wasm" | "worker" | "img" | "style";

// Behavior profile emitted by the battery alongside its fingerprint. This is the
// Proof Bay -> Span contract: the Span uses it as the soft drift baseline.
export type BoundaryKind = "egress" | "script" | "host-message" | "storage";
export interface BehaviorProfile {
  kindFreq: Record<BoundaryKind, number>;
  eventCount: number;
}

export interface SrcRef {
  file: string;             // path inside the hashed artifact
  span: [number, number];   // byte range [start, end)
  contentHash: string;      // sha256 of artifact[file][span] — pins the evidence
}

export interface Witness {
  srcRef: SrcRef;
  kind: EgressKind;
  url: string;              // resolved egress target (origin)
  derivation: string;       // analysis step: source construct -> grant
}

export interface Grant {
  grant: string;            // e.g. "connect-src https://api.stripe.com"
  witnesses: Witness[];     // evidence justifying this grant
}

export interface InclusionProofStep {
  hash: string;
  side: "left" | "right";
}

export interface TransparencyReceipt {
  logId: string;
  treeSize: number;
  leafIndex: number;
  auditPath: string[];      // RFC 6962 inclusion proof (sibling hashes, leaf->root order derived)
  rootHash: string;
  rootSignature: string;    // log signs the rootHash (signed tree head)
}

export interface AdmissionBundle {
  schemaVersion: string;

  subject: {
    artifactHash: string;   // sha256 of the exact view bundle that renders
    artifactRef: string;
    appId: string;
    version: string;
    developerIdentity: SignedIdentity;
    hostTargets: HostTarget[];
  };

  staticProof: {
    cspPolicy: string[];          // the policy that ACTUALLY runs in the iframe
    capabilityManifest: string[]; // typed capabilities
    grants: Grant[];              // one per CSP directive
    minimalityClaim: true;        // "no grant exists without a valid witness"
    completenessClaim: true;      // "every static egress maps to a grant"
    analyzer: { id: string; version: string };
  };

  dynamicAttestation: {
    battery: { id: string; version: string };
    transcriptHash: string;
    observedEgress: string[];     // hosts actually contacted; MUST be covered by cspPolicy
    fingerprint: string;
    fingerprintVariance: number;
    seeds: number[];              // deterministic replay seeds (Tier C)
    result: "PASS";
    behaviorProfile?: BehaviorProfile; // emitted for the Span (drift baseline)
    baseline?: Baseline;               // full attested baseline for the Span's monitor
  };

  issuance: {
    proofBayIdentity: SignedIdentity;
    issuedAt: string;
    expiresAt: string;
    transparencyReceipt: TransparencyReceipt | null;
    signature: string;            // Ed25519 over canonical(core)
  };
}

export type RejectionReason =
  | "SIGNATURE_INVALID"
  | "ISSUER_UNTRUSTED"
  | "LOG_UNTRUSTED"
  | "NOT_IN_TRANSPARENCY_LOG"
  | "NOT_YET_VALID"
  | "EXPIRED"
  | "ARTIFACT_MISMATCH"
  | "BATTERY_OUTDATED"
  | "UNWITNESSED_GRANT"
  | "WITNESS_NOT_IN_ARTIFACT"
  | "POLICY_GRANT_MISMATCH"
  | "EGRESS_EXCEEDS_POLICY"
  | "FINGERPRINT_UNSTABLE"
  | "DYNAMIC_REPLAY_MISMATCH";

export interface StorePolicy {
  tier: "A" | "B" | "C";
  trustedIssuers: string[];   // trusted Proof Bay SPKI PEMs
  trustedLogs: string[];      // trusted transparency-log SPKI PEMs
  minBatteryVersion: string;
  maxFingerprintVariance: number;
}

export type VerificationResult =
  | { ok: true; artifactHash: string; tier: "A" | "B" | "C" }
  | { ok: false; reason: RejectionReason; detail?: string };

const DIRECTIVE: Record<EgressKind, string> = {
  fetch: "connect-src",
  connect: "connect-src",
  wasm: "connect-src",
  worker: "connect-src",
  import: "script-src",
  img: "img-src",
  style: "style-src",
};

export function directiveForKind(kind: EgressKind): string {
  return DIRECTIVE[kind];
}
