// The wired loop over the real subsystems (no vendored copies). Cables -> battery
// -> Proof Bay issuance -> the shared consistency-proven log -> the Span ->
// revocation -> host decision, plus the host-side monitor for log integrity.
import { signBytes, verifyBytes } from "./crypto";
import { canonicalBytes } from "./canonical";
import { TransparencyLog, leafHash, verifyInclusion } from "./merkle";
import { issueBundle, type AttestationInput } from "./proofbay/issue";
import { verifyAdmission, type Reproduction } from "./proofbay/verify";
import type { AdmissionBundle, StorePolicy, SignedIdentity } from "./proofbay/types";
import { Span } from "./span/membrane";
import { deriveEnvelope } from "./span/envelope";
import type { RevocationRecord } from "./span/types";
import type { AnalyzedApp } from "./cables/analyze";
import type { BatteryTranscript, SandboxPolicy } from "./battery/types";

// A sandbox policy (for the battery) derived from what Cables found in source.
export function sandboxPolicyFromAnalysis(a: AnalyzedApp): SandboxPolicy {
  const hosts = new Set<string>();
  const directives = new Set<string>();
  for (const e of a.cspPolicy) {
    const [d, u] = e.split(/\s+/);
    if (d) directives.add(d);
    if (u) {
      try {
        hosts.add(new URL(u).host);
      } catch {
        /* ignore */
      }
    }
  }
  return { hosts, directives, capabilities: new Set(a.capabilityManifest.filter((c) => c.startsWith("storage:"))) };
}

export function attestationFrom(t: BatteryTranscript): AttestationInput {
  return {
    observedEgress: t.observedEgress,
    fingerprint: t.fingerprint,
    fingerprintVariance: t.fingerprintVariance,
    behaviorProfile: t.behaviorProfile,
    baseline: t.baseline,
    seeds: t.seeds,
    transcriptHash: t.transcriptHash,
    batteryVersion: t.batteryVersion,
    result: t.result,
  };
}

export interface AdmitOptions {
  analyzed: AnalyzedApp;
  transcript: BatteryTranscript;
  appId: string;
  version: string;
  developer: SignedIdentity;
  issuer: SignedIdentity;
  issuerPriv: string;
  log: TransparencyLog;
  logPriv: string;
}

export function admit(opts: AdmitOptions): AdmissionBundle {
  return issueBundle({
    app: {
      artifact: opts.analyzed.artifact,
      grants: opts.analyzed.grants,
      cspPolicy: opts.analyzed.cspPolicy,
      capabilityManifest: opts.analyzed.capabilityManifest,
      behaviorProfile: opts.transcript.behaviorProfile,
    },
    appId: opts.appId,
    version: opts.version,
    developer: opts.developer,
    issuer: opts.issuer,
    issuerPriv: opts.issuerPriv,
    log: opts.log,
    logPriv: opts.logPriv,
    issuedAt: new Date(Date.now() - 3_600_000).toISOString(),
    expiresAt: new Date(Date.now() + 365 * 24 * 3_600_000).toISOString(),
    attestation: attestationFrom(opts.transcript),
  });
}

export function openSpan(sessionId: string, bundle: AdmissionBundle, spanPriv: string): Span {
  return new Span(sessionId, deriveEnvelope(bundle), "tfb-span", spanPriv);
}

export interface LoggedRevocation {
  record: RevocationRecord;
  leafIndex: number;
  treeSize: number;
  auditPath: string[];
  rootHash: string;
  rootSignature: string;
}

export function postRevocation(record: RevocationRecord, log: TransparencyLog, logPriv: string): LoggedRevocation {
  const appended = log.append(canonicalBytes(record));
  return {
    record,
    leafIndex: appended.leafIndex,
    treeSize: appended.treeSize,
    auditPath: appended.auditPath,
    rootHash: appended.rootHash,
    rootSignature: signBytes(Buffer.from(appended.rootHash, "hex"), logPriv),
  };
}

export function verifyLoggedRevocation(logged: LoggedRevocation, logPub: string): boolean {
  const leaf = leafHash(canonicalBytes(logged.record));
  return (
    verifyInclusion(leaf, logged.leafIndex, logged.treeSize, logged.auditPath, logged.rootHash) &&
    verifyBytes(Buffer.from(logged.rootHash, "hex"), logged.rootSignature, logPub)
  );
}

export interface HostDecision {
  decision: "RENDER" | "STOP";
  reason: string;
}

export function hostDecision(
  bundle: AdmissionBundle,
  artifact: AnalyzedApp["artifact"],
  policy: StorePolicy,
  logged: LoggedRevocation | null,
  logPub: string,
  reproduce?: () => Reproduction,
): HostDecision {
  const v = verifyAdmission(bundle, artifact, policy, reproduce);
  if (!v.ok) return { decision: "STOP", reason: `admission failed: ${v.reason}` };
  if (logged && logged.record.artifactHash === bundle.subject.artifactHash) {
    if (verifyLoggedRevocation(logged, logPub)) {
      return { decision: "STOP", reason: `revoked (${logged.record.reason}): ${logged.record.detail}` };
    }
  }
  return { decision: "RENDER", reason: `admitted (tier ${v.tier})` };
}
