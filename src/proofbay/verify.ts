// TFB Proof Bay — admission verifier (the commercial wedge).
//
// The store CHECKS the certificate; it never re-derives the app's behavior.
// Three trust dials:
//   Tier A — attested issuer: signature + transparency + binding + freshness.
//   Tier B — proof-checked (default): also validate every grant's witness
//            against the served artifact and enforce minimality. Trusts the
//            math + artifact binding, NOT the issuer's honesty about minimality.
//   Tier C — sampled re-derivation: also replay the dynamic battery from seeds.
import type {
  AdmissionBundle,
  StorePolicy,
  VerificationResult,
  RejectionReason,
} from "./types";
import { directiveForKind } from "./types";
import { artifactHash, sliceHash, type Artifact } from "./artifact";
import { canonicalBytes } from "../canonical";
import { verifyBytes } from "../crypto";
import { leafHash, verifyInclusion } from "../merkle";
import { coreClone, leafClone } from "./seal";
import { policyHosts, grantParts } from "./policy";

// Tier C re-derivation is supplied by the caller (who has the real battery), so
// the verifier never depends on the battery and never re-executes code itself.
export interface Reproduction {
  fingerprint: string;
  observedEgress: string[];
}

const reject = (
  reason: RejectionReason,
  detail?: string,
): VerificationResult => ({ ok: false, reason, detail });

function cmpVersion(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d !== 0) return Math.sign(d);
  }
  return 0;
}

export function verifyAdmission(
  bundle: AdmissionBundle,
  artifact: Artifact,
  policy: StorePolicy,
  reproduce?: () => Reproduction,
): VerificationResult {
  // ---------- Tier A: identity, transparency, freshness, binding ----------
  const issuerPem = bundle.issuance.proofBayIdentity.publicKeyPem;
  if (!policy.trustedIssuers.includes(issuerPem)) {
    return reject("ISSUER_UNTRUSTED", bundle.issuance.proofBayIdentity.name);
  }
  if (!verifyBytes(canonicalBytes(coreClone(bundle)), bundle.issuance.signature, issuerPem)) {
    return reject("SIGNATURE_INVALID");
  }

  const receipt = bundle.issuance.transparencyReceipt;
  if (!receipt) return reject("NOT_IN_TRANSPARENCY_LOG");
  const rootBytes = Buffer.from(receipt.rootHash, "hex");
  if (!policy.trustedLogs.some((pem) => verifyBytes(rootBytes, receipt.rootSignature, pem))) {
    return reject("LOG_UNTRUSTED", receipt.logId);
  }
  const leaf = leafHash(canonicalBytes(leafClone(bundle)));
  if (!verifyInclusion(leaf, receipt.leafIndex, receipt.treeSize, receipt.auditPath, receipt.rootHash)) {
    return reject("NOT_IN_TRANSPARENCY_LOG");
  }

  const now = Date.now();
  if (Date.parse(bundle.issuance.issuedAt) > now) return reject("NOT_YET_VALID");
  if (Date.parse(bundle.issuance.expiresAt) < now) return reject("EXPIRED");

  if (artifactHash(artifact) !== bundle.subject.artifactHash) {
    return reject("ARTIFACT_MISMATCH");
  }

  if (cmpVersion(bundle.dynamicAttestation.battery.version, policy.minBatteryVersion) < 0) {
    return reject("BATTERY_OUTDATED", bundle.dynamicAttestation.battery.version);
  }

  if (policy.tier === "A") {
    return { ok: true, artifactHash: bundle.subject.artifactHash, tier: "A" };
  }

  // ---------- Tier B: proof-carrying core (verify, don't re-derive) ----------
  const declared = bundle.staticProof.cspPolicy;
  const witnessed = new Set<string>();

  for (const g of bundle.staticProof.grants) {
    const { directive, url } = grantParts(g.grant);
    const matching = g.witnesses.filter(
      (w) => directiveForKind(w.kind) === directive && w.url === url,
    );
    const valid = matching.filter(
      (w) => sliceHash(artifact, w.srcRef.file, w.srcRef.span) === w.srcRef.contentHash,
    );
    if (valid.length === 0) {
      // matching-but-bad-hash => evidence missing/tampered; none matching => unjustified
      return reject(
        matching.length > 0 ? "WITNESS_NOT_IN_ARTIFACT" : "UNWITNESSED_GRANT",
        g.grant,
      );
    }
    witnessed.add(g.grant);
  }

  // minimality (user-protecting): every running directive must be witnessed
  for (const d of declared) {
    if (!witnessed.has(d)) return reject("UNWITNESSED_GRANT", d);
  }
  // no smuggled directives: every witnessed grant must be in the running policy
  for (const g of witnessed) {
    if (!declared.includes(g)) return reject("POLICY_GRANT_MISMATCH", g);
  }

  // observed runtime egress must be covered by the policy
  const hosts = policyHosts(declared);
  for (const dom of bundle.dynamicAttestation.observedEgress) {
    if (!hosts.has(dom)) return reject("EGRESS_EXCEEDS_POLICY", dom);
  }

  if (bundle.dynamicAttestation.fingerprintVariance > policy.maxFingerprintVariance) {
    return reject("FINGERPRINT_UNSTABLE", String(bundle.dynamicAttestation.fingerprintVariance));
  }

  if (policy.tier === "B") {
    return { ok: true, artifactHash: bundle.subject.artifactHash, tier: "B" };
  }

  // ---------- Tier C: sampled re-derivation of the dynamic attestation ----------
  if (!reproduce) return reject("DYNAMIC_REPLAY_MISMATCH", "no reproducer supplied");
  const expected = reproduce();
  const a = [...expected.observedEgress].sort();
  const b = [...bundle.dynamicAttestation.observedEgress].sort();
  const sameEgress = a.length === b.length && a.every((d, i) => d === b[i]);
  if (expected.fingerprint !== bundle.dynamicAttestation.fingerprint || !sameEgress) {
    return reject("DYNAMIC_REPLAY_MISMATCH");
  }

  return { ok: true, artifactHash: bundle.subject.artifactHash, tier: "C" };
}
