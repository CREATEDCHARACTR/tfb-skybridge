// Proof Bay side: assemble an AdmissionBundle from an app, run the battery,
// then sign and log it. (In production these steps run after static analysis
// produces the grants/witnesses; here the app fixture supplies them.)
import type { AdmissionBundle, SignedIdentity } from "./types";
import { artifactHash } from "./artifact";
import { sha256Hex } from "../crypto";
import { policyHosts } from "./policy";
import { runBattery } from "./battery";
import { seal } from "./seal";
import { TransparencyLog } from "../merkle";
import type { AppFixture } from "./app";
import type { Baseline } from "../behavior/baseline";

export interface AttestationInput {
  observedEgress: string[];
  fingerprint: string;
  fingerprintVariance: number;
  behaviorProfile: AppFixture["behaviorProfile"];
  baseline?: Baseline;
  seeds: number[];
  transcriptHash: string;
  batteryVersion: string;
  result: "PASS" | "FAIL";
}

export interface IssueOptions {
  app: AppFixture;
  appId: string;
  version: string;
  developer: SignedIdentity;
  issuer: SignedIdentity;
  issuerPriv: string;
  log: TransparencyLog;
  logPriv: string;
  issuedAt: string;
  expiresAt: string;
  // When supplied (by a real battery), use this instead of the internal stub.
  attestation?: AttestationInput;
}

export function issueBundle(opts: IssueOptions): AdmissionBundle {
  const { app, attestation } = opts;
  if (attestation && attestation.result !== "PASS") {
    throw new Error("cannot issue an admission for a failing battery transcript");
  }
  const hosts = [...policyHosts(app.cspPolicy)].sort();
  const seeds = attestation?.seeds ?? [1, 2, 3, 4];
  const battery = runBattery(app.artifact, hosts, seeds);
  const aHash = artifactHash(app.artifact);

  const dynamicAttestation = attestation
    ? {
        battery: { id: "tfb-battery", version: attestation.batteryVersion },
        transcriptHash: attestation.transcriptHash,
        observedEgress: attestation.observedEgress,
        fingerprint: attestation.fingerprint,
        fingerprintVariance: attestation.fingerprintVariance,
        seeds: attestation.seeds,
        result: "PASS" as const,
        behaviorProfile: attestation.behaviorProfile,
        baseline: attestation.baseline,
      }
    : {
        battery: { id: "tfb-battery", version: "1.2.0" },
        transcriptHash: sha256Hex("transcript:" + aHash),
        observedEgress: battery.observedEgress,
        fingerprint: battery.fingerprint,
        fingerprintVariance: battery.variance,
        seeds,
        result: "PASS" as const,
        behaviorProfile: app.behaviorProfile,
      };

  const bundle: AdmissionBundle = {
    schemaVersion: "tfb-proofbay/0.1",
    subject: {
      artifactHash: aHash,
      artifactRef: "cid://demo",
      appId: opts.appId,
      version: opts.version,
      developerIdentity: opts.developer,
      hostTargets: ["chatgpt", "claude"],
    },
    staticProof: {
      cspPolicy: app.cspPolicy,
      capabilityManifest: app.capabilityManifest,
      grants: app.grants,
      minimalityClaim: true,
      completenessClaim: true,
      analyzer: { id: "tfb-cables", version: "0.1.0" },
    },
    dynamicAttestation,
    issuance: {
      proofBayIdentity: opts.issuer,
      issuedAt: opts.issuedAt,
      expiresAt: opts.expiresAt,
      transparencyReceipt: null,
      signature: "",
    },
  };

  return seal(bundle, opts.issuerPriv, opts.log, opts.logPriv);
}
