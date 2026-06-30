// Derive the runtime envelope from what the Proof Bay admitted. The hard
// constraints (allowed hosts/directives/capabilities) come straight from the
// shipped bundle; the behavioral baseline is the one the battery attested. If a
// certificate predates baseline attestation, fall back to a distribution-only
// baseline built from the behavior profile (it flags drift but not volume/order).
import type { AdmissionBundleLike, AdmissionEnvelope, BehaviorProfile } from "./types";
import type { Baseline } from "../behavior/baseline";

const EMPTY_PROFILE: BehaviorProfile = {
  kindFreq: { egress: 0, script: 0, "host-message": 0, storage: 0 },
  eventCount: 0,
};

// A permissive baseline: distribution detector active, sequence/budget inert.
function fallbackBaseline(profile: BehaviorProfile, varianceBudget: number): Baseline {
  return {
    kindFreq: profile.kindFreq,
    distBudget: varianceBudget,
    bigrams: new Set<string>(),
    unexpectedFracBudget: 1, // never flags
    maxRun: Number.POSITIVE_INFINITY,
    minIntervalMs: 0,
    budgets: {}, // unknown keys are ignored by the budget detector
  };
}

export function deriveEnvelope(
  bundle: AdmissionBundleLike,
  varianceBudget = 0.25,
): AdmissionEnvelope {
  const hosts = new Set<string>();
  const directives = new Set<string>();

  for (const entry of bundle.staticProof.cspPolicy) {
    const [directive, url] = entry.split(/\s+/);
    if (directive) directives.add(directive);
    if (url) {
      try {
        hosts.add(new URL(url).host);
      } catch {
        /* ignore malformed entries */
      }
    }
  }
  for (const h of bundle.dynamicAttestation.observedEgress) hosts.add(h);

  const attestedProfile = bundle.dynamicAttestation.behaviorProfile ?? EMPTY_PROFILE;
  const baseline = bundle.dynamicAttestation.baseline ?? fallbackBaseline(attestedProfile, varianceBudget);

  return {
    artifactHash: bundle.subject.artifactHash,
    hosts,
    directives,
    capabilities: new Set(bundle.staticProof.capabilityManifest),
    attestedProfile,
    baseline,
    varianceBudget,
  };
}
