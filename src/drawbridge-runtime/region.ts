import { createHash, randomBytes } from "node:crypto";

const SHA256 = /^[0-9a-f]{64}$/;
const MAX_EVIDENCE_TTL_MS = 3_600_000;
const MAX_ACTIVE_CLAIMS = 4_096;

export interface RegionEvidenceInput {
  regionLabel: string;
  evidenceSource: string;
  syntheticDemoOnly: true;
}

export interface RegionEvidenceBinding {
  tenantRef: string;
  sessionRef: string;
  sequence: number;
}

export interface FrozenRegionScenario extends RegionEvidenceInput {
  scenarioId: string;
  fixtureSha256: string;
}

export interface RegionEvidence extends FrozenRegionScenario, RegionEvidenceBinding {
  evidenceSha256: string;
  issuedAtMs: number;
  expiresAtMs: number;
  nonce: string;
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonical(object[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function hash(value: unknown): string {
  return createHash("sha256").update(canonical(value)).digest("hex");
}

function validateBinding(binding: RegionEvidenceBinding): void {
  if (!SHA256.test(binding.tenantRef) || !SHA256.test(binding.sessionRef)
    || !Number.isSafeInteger(binding.sequence) || binding.sequence < 1) {
    throw new Error("region_evidence_binding_invalid");
  }
}

export class FrozenRegionEvidenceRegistry {
  private readonly records = new Map<string, FrozenRegionScenario>();
  private readonly claimed = new Map<string, number>();

  constructor(input: Record<string, RegionEvidenceInput>) {
    for (const [scenarioId, evidence] of Object.entries(input)) {
      if (!/^[a-z0-9._-]{1,128}$/i.test(scenarioId) || !evidence.regionLabel || !evidence.evidenceSource
        || evidence.syntheticDemoOnly !== true) {
        throw new Error("region_evidence_contract_invalid");
      }
      const fixtureSha256 = hash({ schema: "tfb.drawbridge.synthetic_region_fixture.v1", scenarioId, ...evidence });
      this.records.set(scenarioId, Object.freeze({ scenarioId, ...evidence, fixtureSha256 }));
    }
    Object.freeze(input);
  }

  has(scenarioId: string): boolean {
    return this.records.has(scenarioId);
  }

  issue(
    scenarioId: string,
    binding: RegionEvidenceBinding,
    issuedAtMs: number,
    ttlMs: number,
  ): RegionEvidence | undefined {
    const scenario = this.records.get(scenarioId);
    if (!scenario) return undefined;
    validateBinding(binding);
    if (!Number.isSafeInteger(issuedAtMs) || issuedAtMs < 0
      || !Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > MAX_EVIDENCE_TTL_MS) {
      throw new Error("region_evidence_time_contract_invalid");
    }
    this.pruneClaims(issuedAtMs);
    if (this.claimed.size >= MAX_ACTIVE_CLAIMS) throw new Error("region_evidence_claim_capacity_reached");
    const envelope = {
      schema: "tfb.drawbridge.synthetic_region_evidence.v1",
      ...scenario,
      ...binding,
      issuedAtMs,
      expiresAtMs: issuedAtMs + ttlMs,
      nonce: randomBytes(16).toString("hex"),
    };
    return Object.freeze({ ...envelope, evidenceSha256: hash(envelope) });
  }

  claim(evidence: RegionEvidence, binding: RegionEvidenceBinding, observedAtMs: number): RegionEvidence {
    validateBinding(binding);
    if (!Number.isSafeInteger(observedAtMs) || observedAtMs < 0) throw new Error("region_evidence_time_contract_invalid");
    const { evidenceSha256, ...envelope } = evidence;
    const scenario = this.records.get(evidence.scenarioId);
    if (!scenario || evidence.fixtureSha256 !== scenario.fixtureSha256 || hash(envelope) !== evidenceSha256
      || evidence.tenantRef !== binding.tenantRef || evidence.sessionRef !== binding.sessionRef
      || evidence.sequence !== binding.sequence) {
      throw new Error("region_evidence_binding_invalid");
    }
    this.pruneClaims(observedAtMs);
    if (observedAtMs < evidence.issuedAtMs || observedAtMs > evidence.expiresAtMs) throw new Error("region_evidence_expired");
    if (this.claimed.has(evidenceSha256)) throw new Error("region_evidence_replayed");
    this.claimed.set(evidenceSha256, evidence.expiresAtMs);
    return evidence;
  }

  list(): FrozenRegionScenario[] {
    return [...this.records.values()];
  }

  private pruneClaims(now: number): void {
    for (const [digest, expiresAtMs] of this.claimed) if (expiresAtMs < now) this.claimed.delete(digest);
  }
}

export const DEFAULT_DEMO_REGIONS = new FrozenRegionEvidenceRegistry({
  "bridge.north": { regionLabel: "bridge-north", evidenceSource: "tfb.drawbridge.frozen_demo_scenarios.v1", syntheticDemoOnly: true },
  "bridge.south": { regionLabel: "bridge-south", evidenceSource: "tfb.drawbridge.frozen_demo_scenarios.v1", syntheticDemoOnly: true },
});
