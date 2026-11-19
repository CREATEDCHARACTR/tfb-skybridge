import type { InferenceObservation, ShadowAssessment } from "../behavior/extraction/types";

export const CHATGPT_AGENT_PROVIDER = "chatgpt-agent-standin" as const;
export const MAX_AGENT_RESPONSE_BYTES = 131_072;

export function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index++;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}

export function assertWellFormedUnicode(value: string, error = "text_not_well_formed"): void {
  if (!isWellFormedUnicode(value)) throw new Error(error);
}

export interface RuntimeAuthority {
  authorityGranted: false;
  actionCeiling: "OBSERVE_ONLY";
  integrationAuthorized: false;
  activationAuthorized: false;
  productionClaimAuthorized: false;
}

export const OBSERVE_ONLY_AUTHORITY: RuntimeAuthority = Object.freeze({
  authorityGranted: false,
  actionCeiling: "OBSERVE_ONLY",
  integrationAuthorized: false,
  activationAuthorized: false,
  productionClaimAuthorized: false,
});

export interface RuntimeResult {
  op: string;
  ok: boolean;
  actions: string[];
  skips: string[];
  errors: string[];
  holds: string[];
  metrics: Record<string, unknown>;
  next: string;
  authority: RuntimeAuthority;
  [key: string]: unknown;
}

export interface AgentRequest {
  schema: "tfb.drawbridge.agent_request.v1";
  requestId: string;
  provider: typeof CHATGPT_AGENT_PROVIDER;
  tenantRef: string;
  sessionRef: string;
  sequence: number;
  prompt: string;
  promptSha256: string;
  scenarioId: string;
  regionEvidenceSha256: string;
  regionEvidenceExpiresAtMs: number;
  createdAtMs: number;
  expiresAtMs: number;
  nonce: string;
}

export interface AgentResponseInput {
  requestId: string;
  provider: string;
  response: string;
  responseSha256: string;
}

export interface AgentResponse extends AgentResponseInput {
  schema: "tfb.drawbridge.agent_response.v1";
  createdAtMs: number;
}

export interface PendingTurn {
  requestId: string;
  sequence: number;
  promptCommitment: string;
  requestExpiresAtMs: number;
  regionEvidenceSha256: string;
  regionEvidenceExpiresAtMs: number;
  observation: InferenceObservation;
  createdAtMs: number;
}

export interface DurableTurnReceipt {
  schema: "tfb.drawbridge.runtime_turn_receipt.v2";
  receiptReference: string;
  requestId: string;
  sequence: number;
  promptCommitment: string;
  responseCommitment: string;
  outputFingerprint: string;
  provider: typeof CHATGPT_AGENT_PROVIDER;
  regionEvidenceSha256: string;
  observation: InferenceObservation;
  assessment: ShadowAssessment;
  attestationReference: string | null;
  authority: RuntimeAuthority;
  completedAtMs: number;
}

export interface SessionState {
  schema: "tfb.drawbridge.runtime_session.v2";
  sessionRef: string;
  tenantRef: string;
  generation: string;
  capabilityNonce: string;
  writerFenceToken: string;
  nextSequence: number;
  retiredThroughSequence: number;
  pending: PendingTurn[];
  receipts: DurableTurnReceipt[];
}
