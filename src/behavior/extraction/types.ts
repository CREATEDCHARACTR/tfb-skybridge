import type { BoundaryEvent } from "../types";

export type Uint64Hex = string;

export interface InferenceObservation {
  tenantToken: Uint64Hex;
  sessionToken: Uint64Hex;
  sequence: Uint64Hex;
  querySimhash: Uint64Hex;
  regionToken: Uint64Hex;
}

export interface RawInferenceInput {
  tenantId: string;
  sessionId: string;
  sequence: bigint;
  rawQuery: string;
  regionLabel: string;
}

export type InferenceBoundaryEvent = BoundaryEvent & {
  inference?: InferenceObservation;
};

export interface ShadowAssessment {
  status: "CANDIDATE_EVIDENCE" | "INSUFFICIENT_EVIDENCE";
  reason: string;
  signalId: "drawbridge.extraction.region_spread.v1-research";
  authority: "none";
  gridSize?: number;
  regionCount?: number;
}

export interface DrawbridgeResult {
  op: string;
  ok: boolean;
  actions: string[];
  skips: string[];
  errors: string[];
  metrics: Record<string, unknown>;
  next: string;
  assessment?: ShadowAssessment;
  observation?: InferenceObservation;
}
