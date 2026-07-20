import { createHmac } from "node:crypto";
import type { DrawbridgeResult, InferenceObservation, RawInferenceInput } from "./types";

const UINT64_LIMIT = 1n << 64n;
const HEX64 = /^[0-9a-f]{16}$/;

function result(
  ok: boolean,
  errors: string[],
  observation?: InferenceObservation,
): DrawbridgeResult {
  return {
    op: "drawbridge.extraction.produce_inference_observation",
    ok,
    actions: ok ? ["normalized_query_ephemerally", "derived_opaque_tokens", "emitted_fixed_width_observation"] : [],
    skips: [
      "raw_query_not_retained",
      "raw_identity_not_retained",
      "model_output_not_admitted",
      "policy_action_not_evaluated",
    ],
    errors,
    metrics: {
      raw_payload_retained: false,
      output_field_count: observation ? Object.keys(observation).length : 0,
      query_sketch_algorithm: "drawbridge.query_simhash.tenant_hmac_sha256_shingle.v1",
      opaque_token_algorithm: "drawbridge.opaque_token.hmac_sha256_64.v1",
      authority_granted: false,
      action_ceiling: "OBSERVE_ONLY",
    },
    next: ok
      ? "Pass the opaque observation to the expiring shadow scorer; do not persist producer inputs."
      : "Supply complete bounded producer inputs without retaining or logging raw values.",
    ...(observation ? { observation } : {}),
  };
}

function normalizeQuery(value: string): string {
  return value.normalize("NFKC").trim().toLowerCase().split(/\s+/u).filter(Boolean).join(" ");
}

function shingles(value: string): string[] {
  const normalized = normalizeQuery(value);
  if (!normalized) return [];
  const k = value.trim().length < 20 ? 3 : 4;
  const tokens = normalized.split(" ");
  if (tokens.length >= k) {
    return tokens.slice(0, tokens.length - k + 1).map((_, index) => tokens.slice(index, index + k).join(" "));
  }
  const chars = normalized.replaceAll(" ", "");
  const width = Math.max(2, Math.min(k, chars.length));
  if (chars.length < width) return [normalized];
  return Array.from({ length: chars.length - width + 1 }, (_, index) => chars.slice(index, index + width));
}

function hash64(secret: Buffer, tenantId: string, value: string): bigint {
  const digest = createHmac("sha256", secret)
    .update("drawbridge:query-shingle:v1", "utf8")
    .update("\0")
    .update(tenantId.normalize("NFKC"), "utf8")
    .update("\0")
    .update(value, "utf8")
    .digest();
  return digest.readBigUInt64BE(0);
}

function simhash64(values: string[], secret: Buffer, tenantId: string): bigint {
  if (values.length === 0) return 0n;
  const weights = Array<number>(64).fill(0);
  for (const value of values) {
    const hashed = hash64(secret, tenantId, value);
    for (let bit = 0; bit < 64; bit++) {
      weights[bit] += ((hashed >> BigInt(bit)) & 1n) === 1n ? 1 : -1;
    }
  }
  let output = 0n;
  for (let bit = 0; bit < 64; bit++) if (weights[bit] > 0) output |= 1n << BigInt(bit);
  return output;
}

function token64(secret: Buffer, domain: string, ...values: string[]): string {
  const hmac = createHmac("sha256", secret).update(domain, "utf8");
  for (const value of values) hmac.update("\0").update(value.normalize("NFKC"), "utf8");
  return hmac.digest("hex").slice(0, 16);
}

function hex64(value: bigint): string {
  return value.toString(16).padStart(16, "0");
}

export function isInferenceObservation(value: unknown): value is InferenceObservation {
  if (!value || typeof value !== "object") return false;
  const object = value as Record<string, unknown>;
  const expected = ["querySimhash", "regionToken", "sequence", "sessionToken", "tenantToken"];
  const actual = Object.keys(object).sort();
  return JSON.stringify(actual) === JSON.stringify(expected)
    && expected.every((field) => typeof object[field] === "string" && HEX64.test(object[field] as string));
}

export function produceInferenceObservation(input: RawInferenceInput, secret: Buffer): DrawbridgeResult {
  const errors: string[] = [];
  if (!Buffer.isBuffer(secret) || secret.length < 32) errors.push("producer_secret_minimum_32_bytes_required");
  if (!input || typeof input !== "object") errors.push("producer_input_required");
  if (typeof input?.tenantId !== "string" || !input.tenantId.trim()) errors.push("tenant_id_required");
  if (typeof input?.sessionId !== "string" || !input.sessionId.trim()) errors.push("session_id_required");
  if (typeof input?.regionLabel !== "string" || !input.regionLabel.trim()) errors.push("region_label_required");
  if (typeof input?.rawQuery !== "string" || !normalizeQuery(input.rawQuery)) errors.push("raw_query_required");
  if (typeof input?.sequence !== "bigint" || input.sequence < 0n || input.sequence >= UINT64_LIMIT) {
    errors.push("sequence_uint64_required");
  }
  if (errors.length) return result(false, errors);

  const observation = Object.freeze({
    tenantToken: token64(secret, "drawbridge:tenant:v1", input.tenantId),
    sessionToken: token64(secret, "drawbridge:session:v1", input.tenantId, input.sessionId),
    sequence: hex64(input.sequence),
    querySimhash: hex64(simhash64(shingles(input.rawQuery), secret, input.tenantId)),
    regionToken: token64(secret, "drawbridge:region:v1", input.tenantId, input.regionLabel),
  });
  return result(true, [], observation);
}
