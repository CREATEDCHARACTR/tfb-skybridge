import { createHash, createHmac } from "node:crypto";
import { produceInferenceObservation } from "../behavior/extraction/producer";
import { ShadowExtractionObserver, type ShadowExtractionConfig } from "../behavior/extraction/shadow";
import type { ShadowAssessment } from "../behavior/extraction/types";
import { ExternalAgentExchange } from "./exchange";
import { FrozenRegionEvidenceRegistry } from "./region";
import { RedactedSessionStore } from "./store";
import {
  assertWellFormedUnicode,
  CHATGPT_AGENT_PROVIDER,
  isWellFormedUnicode,
  OBSERVE_ONLY_AUTHORITY,
  type AgentResponseInput,
  type DurableTurnReceipt,
  type RuntimeResult,
} from "./types";

function sha256(value: string | Buffer): string { return createHash("sha256").update(value).digest("hex"); }
function durableCommitment(secret: Buffer, domain: "prompt" | "response", digest: string): string {
  return createHmac("sha256", secret)
    .update(`drawbridge:durable-${domain}-commitment:v1\0`, "utf8")
    .update(digest, "utf8")
    .digest("hex");
}
function outputFingerprint(secret: Buffer, value: string): string {
  return createHmac("sha256", secret)
    .update("drawbridge:durable-output-fingerprint:v1\0", "utf8")
    .update(value.trim().toLowerCase().replace(/\s+/gu, " "), "utf8")
    .digest("hex");
}
function attestationPayloadDigest(requestId: string, promptSha256: string, responseSha256: string): Buffer {
  return createHash("sha256")
    .update("drawbridge:attestation-payload:v1\0", "utf8")
    .update(requestId, "utf8")
    .update("\0", "utf8")
    .update(promptSha256, "utf8")
    .update("\0", "utf8")
    .update(responseSha256, "utf8")
    .digest();
}
function attestationContentAddress(value: unknown): string {
  if (typeof value !== "string") throw new Error("attestation_output_invalid");
  if (!isWellFormedUnicode(value)) throw new Error("attestation_output_invalid");
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length < 1 || bytes.length > 4_096) throw new Error("attestation_output_invalid");
  const digest = createHash("sha256")
    .update("drawbridge:attestation-output:v1\0", "utf8")
    .update(bytes)
    .digest("hex");
  return `attestation-sha256:${digest}`;
}

function result(op: string, ok: boolean, holds: string[], extra: Record<string, unknown> = {}): RuntimeResult {
  return {
    op,
    ok,
    actions: [],
    skips: ["policy_action_not_evaluated", "integration_not_authorized", "activation_not_authorized"],
    errors: [],
    holds,
    metrics: {
      model_provider_network_calls: 0,
      attestation_callback_transport_measured: false,
    },
    next: ok ? "Continue the OBSERVE_ONLY demo journey." : "Heal every named hold before continuing this turn.",
    authority: OBSERVE_ONLY_AUTHORITY,
    ...extra,
  };
}

export interface RuntimeControllerOptions {
  exchange: ExternalAgentExchange;
  store: RedactedSessionStore;
  regions: FrozenRegionEvidenceRegistry;
  producerSecret: Buffer;
  observerConfig?: Partial<ShadowExtractionConfig>;
  regionEvidenceTtlMs?: number;
  now?: () => number;
  attestor?: (payloadDigest: Buffer) => string;
  custodyCheck?: () => void;
}

export interface SessionMutationOptions {
  requireEmptyPending?: boolean;
}

export class DrawbridgeRuntimeController {
  private readonly now: () => number;
  private readonly regionEvidenceTtlMs: number;
  private readonly durableCommitmentKey: Buffer;
  constructor(private readonly options: RuntimeControllerOptions) {
    if (!Buffer.isBuffer(options.producerSecret) || options.producerSecret.length < 32) throw new Error("producer_secret_minimum_32_bytes_required");
    this.durableCommitmentKey = createHmac("sha256", options.producerSecret)
      .update("drawbridge:durable-commitment-key:v1", "utf8")
      .digest();
    this.now = options.now ?? Date.now;
    this.regionEvidenceTtlMs = options.regionEvidenceTtlMs ?? 60_000;
    if (!Number.isInteger(this.regionEvidenceTtlMs) || this.regionEvidenceTtlMs < 1 || this.regionEvidenceTtlMs > 3_600_000) {
      throw new Error("region_evidence_ttl_out_of_range");
    }
  }

  private custodyHold(op: string): RuntimeResult | undefined {
    try { this.options.custodyCheck?.(); return undefined; }
    catch {
      return result(op, false, ["runtime_custody_changed"], {
        errors: ["runtime_custody_changed"],
      });
    }
  }

  health(): RuntimeResult {
    try {
      this.options.custodyCheck?.();
      const swept = this.options.exchange.sweepExpired();
      const expiredPending = this.options.store.reconcileExpiredPending(this.now());
      for (const requestId of expiredPending.requestIds) this.options.exchange.erase(requestId);
      const exchange = this.options.exchange.audit();
      const { pendingBindings, receiptRequestIds, ...store } = this.options.store.audit();
      const rawBindings = this.options.exchange.bindingInventory();
      const crashRecovery = this.options.exchange.drainCrashRecoveries();
      const storeCrashRecovery = this.options.store.drainCrashRecoveries();
      const pending = new Map(pendingBindings.map((binding) => [binding.requestId, binding] as const));
      const receipts = new Set(receiptRequestIds);
      const holds: string[] = [];
      const actions = [
        "swept_expired_raw_exchange", "retired_expired_durable_pending", "validated_custody_roots", "parsed_all_bounded_durable_sessions",
      ];
      const sweepMetrics = swept.metrics as Record<string, unknown>;
      const crashRecoveries = crashRecovery.invalidRequests + crashRecovery.orphanResponses + crashRecovery.crashTemporaries;
      if (crashRecoveries > 0) {
        holds.push("runtime_exchange_crash_state_recovered");
        actions.push("recovered_exchange_crash_state");
      }
      if (storeCrashRecovery.locks + storeCrashRecovery.temporaries > 0) {
        holds.push("runtime_store_crash_state_recovered");
        actions.push("recovered_store_crash_state");
      }
      for (const raw of rawBindings) {
        const durable = pending.get(raw.requestId);
        if (!durable) {
          this.options.exchange.erase(raw.requestId);
          if (receipts.has(raw.requestId)) {
            holds.push("runtime_completed_raw_request_recovered");
            actions.push("erased_completed_raw_request");
          } else {
            holds.push("runtime_orphan_raw_request_recovered");
            actions.push("erased_orphan_raw_request");
          }
          continue;
        }
        if (raw.tenantRef !== durable.tenantRef
          || raw.sessionRef !== durable.sessionRef
          || raw.sequence !== durable.sequence
          || durableCommitment(this.durableCommitmentKey, "prompt", raw.promptSha256) !== durable.promptCommitment
          || raw.regionEvidenceSha256 !== durable.regionEvidenceSha256
          || raw.regionEvidenceExpiresAtMs !== durable.regionEvidenceExpiresAtMs
          || raw.requestExpiresAtMs !== durable.requestExpiresAtMs) {
          holds.push("runtime_pending_request_binding_mismatch");
        }
      }
      const rawIds = new Set(rawBindings.map(({ requestId }) => requestId));
      for (const requestId of pending.keys()) {
        if (!rawIds.has(requestId)) holds.push("runtime_pending_request_missing");
      }
      const uniqueHolds = [...new Set(holds)];
      return {
        ...result("drawbridge.runtime.health", uniqueHolds.length === 0, uniqueHolds),
        actions: [...new Set([...actions, "reconciled_exact_raw_and_durable_request_bindings"])],
        metrics: {
          model_provider_network_calls: 0,
          attestation_callback_transport_measured: false,
          durable_session_contains_raw_prompt_or_response: false,
          raw_exchange_plaintext_pending: exchange.pendingRawRequests + exchange.rawResponseFiles > 0,
          raw_exchange_retention_enforcement: "ACTIVE_RUNTIME_TIMER_OR_NEXT_RUNTIME_SWEEP",
          ...sweepMetrics,
          crash_invalid_requests_recovered_since_health: crashRecovery.invalidRequests,
          crash_orphan_responses_recovered_since_health: crashRecovery.orphanResponses,
          crash_temporaries_recovered_since_health: crashRecovery.crashTemporaries,
          crash_store_locks_recovered_since_health: storeCrashRecovery.locks,
          crash_store_temporaries_recovered_since_health: storeCrashRecovery.temporaries,
          expired_pending_retired: expiredPending.pendingRetired,
          expired_pending_sessions_reclaimed: expiredPending.sessionsReclaimed,
          ...exchange,
          ...store,
        },
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.startsWith("drawbridge_custody_")) {
        return result("drawbridge.runtime.health", false, ["runtime_custody_changed"], {
          errors: ["runtime_custody_changed"],
        });
      }
      const integrityErrorKind = /^[a-z0-9_]+$/u.test(message) ? message : "unclassified_integrity_error";
      return {
        ...result("drawbridge.runtime.health", false, ["runtime_integrity_check_failed"]),
        errors: ["runtime_integrity_check_failed"],
        metrics: {
          model_provider_network_calls: 0,
          attestation_callback_transport_measured: false,
          integrityErrorKind,
        },
      };
    }
  }

  startSession(tenantId: string, sessionId: string, resumeToken?: string): RuntimeResult & {
    sessionRef: string;
    sessionCapability: string;
    sessionResumeToken: string;
  } {
    const custodyHold = this.custodyHold("drawbridge.runtime.start_session");
    if (custodyHold) return { ...custodyHold, sessionRef: "", sessionCapability: "", sessionResumeToken: "" };
    try { assertWellFormedUnicode(tenantId); assertWellFormedUnicode(sessionId); }
    catch { return { ...result("drawbridge.runtime.start_session", false, ["text_not_well_formed"]), sessionRef: "", sessionCapability: "", sessionResumeToken: "" }; }
    this.options.exchange.sweepExpired();
    try {
      const expiredPending = this.options.store.reconcileExpiredPending(this.now());
      for (const requestId of expiredPending.requestIds) this.options.exchange.erase(requestId);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        ...result("drawbridge.runtime.start_session", false, ["session_state_commit_failed"], { errors: [message] }),
        sessionRef: "", sessionCapability: "", sessionResumeToken: "",
      };
    }
    let identity: { sessionRef: string; exists: boolean };
    try { identity = this.options.store.sessionIdentity(tenantId, sessionId); }
    catch (error) {
      return {
        ...result("drawbridge.runtime.start_session", false, ["session_identity_invalid"], {
          errors: [error instanceof Error ? error.message : String(error)],
        }),
        sessionRef: "", sessionCapability: "", sessionResumeToken: "",
      };
    }
    if (identity.exists && !resumeToken) {
      return {
        ...result("drawbridge.runtime.start_session", false, ["session_resume_token_required"]),
        sessionRef: identity.sessionRef, sessionCapability: "", sessionResumeToken: "",
      };
    }
    if (identity.exists && !this.options.store.verifySessionResumeToken(identity.sessionRef, resumeToken)) {
      return {
        ...result("drawbridge.runtime.start_session", false, ["session_resume_token_invalid"]),
        sessionRef: identity.sessionRef, sessionCapability: "", sessionResumeToken: "",
      };
    }
    let started;
    try { started = this.options.store.startSession(tenantId, sessionId, resumeToken); }
    catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        ...result("drawbridge.runtime.start_session", false, [message], { errors: [message] }),
        sessionRef: identity.sessionRef, sessionCapability: "", sessionResumeToken: "",
      };
    }
    const { state, sessionCapability, sessionResumeToken } = started;
    return {
      ...result("drawbridge.runtime.start_session", true, []),
      actions: ["created_or_loaded_redacted_session"],
      sessionRef: state.sessionRef,
      sessionCapability,
      sessionResumeToken,
    };
  }

  verifySessionCapability(sessionRef: string, supplied: string | undefined): boolean {
    if (this.custodyHold("drawbridge.runtime.verify_session_capability")) return false;
    return this.options.store.verifySessionCapability(sessionRef, supplied);
  }

  requestSessionRef(requestId: string): string | undefined {
    if (this.custodyHold("drawbridge.runtime.request_session_ref")) return undefined;
    return this.options.store.requestSessionRef(requestId);
  }

  submitPrompt(
    sessionRef: string,
    prompt: string,
    scenarioId: string,
    sessionCapability: string,
    options: SessionMutationOptions = {},
  ): RuntimeResult & { requestId?: string; sequence?: number } {
    const custodyHold = this.custodyHold("drawbridge.runtime.submit_prompt");
    if (custodyHold) return custodyHold;
    if (!isWellFormedUnicode(prompt) || !isWellFormedUnicode(scenarioId)) {
      return result("drawbridge.runtime.submit_prompt", false, ["text_not_well_formed"]);
    }
    if (!sessionCapability) return result("drawbridge.runtime.submit_prompt", false, ["session_capability_required"]);
    this.options.exchange.sweepExpired();
    if (!this.options.regions.has(scenarioId)) return result("drawbridge.runtime.submit_prompt", false, ["region_evidence_not_registered"]);
    let state;
    try {
      state = this.options.store.loadSession(sessionRef, sessionCapability);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message === "session_capability_invalid" || message === "session_capability_required") {
        return result("drawbridge.runtime.submit_prompt", false, [message]);
      }
      if (message.startsWith("session_store_")) {
        return result("drawbridge.runtime.submit_prompt", false, ["session_state_commit_failed"], { errors: [message] });
      }
      return result("drawbridge.runtime.submit_prompt", false, ["session_not_found"]);
    }
    if (options.requireEmptyPending && state.pending.length > 0) {
      return result("drawbridge.runtime.submit_prompt", false, ["session_pending_turn_requires_recovery"]);
    }
    const sequence = state.nextSequence;
    const binding = { tenantRef: state.tenantRef, sessionRef: state.sessionRef, sequence };
    let evidence;
    try {
      const issued = this.options.regions.issue(scenarioId, binding, this.now(), this.regionEvidenceTtlMs);
      if (!issued) return result("drawbridge.runtime.submit_prompt", false, ["region_evidence_not_registered"]);
      evidence = this.options.regions.claim(issued, binding, this.now());
    } catch (error) {
      return result("drawbridge.runtime.submit_prompt", false, ["region_evidence_contract_invalid"], {
        errors: [error instanceof Error ? error.message : String(error)],
      });
    }
    const producer = produceInferenceObservation({
      tenantId: state.tenantRef,
      sessionId: state.sessionRef,
      sequence: BigInt(sequence),
      rawQuery: prompt,
      regionLabel: evidence.regionLabel,
    }, this.options.producerSecret);
    if (!producer.ok || !producer.observation) return result("drawbridge.runtime.submit_prompt", false, ["inference_observation_not_produced"], { producer });
    let request;
    try {
      request = this.options.exchange.createRequest({
        tenantRef: state.tenantRef,
        sessionRef: state.sessionRef,
        sequence,
        prompt,
        scenarioId,
        regionEvidenceSha256: evidence.evidenceSha256,
        regionEvidenceExpiresAtMs: evidence.expiresAtMs,
      });
    } catch (error) {
      return result("drawbridge.runtime.submit_prompt", false, ["agent_request_write_failed"], {
        errors: [error instanceof Error ? error.message : String(error)],
      });
    }
    try {
      this.options.store.addPending(sessionRef, {
        requestId: request.requestId,
        sequence,
        promptCommitment: durableCommitment(this.durableCommitmentKey, "prompt", request.promptSha256),
        regionEvidenceSha256: evidence.evidenceSha256,
        regionEvidenceExpiresAtMs: evidence.expiresAtMs,
        requestExpiresAtMs: request.expiresAtMs,
        observation: producer.observation,
        createdAtMs: request.createdAtMs,
      }, { sessionCapability, requireEmptyPending: options.requireEmptyPending });
    } catch (error) {
      this.options.exchange.erase(request.requestId);
      const message = error instanceof Error ? error.message : String(error);
      const namedHold = ["session_capability_invalid", "session_pending_turn_requires_recovery"].includes(message)
        ? message
        : "session_state_commit_failed";
      return result("drawbridge.runtime.submit_prompt", false, [namedHold], { errors: [message] });
    }
    return {
      ...result("drawbridge.runtime.submit_prompt", true, []),
      actions: ["validated_region_evidence", "produced_opaque_observation", "wrote_content_addressed_agent_request"],
      metrics: {
        model_provider_network_calls: 0,
        attestation_callback_transport_measured: false,
        durable_session_contains_raw_prompt_or_response: false,
        raw_exchange_plaintext_pending: true,
        raw_exchange_retention_enforcement: "ACTIVE_RUNTIME_TIMER_OR_NEXT_RUNTIME_SWEEP",
      },
      requestId: request.requestId,
      sequence,
      provider: CHATGPT_AGENT_PROVIDER,
      status: "PENDING_AGENT_RESPONSE",
      syntheticDemoOnly: true,
      regionEvidenceSha256: evidence.evidenceSha256,
    };
  }

  submitAgentResponse(input: AgentResponseInput): RuntimeResult {
    const custodyHold = this.custodyHold("drawbridge.runtime.submit_agent_response");
    if (custodyHold) return custodyHold;
    if (![input.requestId, input.provider, input.response, input.responseSha256].every((value) => isWellFormedUnicode(value))) {
      return result("drawbridge.runtime.submit_agent_response", false, ["text_not_well_formed"]);
    }
    const found = this.options.store.findAgentRequest(input.requestId);
    if (!found) return result("drawbridge.runtime.submit_agent_response", false, ["request_not_registered"]);
    if (found.receipt) {
      const digestMatches = input.provider === CHATGPT_AGENT_PROVIDER
        && sha256(input.response) === input.responseSha256
        && durableCommitment(this.durableCommitmentKey, "response", input.responseSha256) === found.receipt.responseCommitment;
      return digestMatches
        ? result("drawbridge.runtime.submit_agent_response", true, [], {
          actions: ["duplicate_completed_response_noop"],
          requestId: input.requestId,
          responseSha256: input.responseSha256,
          provider: input.provider,
        })
        : result("drawbridge.runtime.submit_agent_response", false, ["completed_response_conflict"], { requestId: input.requestId });
    }
    return this.options.exchange.submitResponse(input);
  }

  getAgentRequest(requestId: string): RuntimeResult {
    const custodyHold = this.custodyHold("drawbridge.runtime.get_agent_request");
    if (custodyHold) return custodyHold;
    const found = this.options.store.findAgentRequest(requestId);
    if (!found?.pending) return result("drawbridge.runtime.get_agent_request", false, ["pending_request_not_registered"]);
    try {
      const request = this.options.exchange.readRequest(requestId);
      if (request.tenantRef !== found.session.tenantRef
        || request.sessionRef !== found.session.sessionRef
        || request.sequence !== found.pending.sequence
        || durableCommitment(this.durableCommitmentKey, "prompt", request.promptSha256) !== found.pending.promptCommitment
        || request.regionEvidenceSha256 !== found.pending.regionEvidenceSha256
        || request.regionEvidenceExpiresAtMs !== found.pending.regionEvidenceExpiresAtMs) {
        return result("drawbridge.runtime.get_agent_request", false, ["agent_request_binding_mismatch"]);
      }
      return {
        ...result("drawbridge.runtime.get_agent_request", true, []),
        actions: ["returned_authenticated_transient_agent_request"],
        metrics: {
          model_provider_network_calls: 0,
          attestation_callback_transport_measured: false,
          durable_session_contains_raw_prompt_or_response: false,
          raw_exchange_plaintext_pending: true,
          raw_payload_transiently_returned_to_authenticated_agent: true,
          raw_exchange_retention_enforcement: "ACTIVE_RUNTIME_TIMER_OR_NEXT_RUNTIME_SWEEP",
        },
        request,
      };
    } catch {
      return result("drawbridge.runtime.get_agent_request", false, ["agent_request_contract_invalid"]);
    }
  }

  sessionStatus(sessionRef: string, sessionCapability: string): RuntimeResult {
    const custodyHold = this.custodyHold("drawbridge.runtime.session_status");
    if (custodyHold) return custodyHold;
    if (!sessionCapability) return result("drawbridge.runtime.session_status", false, ["session_capability_required"]);
    try {
      const state = this.options.store.loadSession(sessionRef, sessionCapability);
      const orderedPending = [...state.pending].sort((left, right) => left.sequence - right.sequence);
      return {
        ...result("drawbridge.runtime.session_status", true, []),
        actions: ["returned_redacted_session_status"],
        sessionRef: state.sessionRef,
        nextSequence: state.nextSequence,
        pending: orderedPending.map(({ requestId, sequence, regionEvidenceSha256 }) => ({
          requestId, sequence, regionEvidenceSha256, status: "PENDING_AGENT_RESPONSE",
        })),
        actionablePendingRequestId: orderedPending[0]?.requestId ?? null,
        receipts: state.receipts.map(({ requestId, sequence, receiptReference, assessment, provider, regionEvidenceSha256, attestationReference }) => ({
          requestId, sequence, receiptReference, assessment, provider, regionEvidenceSha256, attestationReference,
        })),
        syntheticDemoOnly: true,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return result("drawbridge.runtime.session_status", false, [message === "session_capability_invalid" ? message : "session_not_found"]);
    }
  }

  eraseSession(sessionRef: string, sessionCapability: string): RuntimeResult {
    const custodyHold = this.custodyHold("drawbridge.runtime.erase_session");
    if (custodyHold) return custodyHold;
    if (!sessionCapability) return result("drawbridge.runtime.erase_session", false, ["session_capability_required"]);
    let erased;
    try { erased = this.options.store.eraseSession(sessionRef, sessionCapability); }
    catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return result("drawbridge.runtime.erase_session", false, [message === "session_capability_invalid" ? message : "session_not_found"]);
    }
    if (erased) for (const pending of erased.pending) this.options.exchange.erase(pending.requestId);
    return erased
      ? {
        ...result("drawbridge.runtime.erase_session", true, []),
        actions: ["erased_pending_raw_exchange", "erased_redacted_session_state"],
      }
      : result("drawbridge.runtime.erase_session", false, ["session_not_found"]);
  }

  listRegions(): RuntimeResult {
    const custodyHold = this.custodyHold("drawbridge.runtime.list_regions");
    if (custodyHold) return custodyHold;
    return {
      ...result("drawbridge.runtime.list_regions", true, []),
      actions: ["returned_frozen_synthetic_region_registry"],
      regions: this.options.regions.list().map(({ scenarioId, evidenceSource, fixtureSha256, syntheticDemoOnly }) => ({
        scenarioId, evidenceSource, fixtureSha256, syntheticDemoOnly,
      })),
      syntheticDemoOnly: true,
    };
  }

  completeTurn(requestId: string, sessionCapability: string): RuntimeResult & {
    response?: string;
    assessment?: ShadowAssessment;
    receiptReference?: string;
    attestationReference?: string | null;
  } {
    const custodyHold = this.custodyHold("drawbridge.runtime.complete_turn");
    if (custodyHold) return custodyHold;
    if (!sessionCapability) return result("drawbridge.runtime.complete_turn", false, ["session_capability_required"]);
    let found;
    try { found = this.options.store.findRequest(requestId, sessionCapability); }
    catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return result("drawbridge.runtime.complete_turn", false, [message === "session_capability_invalid" ? message : "request_not_registered"]);
    }
    if (!found) return result("drawbridge.runtime.complete_turn", false, ["request_not_registered"]);
    if (found.receipt) {
      const erased = this.options.exchange.erase(requestId);
      return {
        ...result("drawbridge.runtime.complete_turn", true, []),
        actions: ["duplicate_completion_noop", ...(erased ? ["erased_recovered_raw_exchange"] : [])],
        receiptReference: found.receipt.receiptReference,
        assessment: found.receipt.assessment,
      };
    }
    if (!found.pending) return result("drawbridge.runtime.complete_turn", false, ["pending_request_not_found"]);
    const preConsumeHolds: string[] = [];
    const beforeConsume = this.now();
    if (beforeConsume > found.pending.requestExpiresAtMs) preConsumeHolds.push("request_expired");
    if (beforeConsume > found.pending.regionEvidenceExpiresAtMs) preConsumeHolds.push("region_evidence_expired");
    if (preConsumeHolds.length) {
      try { this.options.store.abandonThrough(found.session.sessionRef, requestId, sessionCapability); }
      catch (error) {
        return result("drawbridge.runtime.complete_turn", false, [...preConsumeHolds, "session_state_commit_failed"], {
          errors: [error instanceof Error ? error.message : String(error)],
        });
      }
      this.options.exchange.erase(requestId);
      return result("drawbridge.runtime.complete_turn", false, preConsumeHolds, {
        actions: ["erased_expired_raw_exchange", "retired_expired_pending_turn"],
      });
    }
    let exchange;
    try { exchange = this.options.exchange.consume(requestId); }
    catch (error) {
      const hold = error instanceof Error && error.message === "request_expired" ? "request_expired" : "agent_response_contract_invalid";
      if (hold === "request_expired") {
        try { this.options.store.abandonThrough(found.session.sessionRef, requestId, sessionCapability); }
        catch (commitError) {
          return result("drawbridge.runtime.complete_turn", false, [hold, "session_state_commit_failed"], {
            errors: [commitError instanceof Error ? commitError.message : String(commitError)],
          });
        }
        return result("drawbridge.runtime.complete_turn", false, [hold], {
          actions: ["erased_expired_raw_exchange", "retired_expired_pending_turn"],
        });
      }
      return result("drawbridge.runtime.complete_turn", false, [hold]);
    }
    if (!exchange) return result("drawbridge.runtime.complete_turn", false, ["agent_response_pending"]);
    if (exchange.request.tenantRef !== found.session.tenantRef
      || exchange.request.sessionRef !== found.session.sessionRef
      || exchange.request.sequence !== found.pending.sequence
      || durableCommitment(this.durableCommitmentKey, "prompt", exchange.request.promptSha256) !== found.pending.promptCommitment
      || exchange.request.regionEvidenceSha256 !== found.pending.regionEvidenceSha256
      || exchange.request.regionEvidenceExpiresAtMs !== found.pending.regionEvidenceExpiresAtMs) {
      return result("drawbridge.runtime.complete_turn", false, ["agent_request_binding_mismatch"]);
    }
    if (this.now() > found.pending.regionEvidenceExpiresAtMs) {
      try { this.options.store.abandonThrough(found.session.sessionRef, requestId, sessionCapability); }
      catch (error) {
        return result("drawbridge.runtime.complete_turn", false, ["region_evidence_expired", "session_state_commit_failed"], {
          errors: [error instanceof Error ? error.message : String(error)],
        });
      }
      this.options.exchange.erase(requestId);
      return result("drawbridge.runtime.complete_turn", false, ["region_evidence_expired"], {
        actions: ["erased_expired_raw_exchange", "reset_observation_history_through_expired_turn"],
      });
    }

    let attestationReference: string | null = null;
    if (this.options.attestor) {
      try {
        const digest = attestationPayloadDigest(requestId, exchange.request.promptSha256, exchange.response.responseSha256);
        attestationReference = attestationContentAddress(this.options.attestor(digest));
      } catch (error) {
        const hold = error instanceof Error && error.message === "attestation_output_invalid"
          ? "attestation_output_invalid"
          : "attestation_failed";
        return result("drawbridge.runtime.complete_turn", false, [hold]);
      }
    }

    const observer = new ShadowExtractionObserver(this.options.observerConfig, this.now);
    let observed;
    const replayFloor = this.now() - observer.config.ttlMs;
    const replayCeiling = Math.max(0, observer.config.maxWindow - 1);
    const replayable = found.session.receipts
      .filter((receipt) => receipt.completedAtMs > replayFloor)
      .sort((left, right) => left.sequence - right.sequence)
      .slice(-replayCeiling);
    for (const prior of replayable) observed = observer.observe(prior.observation);
    observed = observer.observe(found.pending.observation);
    observer.close();
    if (!observed.ok || !observed.assessment) return result("drawbridge.runtime.complete_turn", false, ["shadow_observer_failed"], { observer: observed });

    const commitAtMs = this.now();
    const postAttestationHolds: string[] = [];
    if (commitAtMs > found.pending.requestExpiresAtMs) postAttestationHolds.push("request_expired_after_attestation");
    if (commitAtMs > found.pending.regionEvidenceExpiresAtMs) postAttestationHolds.push("region_evidence_expired_after_attestation");
    if (postAttestationHolds.length) {
      try { this.options.store.abandonThrough(found.session.sessionRef, requestId, sessionCapability); }
      catch (error) {
        return result("drawbridge.runtime.complete_turn", false, [...postAttestationHolds, "session_state_commit_failed"], {
          errors: [error instanceof Error ? error.message : String(error)],
        });
      }
      this.options.exchange.erase(requestId);
      return result("drawbridge.runtime.complete_turn", false, postAttestationHolds, {
        actions: ["erased_expired_raw_exchange", "retired_expired_pending_turn_after_attestation"],
      });
    }
    let refreshed;
    try { refreshed = this.options.store.findRequest(requestId, sessionCapability); }
    catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return result("drawbridge.runtime.complete_turn", false, [
        message === "session_capability_invalid" ? message : "request_state_changed_after_attestation",
      ]);
    }
    if (!refreshed?.pending || refreshed.session.sessionRef !== found.session.sessionRef
      || refreshed.session.tenantRef !== found.session.tenantRef
      || refreshed.session.generation !== found.session.generation
      || refreshed.session.capabilityNonce !== found.session.capabilityNonce
      || refreshed.pending.sequence !== found.pending.sequence
      || refreshed.pending.promptCommitment !== found.pending.promptCommitment
      || refreshed.pending.regionEvidenceSha256 !== found.pending.regionEvidenceSha256
      || refreshed.pending.regionEvidenceExpiresAtMs !== found.pending.regionEvidenceExpiresAtMs
      || refreshed.pending.requestExpiresAtMs !== found.pending.requestExpiresAtMs
      || refreshed.pending.createdAtMs !== found.pending.createdAtMs
      || JSON.stringify(refreshed.pending.observation) !== JSON.stringify(found.pending.observation)
      || !this.options.exchange.has(requestId)) {
      return result("drawbridge.runtime.complete_turn", false, ["request_state_changed_after_attestation"]);
    }

    const receiptBody = {
      schema: "tfb.drawbridge.runtime_turn_receipt.v2" as const,
      requestId,
      sequence: found.pending.sequence,
      promptCommitment: found.pending.promptCommitment,
      responseCommitment: durableCommitment(this.durableCommitmentKey, "response", exchange.response.responseSha256),
      outputFingerprint: outputFingerprint(this.durableCommitmentKey, exchange.response.response),
      provider: CHATGPT_AGENT_PROVIDER,
      regionEvidenceSha256: found.pending.regionEvidenceSha256,
      observation: found.pending.observation,
      assessment: observed.assessment,
      attestationReference,
      authority: OBSERVE_ONLY_AUTHORITY,
      completedAtMs: commitAtMs,
    };
    const receiptReference = sha256(JSON.stringify(receiptBody));
    const receipt: DurableTurnReceipt = { ...receiptBody, receiptReference };
    try { this.options.store.complete(found.session.sessionRef, requestId, receipt, sessionCapability, commitAtMs); }
    catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message === "request_expired_before_commit" || message === "region_evidence_expired_before_commit") {
        const expiryHold = message === "request_expired_before_commit"
          ? "request_expired_after_attestation"
          : "region_evidence_expired_after_attestation";
        try { this.options.store.abandonThrough(found.session.sessionRef, requestId, sessionCapability); }
        catch (retirementError) {
          const retirementMessage = retirementError instanceof Error ? retirementError.message : String(retirementError);
          if (retirementMessage === "session_capability_invalid") {
            return result("drawbridge.runtime.complete_turn", false, [retirementMessage], { errors: [message, retirementMessage] });
          }
          return result("drawbridge.runtime.complete_turn", false, [expiryHold, "session_state_commit_failed"], {
            errors: [message, retirementMessage],
          });
        }
        this.options.exchange.erase(requestId);
        return result("drawbridge.runtime.complete_turn", false, [expiryHold], { errors: [message] });
      }
      if (message === "session_capability_invalid") {
        return result("drawbridge.runtime.complete_turn", false, [message], { errors: [message] });
      }
      return result("drawbridge.runtime.complete_turn", false, ["session_state_commit_failed"], { errors: [message] });
    }
    const erased = this.options.exchange.erase(requestId);
    return {
      ...result("drawbridge.runtime.complete_turn", true, []),
      actions: [
        "consumed_agent_response",
        "evaluated_authoritative_shadow_observer",
        "committed_redacted_turn_receipt",
        erased ? "erased_raw_exchange" : "raw_exchange_already_absent",
      ],
      metrics: {
        model_provider_network_calls: 0,
        attestation_callback_transport_measured: false,
        durable_session_contains_raw_prompt_or_response: false,
        raw_exchange_plaintext_pending_for_request: false,
        raw_exchange_retention_enforcement: "ACTIVE_RUNTIME_TIMER_OR_NEXT_RUNTIME_SWEEP",
      },
      response: exchange.response.response,
      assessment: observed.assessment,
      receiptReference,
      attestationReference,
      syntheticDemoOnly: true,
    };
  }
}
