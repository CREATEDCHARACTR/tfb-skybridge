import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  rmSync,
  unlinkSync,
  writeFileSync,
  type Stats,
} from "node:fs";
import { basename, join, parse, resolve } from "node:path";
import {
  assertWellFormedUnicode,
  CHATGPT_AGENT_PROVIDER,
  isWellFormedUnicode,
  MAX_AGENT_RESPONSE_BYTES,
  OBSERVE_ONLY_AUTHORITY,
  type AgentRequest,
  type AgentResponse,
  type AgentResponseInput,
  type RuntimeResult,
} from "./types";

const SHA256 = /^[0-9a-f]{64}$/;
const NONCE = /^[0-9a-f]{32}$/;
const REQUEST_KEYS = [
  "createdAtMs", "expiresAtMs", "nonce", "prompt", "promptSha256", "provider",
  "regionEvidenceExpiresAtMs", "regionEvidenceSha256", "requestId", "scenarioId", "schema", "sequence", "sessionRef", "tenantRef",
].sort();
const RESPONSE_KEYS = ["createdAtMs", "provider", "requestId", "response", "responseSha256", "schema"].sort();
const OWNED_TEMPORARY = /^\.([0-9a-f]{64})\.(request|response)\.json\.([1-9][0-9]*)\.([0-9a-f]{12})\.tmp$/;
const MAX_TIMER_DELAY_MS = 2_147_000_000;

export interface ExchangeBinding {
  requestId: string;
  tenantRef: string;
  sessionRef: string;
  sequence: number;
  promptSha256: string;
  regionEvidenceSha256: string;
  regionEvidenceExpiresAtMs: number;
  requestExpiresAtMs: number;
  responsePresent: boolean;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function canonical(value: Record<string, unknown>): string {
  return JSON.stringify(Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b))));
}

function exactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  return JSON.stringify(Object.keys(value).sort()) === JSON.stringify(expected);
}

function isSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function requestEnvelope(value: AgentRequest): Omit<AgentRequest, "prompt" | "requestId"> {
  const { prompt: _prompt, requestId: _requestId, ...envelope } = value;
  return envelope;
}

function assertRequest(value: unknown, expectedId?: string): asserts value is AgentRequest {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("agent_request_contract_invalid");
  const object = value as Record<string, unknown>;
  if (!exactKeys(object, REQUEST_KEYS)
    || object.schema !== "tfb.drawbridge.agent_request.v1"
    || object.provider !== CHATGPT_AGENT_PROVIDER
    || typeof object.requestId !== "string" || !SHA256.test(object.requestId)
    || (expectedId !== undefined && object.requestId !== expectedId)
    || typeof object.tenantRef !== "string" || !SHA256.test(object.tenantRef)
    || typeof object.sessionRef !== "string" || !SHA256.test(object.sessionRef)
    || !Number.isSafeInteger(object.sequence) || (object.sequence as number) < 1
    || typeof object.prompt !== "string" || !isWellFormedUnicode(object.prompt)
    || object.prompt.length < 1 || Buffer.byteLength(object.prompt) > 65_536
    || typeof object.promptSha256 !== "string" || !SHA256.test(object.promptSha256)
    || typeof object.scenarioId !== "string" || !/^[a-z0-9._-]{1,128}$/i.test(object.scenarioId)
    || typeof object.regionEvidenceSha256 !== "string" || !SHA256.test(object.regionEvidenceSha256)
    || !isSafeInteger(object.regionEvidenceExpiresAtMs) || (object.regionEvidenceExpiresAtMs as number) <= (object.createdAtMs as number)
    || !isSafeInteger(object.createdAtMs) || !isSafeInteger(object.expiresAtMs)
    || (object.expiresAtMs as number) <= (object.createdAtMs as number)
    || typeof object.nonce !== "string" || !NONCE.test(object.nonce)) {
    throw new Error("agent_request_contract_invalid");
  }
  const request = object as unknown as AgentRequest;
  if (sha256(request.prompt) !== request.promptSha256
    || sha256(canonical(requestEnvelope(request))) !== request.requestId) {
    throw new Error("request_content_address_mismatch");
  }
}

function assertResponse(value: unknown, expectedId?: string): asserts value is AgentResponse {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("agent_response_contract_invalid");
  const object = value as Record<string, unknown>;
  if (!exactKeys(object, RESPONSE_KEYS)
    || object.schema !== "tfb.drawbridge.agent_response.v1"
    || object.provider !== CHATGPT_AGENT_PROVIDER
    || typeof object.requestId !== "string" || !SHA256.test(object.requestId)
    || (expectedId !== undefined && object.requestId !== expectedId)
    || typeof object.response !== "string" || !isWellFormedUnicode(object.response) || Buffer.byteLength(object.response) > MAX_AGENT_RESPONSE_BYTES
    || typeof object.responseSha256 !== "string" || !SHA256.test(object.responseSha256)
    || !isSafeInteger(object.createdAtMs)) {
    throw new Error("agent_response_contract_invalid");
  }
  if (sha256(object.response as string) !== object.responseSha256) throw new Error("agent_response_contract_invalid");
}

function baseResult(op: string, ok: boolean, holds: string[], extra: Record<string, unknown> = {}): RuntimeResult {
  return {
    op,
    ok,
    actions: ok ? ["validated_content_addressed_agent_exchange"] : [],
    skips: ["model_provider_network_not_called", "local_model_not_called", "policy_action_not_evaluated"],
    errors: [],
    holds,
    metrics: {
      model_provider_network_calls: 0,
      raw_exchange_retention_enforcement: "ACTIVE_RUNTIME_TIMER_OR_NEXT_RUNTIME_SWEEP",
    },
    next: ok ? "Continue through the Drawbridge controller." : "Heal every named exchange hold before consuming the response.",
    authority: OBSERVE_ONLY_AUTHORITY,
    ...extra,
  };
}

function ensureCustodyRoot(root: string, createMissing: boolean): void {
  const absolute = resolve(root);
  const rootPath = parse(absolute).root;
  let current = rootPath;
  let createdFinal = false;
  for (const segment of absolute.slice(rootPath.length).split("/").filter(Boolean)) {
    current = join(current, segment);
    if (existsSync(current)) {
      const status = lstatSync(current);
      if (status.isSymbolicLink()) {
        throw new Error(current === absolute ? "exchange_root_symlink_forbidden" : "exchange_ancestor_symlink_forbidden");
      }
      if (!status.isDirectory()) throw new Error(current === absolute ? "exchange_root_not_directory" : "exchange_ancestor_not_directory");
      if (current === absolute) {
        const uid = process.getuid?.();
        if (uid !== undefined && status.uid !== uid) throw new Error("exchange_root_owner_required");
        if ((status.mode & 0o777) !== 0o700) throw new Error("exchange_root_mode_0700_required");
      }
    } else {
      if (!createMissing) throw new Error("exchange_root_missing");
      mkdirSync(current, { mode: 0o700 });
      if (current === absolute) createdFinal = true;
    }
  }
  if (createdFinal) chmodSync(root, 0o700);
}

export class ExternalAgentExchange {
  private readonly now: () => number;
  private readonly ttlMs: number;
  private readonly expiryTimers = new Map<string, ReturnType<typeof setTimeout>>();
  private readonly rootIdentity: Pick<Stats, "dev" | "ino">;
  private crashRecoveries = { invalidRequests: 0, orphanResponses: 0, crashTemporaries: 0 };

  constructor(readonly root: string, options: { now?: () => number; ttlMs?: number } = {}) {
    this.now = options.now ?? Date.now;
    this.ttlMs = options.ttlMs ?? 300_000;
    if (!Number.isInteger(this.ttlMs) || this.ttlMs < 1 || this.ttlMs > 3_600_000) throw new Error("agent_exchange_ttl_out_of_range");
    ensureCustodyRoot(root, true);
    const rootStatus = lstatSync(root);
    this.rootIdentity = { dev: rootStatus.dev, ino: rootStatus.ino };
    this.sweepExpired();
  }

  private assertRootIdentity(): void {
    ensureCustodyRoot(this.root, false);
    const current = lstatSync(this.root);
    if (current.dev !== this.rootIdentity.dev || current.ino !== this.rootIdentity.ino) {
      throw new Error("exchange_root_identity_changed");
    }
  }

  private requestPath(id: string): string { this.assertRootIdentity(); return join(this.root, `${id}.request.json`); }
  private responsePath(id: string): string { this.assertRootIdentity(); return join(this.root, `${id}.response.json`); }

  private fsyncRoot(): void {
    this.assertRootIdentity();
    const directory = openSync(this.root, constants.O_RDONLY);
    try { fsyncSync(directory); } finally { closeSync(directory); }
  }

  private processAlive(pid: number): boolean {
    try { process.kill(pid, 0); return true; }
    catch (error) { return (error as NodeJS.ErrnoException).code === "EPERM"; }
  }

  private scheduleExpiry(request: AgentRequest): void {
    const existing = this.expiryTimers.get(request.requestId);
    if (existing) clearTimeout(existing);
    const remaining = Math.max(1, request.expiresAtMs - this.now() + 1);
    const timer = setTimeout(() => {
      this.expiryTimers.delete(request.requestId);
      try {
        if (this.now() > request.expiresAtMs) this.erase(request.requestId);
        else this.scheduleExpiry(request);
      } catch {
        // The owner may have closed and removed its temporary demo root.
      }
    }, Math.min(remaining, MAX_TIMER_DELAY_MS));
    timer.unref();
    this.expiryTimers.set(request.requestId, timer);
  }

  private readCustodied(path: string): string {
    this.assertRootIdentity();
    const status = lstatSync(path);
    if (status.isSymbolicLink()) throw new Error("exchange_file_symlink_forbidden");
    if (!status.isFile()) throw new Error("exchange_file_not_regular");
    let descriptor: number;
    try { descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ELOOP") throw new Error("exchange_file_symlink_forbidden");
      throw error;
    }
    try {
      if (!fstatSync(descriptor).isFile()) throw new Error("exchange_file_not_regular");
      return readFileSync(descriptor, "utf8");
    } finally { closeSync(descriptor); }
  }

  private exclusiveWrite(path: string, value: unknown): "created" | "exists" {
    this.assertRootIdentity();
    const temporary = join(this.root, `.${basename(path)}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`);
    try {
      const descriptor = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      try {
        writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`, "utf8");
        fsyncSync(descriptor);
      } finally { closeSync(descriptor); }
      try {
        linkSync(temporary, path);
        this.fsyncRoot();
        return "created";
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST") return "exists";
        throw error;
      }
    } finally {
      if (existsSync(temporary)) {
        unlinkSync(temporary);
        this.fsyncRoot();
      }
    }
  }

  createRequest(input: {
    tenantRef: string;
    sessionRef: string;
    sequence: number;
    prompt: string;
    scenarioId: string;
    regionEvidenceSha256: string;
    regionEvidenceExpiresAtMs: number;
  }): AgentRequest {
    assertWellFormedUnicode(input.prompt);
    assertWellFormedUnicode(input.scenarioId);
    const createdAtMs = this.now();
    const promptSha256 = sha256(input.prompt);
    const envelope = {
      schema: "tfb.drawbridge.agent_request.v1",
      provider: CHATGPT_AGENT_PROVIDER,
      tenantRef: input.tenantRef,
      sessionRef: input.sessionRef,
      sequence: input.sequence,
      promptSha256,
      scenarioId: input.scenarioId,
      regionEvidenceSha256: input.regionEvidenceSha256,
      regionEvidenceExpiresAtMs: input.regionEvidenceExpiresAtMs,
      createdAtMs,
      expiresAtMs: createdAtMs + this.ttlMs,
      nonce: randomBytes(16).toString("hex"),
    } as const;
    const requestId = sha256(canonical(envelope));
    const request: AgentRequest = { ...envelope, requestId, prompt: input.prompt };
    assertRequest(request, requestId);
    if (this.exclusiveWrite(this.requestPath(requestId), request) !== "created") throw new Error("request_id_collision");
    this.scheduleExpiry(request);
    return request;
  }

  readRequest(requestId: string): AgentRequest {
    if (!SHA256.test(requestId)) throw new Error("request_id_invalid");
    const value = JSON.parse(this.readCustodied(this.requestPath(requestId))) as unknown;
    assertRequest(value, requestId);
    return value;
  }

  submitResponse(input: AgentResponseInput): RuntimeResult {
    if (![input.requestId, input.provider, input.response, input.responseSha256].every((value) => isWellFormedUnicode(value))) {
      return baseResult("drawbridge.exchange.submit_response", false, ["text_not_well_formed"]);
    }
    const holds: string[] = [];
    if (input.provider !== CHATGPT_AGENT_PROVIDER) holds.push("provider_not_allowed");
    if (!SHA256.test(input.requestId) || !existsSync(this.requestPath(input.requestId))) holds.push("request_not_found");
    if (Buffer.byteLength(input.response) > MAX_AGENT_RESPONSE_BYTES) holds.push("response_too_large");
    if (!SHA256.test(input.responseSha256) || sha256(input.response) !== input.responseSha256) holds.push("response_sha256_mismatch");
    let request: AgentRequest | undefined;
    if (!holds.includes("request_not_found")) {
      try { request = this.readRequest(input.requestId); } catch { holds.push("request_content_address_mismatch"); }
    }
    if (request && this.now() > request.expiresAtMs) {
      holds.push("request_expired");
      this.erase(input.requestId);
    }
    if (holds.length) return baseResult("drawbridge.runtime.submit_agent_response", false, [...new Set(holds)], { requestId: input.requestId });

    const response: AgentResponse = {
      schema: "tfb.drawbridge.agent_response.v1",
      requestId: input.requestId,
      provider: CHATGPT_AGENT_PROVIDER,
      response: input.response,
      responseSha256: input.responseSha256,
      createdAtMs: this.now(),
    };
    assertResponse(response, input.requestId);
    const path = this.responsePath(input.requestId);
    if (this.exclusiveWrite(path, response) === "created") {
      return baseResult("drawbridge.runtime.submit_agent_response", true, [], {
        requestId: input.requestId,
        responseSha256: input.responseSha256,
        provider: CHATGPT_AGENT_PROVIDER,
        metrics: {
          model_provider_network_calls: 0,
          raw_exchange_plaintext_pending: true,
          raw_exchange_retention_enforcement: "ACTIVE_RUNTIME_TIMER_OR_NEXT_RUNTIME_SWEEP",
        },
      });
    }
    try {
      const existing = JSON.parse(this.readCustodied(path)) as unknown;
      assertResponse(existing, input.requestId);
      if (existing.provider === input.provider && existing.responseSha256 === input.responseSha256 && existing.response === input.response) {
        return baseResult("drawbridge.runtime.submit_agent_response", true, [], {
          actions: ["duplicate_response_noop"],
          requestId: input.requestId,
          responseSha256: input.responseSha256,
          provider: CHATGPT_AGENT_PROVIDER,
          metrics: {
            model_provider_network_calls: 0,
            raw_exchange_plaintext_pending: true,
            raw_exchange_retention_enforcement: "ACTIVE_RUNTIME_TIMER_OR_NEXT_RUNTIME_SWEEP",
          },
        });
      }
    } catch {
      return baseResult("drawbridge.runtime.submit_agent_response", false, ["response_conflict", "existing_response_contract_invalid"], { requestId: input.requestId });
    }
    return baseResult("drawbridge.runtime.submit_agent_response", false, ["response_conflict"], { requestId: input.requestId });
  }

  consume(requestId: string): { request: AgentRequest; response: AgentResponse } | undefined {
    if (!existsSync(this.requestPath(requestId)) || !existsSync(this.responsePath(requestId))) return undefined;
    const request = this.readRequest(requestId);
    if (this.now() > request.expiresAtMs) {
      this.erase(requestId);
      throw new Error("request_expired");
    }
    const response = JSON.parse(this.readCustodied(this.responsePath(requestId))) as unknown;
    assertResponse(response, requestId);
    return { request, response };
  }

  has(requestId: string): boolean {
    return existsSync(this.requestPath(requestId)) || existsSync(this.responsePath(requestId));
  }

  erase(requestId: string): boolean {
    if (!SHA256.test(requestId)) return false;
    const timer = this.expiryTimers.get(requestId);
    if (timer) clearTimeout(timer);
    this.expiryTimers.delete(requestId);
    const existed = this.has(requestId);
    rmSync(this.requestPath(requestId), { force: true });
    rmSync(this.responsePath(requestId), { force: true });
    if (existed) this.fsyncRoot();
    return existed;
  }

  sweepExpired(): RuntimeResult {
    this.assertRootIdentity();
    ensureCustodyRoot(this.root, false);
    let expired = 0;
    let invalid = 0;
    let orphanResponses = 0;
    let crashTemporaries = 0;
    let liveTemporaries = 0;
    for (const name of readdirSync(this.root)) {
      const temporary = OWNED_TEMPORARY.exec(name);
      if (!temporary) continue;
      if (this.processAlive(Number(temporary[3]))) {
        liveTemporaries++;
        continue;
      }
      const path = join(this.root, name);
      const status = lstatSync(path);
      const uid = process.getuid?.();
      if (status.isSymbolicLink() || !status.isFile()
        || (uid !== undefined && status.uid !== uid) || (status.mode & 0o777) !== 0o600
        || status.nlink !== 1) {
        throw new Error("exchange_temporary_file_unsafe");
      }
      unlinkSync(path);
      crashTemporaries++;
    }
    for (const name of readdirSync(this.root)) {
      const requestMatch = /^([0-9a-f]{64})\.request\.json$/.exec(name);
      if (!requestMatch) continue;
      const requestId = requestMatch[1];
      try {
        const request = this.readRequest(requestId);
        if (this.now() > request.expiresAtMs) {
          if (this.erase(requestId)) expired++;
        } else this.scheduleExpiry(request);
      } catch {
        this.erase(requestId);
        invalid++;
      }
    }
    for (const name of readdirSync(this.root)) {
      const responseMatch = /^([0-9a-f]{64})\.response\.json$/.exec(name);
      if (responseMatch && !existsSync(this.requestPath(responseMatch[1]))) {
        rmSync(this.responsePath(responseMatch[1]), { force: true });
        orphanResponses++;
      }
    }
    if (orphanResponses || crashTemporaries) this.fsyncRoot();
    this.crashRecoveries.invalidRequests += invalid;
    this.crashRecoveries.orphanResponses += orphanResponses;
    this.crashRecoveries.crashTemporaries += crashTemporaries;
    return baseResult("drawbridge.runtime.sweep_agent_exchange", true, [], {
      actions: expired || invalid || orphanResponses || crashTemporaries ? ["erased_expired_invalid_or_crash_raw_exchange"] : [],
      metrics: {
        expired_requests_erased: expired,
        invalid_requests_erased: invalid,
        orphan_responses_erased: orphanResponses,
        crash_temporaries_erased: crashTemporaries,
        live_temporaries_preserved: liveTemporaries,
        model_provider_network_calls: 0,
        raw_exchange_retention_enforcement: "ACTIVE_RUNTIME_TIMER_OR_NEXT_RUNTIME_SWEEP",
      },
    });
  }

  drainCrashRecoveries(): { invalidRequests: number; orphanResponses: number; crashTemporaries: number } {
    const recovered = { ...this.crashRecoveries };
    this.crashRecoveries = { invalidRequests: 0, orphanResponses: 0, crashTemporaries: 0 };
    return recovered;
  }

  pendingIds(): string[] {
    this.assertRootIdentity();
    ensureCustodyRoot(this.root, false);
    const ids: string[] = [];
    for (const name of readdirSync(this.root)) {
      const match = /^([0-9a-f]{64})\.request\.json$/.exec(name);
      if (!match) continue;
      const status = lstatSync(join(this.root, name));
      if (status.isSymbolicLink()) throw new Error("exchange_file_symlink_forbidden");
      if (!status.isFile()) throw new Error("exchange_file_not_regular");
      ids.push(match[1]);
    }
    return ids.sort();
  }

  bindingInventory(): ExchangeBinding[] {
    this.assertRootIdentity();
    return this.pendingIds().map((requestId) => {
      const request = this.readRequest(requestId);
      let responsePresent = false;
      if (existsSync(this.responsePath(requestId))) {
        const response = JSON.parse(this.readCustodied(this.responsePath(requestId))) as unknown;
        assertResponse(response, requestId);
        responsePresent = true;
      }
      return {
        requestId,
        tenantRef: request.tenantRef,
        sessionRef: request.sessionRef,
        sequence: request.sequence,
        promptSha256: request.promptSha256,
        regionEvidenceSha256: request.regionEvidenceSha256,
        regionEvidenceExpiresAtMs: request.regionEvidenceExpiresAtMs,
        requestExpiresAtMs: request.expiresAtMs,
        responsePresent,
      };
    });
  }

  audit(): { pendingRawRequests: number; rawResponseFiles: number } {
    this.assertRootIdentity();
    ensureCustodyRoot(this.root, false);
    this.sweepExpired();
    const names = readdirSync(this.root);
    if (names.some((name) => !/^[0-9a-f]{64}\.(request|response)\.json$/.test(name))) {
      throw new Error("exchange_unexpected_file");
    }
    for (const requestId of this.pendingIds()) {
      if (existsSync(this.responsePath(requestId))) this.consume(requestId);
    }
    return {
      pendingRawRequests: this.pendingIds().length,
      rawResponseFiles: names.filter((name) => /^[0-9a-f]{64}\.response\.json$/.test(name)).length,
    };
  }

  close(): void {
    for (const timer of this.expiryTimers.values()) clearTimeout(timer);
    this.expiryTimers.clear();
  }
}
