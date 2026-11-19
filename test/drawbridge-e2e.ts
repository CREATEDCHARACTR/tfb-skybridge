import { chmodSync, existsSync, linkSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, realpathSync, renameSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { DrawbridgeRuntimeController } from "../src/drawbridge-runtime/controller";
import { ExternalAgentExchange } from "../src/drawbridge-runtime/exchange";
import { FrozenRegionEvidenceRegistry } from "../src/drawbridge-runtime/region";
import { RedactedSessionStore } from "../src/drawbridge-runtime/store";
import { renderDrawbridgeConsole } from "../src/drawbridge-runtime/ui";
import { createDrawbridgeHttpServer, dispatchDrawbridgeHttp, isExactJsonMediaType, parseStrictJson, requestLoopbackJson } from "../src/drawbridge-runtime/server";
import { createDrawbridgeRuntime } from "../src/drawbridge-runtime/bootstrap";
import { parseAndValidateDrawbridgeArguments, runDrawbridgeCli } from "../src/drawbridge-runtime/cli";
import { MAX_AGENT_RESPONSE_BYTES, OBSERVE_ONLY_AUTHORITY, type RuntimeResult } from "../src/drawbridge-runtime/types";

type TestCase = { name: string; run: () => void | Promise<void> };
const tests: TestCase[] = [];
const test = (name: string, run: TestCase["run"]) => tests.push({ name, run });
const assert: (value: unknown, message: string) => asserts value = (value, message) => { if (!value) throw new Error(message); };
const equal = (actual: unknown, expected: unknown, message: string) => {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error(`${message}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
};
const throws = (run: () => unknown, expected: string, message: string) => {
  try { run(); } catch (error) {
    assert(error instanceof Error && error.message.includes(expected), `${message}: ${error instanceof Error ? error.message : String(error)}`);
    return;
  }
  throw new Error(`${message}: did not throw`);
};
const throwsAsync = async (run: () => Promise<unknown>, expected: string, message: string) => {
  try { await run(); } catch (error) {
    assert(error instanceof Error && error.message.includes(expected), `${message}: ${error instanceof Error ? error.message : String(error)}`);
    return;
  }
  throw new Error(`${message}: did not reject`);
};

const fixtures = new FrozenRegionEvidenceRegistry({
  "demo.north": { regionLabel: "north", evidenceSource: "frozen-demo-registry-v1", syntheticDemoOnly: true },
  "demo.south": { regionLabel: "south", evidenceSource: "frozen-demo-registry-v1", syntheticDemoOnly: true },
});

function harness(options: {
  now?: () => number;
  attestor?: (payloadDigest: Buffer) => string;
  maxReceipts?: number;
  receiptTtlMs?: number;
  exchangeTtlMs?: number;
  regionEvidenceTtlMs?: number;
  staleLockMs?: number;
  maxSessions?: number;
  maxPending?: number;
  beforeStateCommit?: (lockPath: string) => void;
  beforeRecoveryRetire?: (lockPath: string) => void;
  afterRecoveryFenceCheck?: (lockPath: string) => void;
  afterRecoveryOwnerTakeover?: (ownerPath: string) => void;
  afterStateFenceCheck?: (lockPath: string) => void;
  afterStatePublish?: (lockPath: string) => void;
} = {}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "drawbridge-e2e-")));
  const now = options.now ?? (() => Date.now());
  const exchange = new ExternalAgentExchange(join(root, "exchange"), { now, ttlMs: options.exchangeTtlMs ?? 60_000 });
  const storeOptions = {
    now,
    maxReceipts: options.maxReceipts,
    receiptTtlMs: options.receiptTtlMs ?? 60_000,
    staleLockMs: options.staleLockMs,
    maxSessions: options.maxSessions,
    maxPending: options.maxPending,
    beforeStateCommit: options.beforeStateCommit,
    beforeRecoveryRetire: options.beforeRecoveryRetire,
    afterRecoveryFenceCheck: options.afterRecoveryFenceCheck,
    afterRecoveryOwnerTakeover: options.afterRecoveryOwnerTakeover,
    afterStateFenceCheck: options.afterStateFenceCheck,
    afterStatePublish: options.afterStatePublish,
  };
  const store = new RedactedSessionStore(join(root, "state"), storeOptions);
  const controller = new DrawbridgeRuntimeController({
    exchange,
    store,
    regions: fixtures,
    producerSecret: Buffer.alloc(32, 9),
    now,
    observerConfig: { hammingThreshold: 64, minGridSize: 4, minRegionCount: 2, ttlMs: 60_000 },
    regionEvidenceTtlMs: options.regionEvidenceTtlMs ?? 60_000,
    attestor: options.attestor,
  });
  return {
    root,
    exchange,
    store,
    controller,
    cleanup: () => {
      exchange.close();
      store.close();
      rmSync(root, { recursive: true, force: true });
    },
  };
}

const pause = (milliseconds: number) => new Promise<void>((resolve) => setTimeout(resolve, milliseconds));

function fulfill(exchange: ExternalAgentExchange, requestId: string, text: string) {
  const digest = createHash("sha256").update(text).digest("hex");
  return exchange.submitResponse({ requestId, provider: "chatgpt-agent-standin", response: text, responseSha256: digest });
}

test("external ChatGPT-agent exchange is content-addressed and uses no network route", () => {
  const h = harness();
  try {
    const session = h.controller.startSession("tenant-a", "session-a");
    const pending = h.controller.submitPrompt(session.sessionRef, "Inspect this bridge", "demo.north", session.sessionCapability);
    assert(pending.ok && pending.requestId, "request should be pending");
    assert(!JSON.stringify(pending).includes("Inspect this bridge"), "public result must not echo raw prompt");
    const request = h.exchange.readRequest(pending.requestId);
    equal(request.provider, "chatgpt-agent-standin", "provider contract");
    equal(request.tenantRef, h.store.loadSession(session.sessionRef, session.sessionCapability).tenantRef, "opaque tenant binding");
    equal(request.sessionRef, session.sessionRef, "opaque session binding");
    equal(request.sequence, 1, "monotonic sequence binding");
    assert(!("url" in request), "exchange must not carry a provider URL");
  } finally { h.cleanup(); }
});

test("runtime narration distinguishes bounded raw exchange from redacted durable state", () => {
  const h = harness();
  try {
    const session = h.controller.startSession("tenant-retention-truth", "session-retention-truth");
    const prompt = "pending plaintext canary";
    const pending = h.controller.submitPrompt(session.sessionRef, prompt, "demo.north", session.sessionCapability);
    assert(pending.ok && pending.requestId, "pending request admitted");
    equal(pending.metrics.raw_exchange_plaintext_pending, true, "submit narrates pending plaintext");
    equal(pending.metrics.durable_session_contains_raw_prompt_or_response, false, "durable session is redacted");
    equal(pending.metrics.raw_exchange_retention_enforcement, "ACTIVE_RUNTIME_TIMER_OR_NEXT_RUNTIME_SWEEP", "retention enforcement scope");
    assert(!("raw_payload_retained" in pending.metrics), "ambiguous false retention metric removed");
    assert(readFileSync(join(h.exchange.root, `${pending.requestId}.request.json`), "utf8").includes(prompt), "bounded exchange actually contains the narrated plaintext");

    const health = h.controller.health();
    equal(health.metrics.pendingRawRequests, 1, "health counts pending raw request files");
    equal(health.metrics.raw_exchange_plaintext_pending, true, "health narrates pending plaintext");
    equal(health.metrics.durable_session_contains_raw_prompt_or_response, false, "health narrates redacted durable state");

    fulfill(h.exchange, pending.requestId, "retention truth response");
    assert(h.controller.completeTurn(pending.requestId, session.sessionCapability).ok, "turn completes");
    const after = h.controller.health();
    equal(after.metrics.pendingRawRequests, 0, "completed raw request count is zero");
    equal(after.metrics.raw_exchange_plaintext_pending, false, "health clears plaintext-pending narration");
  } finally { h.cleanup(); }
});

test("durable state uses keyed commitments instead of public dictionary hashes", () => {
  const h = harness();
  try {
    const prompt = "yes";
    const response = "no";
    const promptSha256 = createHash("sha256").update(prompt).digest("hex");
    const responseSha256 = createHash("sha256").update(response).digest("hex");
    const publicOutputSketch = createHash("blake2b512").update(response).digest("hex").slice(0, 16);
    const session = h.controller.startSession("tenant-dictionary", "session-dictionary");
    const pending = h.controller.submitPrompt(session.sessionRef, prompt, "demo.north", session.sessionCapability);
    assert(pending.requestId, "dictionary request admitted");
    const pendingBytes = readFileSync(join(h.store.root, `${session.sessionRef}.json`), "utf8");
    assert(!pendingBytes.includes(promptSha256), "pending durable state excludes public prompt hash");
    assert(!pendingBytes.includes(`\"${prompt}\"`), "pending durable state excludes raw prompt");

    fulfill(h.exchange, pending.requestId, response);
    assert(h.controller.completeTurn(pending.requestId, session.sessionCapability).ok, "dictionary turn completes");
    const durableBytes = readFileSync(join(h.store.root, `${session.sessionRef}.json`), "utf8");
    for (const publicValue of [promptSha256, responseSha256, publicOutputSketch, `\"${prompt}\"`, `\"${response}\"`]) {
      assert(!durableBytes.includes(publicValue), `durable state excludes public dictionary linkage ${publicValue}`);
    }
    const durable = JSON.parse(durableBytes) as { schema: string; receipts: Array<Record<string, unknown>> };
    equal(durable.schema, "tfb.drawbridge.runtime_session.v2", "keyed durable session schema");
    equal(durable.receipts[0]?.schema, "tfb.drawbridge.runtime_turn_receipt.v2", "keyed durable receipt schema");
    for (const field of ["promptCommitment", "responseCommitment", "outputFingerprint"]) {
      assert(typeof durable.receipts[0]?.[field] === "string" && /^[0-9a-f]{64}$/.test(durable.receipts[0][field] as string), `${field} is keyed fixed-width evidence`);
    }
    durable.receipts[0].schema = "tfb.drawbridge.runtime_turn_receipt.v1";
    writeFileSync(join(h.store.root, `${session.sessionRef}.json`), `${JSON.stringify(durable)}\n`, { mode: 0o600 });
    throws(() => h.store.loadSession(session.sessionRef, session.sessionCapability), "session_store_contract_invalid", "legacy public-hash receipt schema fails closed");
  } finally { h.cleanup(); }
});

test("content address rejects cross-session or sequence substitution", () => {
  const h = harness();
  try {
    const first = h.controller.startSession("tenant-a", "session-a");
    const second = h.controller.startSession("tenant-a", "session-b");
    const pending = h.controller.submitPrompt(first.sessionRef, "bound request", "demo.north", first.sessionCapability);
    assert(pending.requestId, "request id");
    const requestPath = join(h.exchange.root, `${pending.requestId}.request.json`);
    const request = JSON.parse(readFileSync(requestPath, "utf8")) as Record<string, unknown>;
    request.sessionRef = second.sessionRef;
    request.sequence = 2;
    writeFileSync(requestPath, `${JSON.stringify(request)}\n`, { mode: 0o600 });
    throws(() => h.exchange.readRequest(pending.requestId as string), "request_content_address_mismatch", "substitution must fail closed");
  } finally { h.cleanup(); }
});

test("content addressing rejects malformed Unicode before hashing or replay", () => {
  const h = harness();
  try {
    const session = h.controller.startSession("tenant-unicode", "session-unicode");
    const direct = h.controller.submitPrompt(session.sessionRef, "\ud800", "demo.north", session.sessionCapability);
    assert(!direct.ok && direct.holds.includes("text_not_well_formed"), "direct lone surrogate is rejected before hashing");

    const pending = h.controller.submitPrompt(session.sessionRef, "\ufffd", "demo.north", session.sessionCapability);
    assert(pending.requestId, "well-formed replacement character request admitted");
    const requestPath = join(h.exchange.root, `${pending.requestId}.request.json`);
    const request = JSON.parse(readFileSync(requestPath, "utf8")) as Record<string, unknown>;
    request.prompt = "\ud801";
    writeFileSync(requestPath, `${JSON.stringify(request)}\n`, { mode: 0o600 });
    const replay = h.controller.getAgentRequest(pending.requestId);
    assert(!replay.ok && replay.holds.includes("agent_request_contract_invalid"), "colliding malformed substitution is rejected on read");

    const response = h.controller.submitAgentResponse({
      requestId: pending.requestId,
      provider: "chatgpt-agent-standin",
      response: "\udfff",
      responseSha256: createHash("sha256").update("\udfff").digest("hex"),
    });
    assert(!response.ok && response.holds.includes("text_not_well_formed"), "malformed response is rejected before digest comparison");
    throws(() => parseStrictJson('{"prompt":"\\ud800"}'), "json_string_not_well_formed", "HTTP JSON rejects escaped lone surrogate");
  } finally { h.cleanup(); }
});

test("missing region evidence fails closed before a raw request is written", () => {
  const h = harness();
  try {
    const session = h.controller.startSession("tenant-a", "session-a");
    const result = h.controller.submitPrompt(session.sessionRef, "unknown region", "not-registered", session.sessionCapability);
    assert(!result.ok, "unregistered region must hold");
    assert(result.holds.includes("region_evidence_not_registered"), "missing region hold");
    equal(h.exchange.pendingIds(), [], "no request should be emitted");
  } finally { h.cleanup(); }
});

test("response request, digest, provider, replay and expiry mismatches fail closed", () => {
  let now = 1000;
  const h = harness({ now: () => now });
  try {
    const session = h.controller.startSession("tenant-a", "session-a");
    const pending = h.controller.submitPrompt(session.sessionRef, "hello bridge", "demo.north", session.sessionCapability);
    assert(pending.requestId, "request id");
    const wrongDigest = h.exchange.submitResponse({ requestId: pending.requestId, provider: "chatgpt-agent-standin", response: "hello", responseSha256: "0".repeat(64) });
    assert(!wrongDigest.ok && wrongDigest.holds.includes("response_sha256_mismatch"), "digest mismatch");
    const wrongProvider = h.exchange.submitResponse({ requestId: pending.requestId, provider: "ollama", response: "hello", responseSha256: createHash("sha256").update("hello").digest("hex") });
    assert(!wrongProvider.ok && wrongProvider.holds.includes("provider_not_allowed"), "provider mismatch");
    assert(fulfill(h.exchange, pending.requestId, "hello").ok, "first response");
    const replay = fulfill(h.exchange, pending.requestId, "different");
    assert(!replay.ok && replay.holds.includes("response_conflict"), "conflicting replay");
    const expiredPending = h.controller.submitPrompt(session.sessionRef, "second", "demo.south", session.sessionCapability);
    assert(expiredPending.requestId, "second id");
    now += 60_001;
    const expired = fulfill(h.exchange, expiredPending.requestId, "late");
    assert(!expired.ok && expired.holds.includes("request_expired"), "expired request");
  } finally { h.cleanup(); }
});

test("lost acknowledgement after completion returns a content-bound idempotent response receipt", () => {
  const h = harness();
  try {
    const session = h.controller.startSession("tenant-lost-ack", "session-lost-ack");
    const pending = h.controller.submitPrompt(
      session.sessionRef, "completed response retry", "demo.north", session.sessionCapability,
    );
    assert(pending.requestId, "request id");
    const response = "exact completed response bytes";
    const responseSha256 = createHash("sha256").update(response).digest("hex");
    const input = {
      requestId: pending.requestId,
      provider: "chatgpt-agent-standin",
      response,
      responseSha256,
    };
    assert(h.controller.submitAgentResponse(input).ok, "first admission succeeds");
    assert(h.controller.completeTurn(pending.requestId, session.sessionCapability).ok, "turn completes before acknowledgement retry");

    const retry = h.controller.submitAgentResponse(input);
    assert(retry.ok && retry.actions.includes("duplicate_completed_response_noop"), "exact retry is idempotent");
    equal(retry.requestId, pending.requestId, "retry receipt binds request");
    equal(retry.responseSha256, responseSha256, "retry receipt binds response digest");
    equal(retry.provider, "chatgpt-agent-standin", "retry receipt binds provider");

    const conflict = h.controller.submitAgentResponse({
      ...input,
      response: "conflicting completed response bytes",
      responseSha256: createHash("sha256").update("conflicting completed response bytes").digest("hex"),
    });
    assert(!conflict.ok && conflict.holds.includes("completed_response_conflict"), "conflicting completed retry holds closed");
  } finally { h.cleanup(); }
});

test("response admission shares a wire-safe byte ceiling", () => {
  const h = harness();
  try {
    const session = h.controller.startSession("tenant-wire", "session-wire");
    const pending = h.controller.submitPrompt(session.sessionRef, "wire bound", "demo.north", session.sessionCapability);
    assert(pending.requestId, "request id");
    const response = "x".repeat(MAX_AGENT_RESPONSE_BYTES + 1);
    const refused = fulfill(h.exchange, pending.requestId, response);
    assert(!refused.ok && refused.holds.includes("response_too_large"), "response is refused before a completion can exceed loopback framing");
    assert(!h.exchange.has(pending.requestId) || h.exchange.pendingIds().includes(pending.requestId), "request remains recoverable without an oversized response");
  } finally { h.cleanup(); }
});

test("a response submitted in time cannot complete after request expiry", () => {
  let now = 10_000;
  const h = harness({ now: () => now });
  try {
    const session = h.controller.startSession("tenant-a", "session-a");
    const pending = h.controller.submitPrompt(session.sessionRef, "expires after response", "demo.north", session.sessionCapability);
    assert(pending.requestId, "request id");
    assert(fulfill(h.exchange, pending.requestId, "on-time response").ok, "response supplied before expiry");
    now += 60_001;
    const completed = h.controller.completeTurn(pending.requestId, session.sessionCapability);
    assert(!completed.ok && completed.holds.includes("request_expired"), "late completion must hold");
    equal(h.exchange.pendingIds(), [], "expired raw exchange erased");
    equal(h.store.loadSession(session.sessionRef, session.sessionCapability).receipts.length, 0, "no expired receipt committed");
  } finally { h.cleanup(); }
});

test("unexpired exchange cannot assess after its accountable region evidence expires", () => {
  let now = 20_000;
  const h = harness({ now: () => now, exchangeTtlMs: 300_000, regionEvidenceTtlMs: 60_000 });
  try {
    const session = h.controller.startSession("tenant-a", "session-a");
    const pending = h.controller.submitPrompt(session.sessionRef, "region expires first", "demo.north", session.sessionCapability);
    assert(pending.requestId, "request id");
    assert(fulfill(h.exchange, pending.requestId, "on-time agent response").ok, "agent response supplied");
    now += 120_000;
    const completed = h.controller.completeTurn(pending.requestId, session.sessionCapability);
    assert(!completed.ok && completed.holds.includes("region_evidence_expired"), "expired evidence holds assessment");
    equal(h.exchange.pendingIds(), [], "raw exchange erased");
    const state = h.store.loadSession(session.sessionRef, session.sessionCapability);
    equal(state.receipts.length, 0, "no assessment receipt committed");
    equal(state.pending.length, 0, "expired turn retired without bricking session");
    equal(state.retiredThroughSequence, 1, "history reset through expired turn");
    const next = h.controller.submitPrompt(session.sessionRef, "fresh evidence", "demo.south", session.sessionCapability);
    equal(next.sequence, 2, "session remains monotonic after expiry hold");
  } finally { h.cleanup(); }
});

test("exclusive response publication preserves the first winner across adapters", () => {
  const h = harness();
  try {
    const session = h.controller.startSession("tenant-a", "session-a");
    const pending = h.controller.submitPrompt(session.sessionRef, "race", "demo.north", session.sessionCapability);
    assert(pending.requestId, "request id");
    const secondAdapter = new ExternalAgentExchange(h.exchange.root, { ttlMs: 60_000 });
    const first = fulfill(h.exchange, pending.requestId, "winner-a");
    const second = fulfill(secondAdapter, pending.requestId, "winner-b");
    assert(first.ok, "first publication wins");
    assert(!second.ok && second.holds.includes("response_conflict"), "later publication conflicts");
    equal(h.exchange.consume(pending.requestId)?.response.response, "winner-a", "winner cannot be overwritten");
  } finally { h.cleanup(); }
});

test("exchange refuses symlink roots and symlink request files", () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "drawbridge-symlink-")));
  try {
    const real = join(root, "real");
    mkdirSync(real);
    const linked = join(root, "linked");
    symlinkSync(real, linked, "dir");
    throws(() => new ExternalAgentExchange(linked), "exchange_root_symlink_forbidden", "symlink root");

    const exchange = new ExternalAgentExchange(join(root, "exchange"));
    const request = exchange.createRequest({
      tenantRef: "a".repeat(64), sessionRef: "b".repeat(64), sequence: 1,
      prompt: "custody", scenarioId: "demo.north", regionEvidenceSha256: "c".repeat(64),
      regionEvidenceExpiresAtMs: Date.now() + 60_000,
    });
    const requestPath = join(exchange.root, `${request.requestId}.request.json`);
    const target = join(root, "target.json");
    writeFileSync(target, readFileSync(requestPath));
    rmSync(requestPath);
    symlinkSync(target, requestPath);
    throws(() => exchange.readRequest(request.requestId), "exchange_file_symlink_forbidden", "symlink request");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("exchange and store refuse a symlinked ancestor before creating custody roots", () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "drawbridge-ancestor-")));
  try {
    const real = join(root, "real");
    mkdirSync(real);
    const linked = join(root, "linked");
    symlinkSync(real, linked, "dir");
    throws(() => new ExternalAgentExchange(join(linked, "exchange")), "exchange_ancestor_symlink_forbidden", "exchange ancestor");
    throws(() => new RedactedSessionStore(join(linked, "state")), "session_store_ancestor_symlink_forbidden", "store ancestor");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("pre-existing shared directories are held without permission mutation", () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "drawbridge-shared-root-")));
  try {
    const sharedExchange = join(root, "shared-exchange");
    const sharedStore = join(root, "shared-store");
    mkdirSync(sharedExchange, { mode: 0o755 });
    mkdirSync(sharedStore, { mode: 0o755 });
    chmodSync(sharedExchange, 0o755);
    chmodSync(sharedStore, 0o755);
    throws(() => new ExternalAgentExchange(sharedExchange), "exchange_root_mode_0700_required", "shared exchange root");
    throws(() => new RedactedSessionStore(sharedStore), "session_store_root_mode_0700_required", "shared store root");
    equal(statSync(sharedExchange).mode & 0o777, 0o755, "exchange mode unchanged");
    equal(statSync(sharedStore).mode & 0o777, 0o755, "store mode unchanged");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("per-turn region evidence expires and cannot be replayed", () => {
  const registry = new FrozenRegionEvidenceRegistry({
    "demo.bound": { regionLabel: "bound", evidenceSource: "fixture-v1", syntheticDemoOnly: true },
  });
  const binding = { tenantRef: "a".repeat(64), sessionRef: "b".repeat(64), sequence: 1 };
  const evidence = registry.issue("demo.bound", binding, 1_000, 100);
  assert(evidence, "evidence issued");
  registry.claim(evidence, binding, 1_050);
  throws(() => registry.claim(evidence, binding, 1_051), "region_evidence_replayed", "replay");
  const expired = registry.issue("demo.bound", { ...binding, sequence: 2 }, 2_000, 100);
  assert(expired, "expiring evidence issued");
  throws(() => registry.claim(expired, { ...binding, sequence: 2 }, 2_101), "region_evidence_expired", "expiry");
});

test("four accountable turns reach candidate evidence and durable receipts stay redacted", () => {
  const h = harness();
  try {
    const session = h.controller.startSession("tenant-a", "session-a");
    let completed;
    for (const [index, scenario] of ["demo.north", "demo.north", "demo.south", "demo.south"].entries()) {
      const prompt = `bridge inspection alpha beta gamma ${index}`;
      const pending = h.controller.submitPrompt(session.sessionRef, prompt, scenario, session.sessionCapability);
      assert(pending.requestId, "pending id");
      fulfill(h.exchange, pending.requestId, `ChatGPT stand-in response ${index}`);
      completed = h.controller.completeTurn(pending.requestId, session.sessionCapability);
      assert(completed.ok, `turn ${index} completes`);
    }
    equal(completed?.assessment?.status, "CANDIDATE_EVIDENCE", "candidate status");
    equal(completed?.authority.actionCeiling, "OBSERVE_ONLY", "authority ceiling");
    const durable = JSON.stringify(h.store.loadSession(session.sessionRef, session.sessionCapability));
    for (const raw of ["bridge inspection", "ChatGPT stand-in response", "tenant-a", "session-a", "north", "south"]) {
      assert(!durable.includes(raw), `durable state leaked ${raw}`);
    }
    equal(h.exchange.pendingIds(), [], "raw exchange erased after completion");
  } finally { h.cleanup(); }
});

test("restart preserves monotonic sequence and exact completed request retry is idempotent", () => {
  const h = harness();
  try {
    const session = h.controller.startSession("tenant-a", "session-a");
    const pending = h.controller.submitPrompt(session.sessionRef, "first bridge turn", "demo.north", session.sessionCapability);
    assert(pending.requestId, "request id");
    fulfill(h.exchange, pending.requestId, "first response");
    const first = h.controller.completeTurn(pending.requestId, session.sessionCapability);
    assert(first.ok, "first complete");
    const restarted = new DrawbridgeRuntimeController({
      exchange: h.exchange,
      store: h.store,
      regions: fixtures,
      producerSecret: Buffer.alloc(32, 9),
      observerConfig: { hammingThreshold: 64, minGridSize: 4, minRegionCount: 2, ttlMs: 60_000 },
    });
    const retry = restarted.completeTurn(pending.requestId, session.sessionCapability);
    assert(retry.ok && retry.actions.includes("duplicate_completion_noop"), "retry noop");
    const second = restarted.submitPrompt(session.sessionRef, "second bridge turn", "demo.south", session.sessionCapability);
    equal(second.sequence, 2, "monotonic sequence after restart");
  } finally { h.cleanup(); }
});

test("duplicate completion erases crash-leftover raw exchange and expired orphan sweep removes abandoned requests", () => {
  let now = 2_000;
  const h = harness({ now: () => now });
  try {
    const session = h.controller.startSession("tenant-a", "session-a");
    const pending = h.controller.submitPrompt(session.sessionRef, "crash window", "demo.north", session.sessionCapability);
    assert(pending.requestId, "request id");
    fulfill(h.exchange, pending.requestId, "response");
    const requestPath = join(h.exchange.root, `${pending.requestId}.request.json`);
    const responsePath = join(h.exchange.root, `${pending.requestId}.response.json`);
    const requestBytes = readFileSync(requestPath);
    const responseBytes = readFileSync(responsePath);
    assert(h.controller.completeTurn(pending.requestId, session.sessionCapability).ok, "turn complete");
    writeFileSync(requestPath, requestBytes, { mode: 0o600 });
    writeFileSync(responsePath, responseBytes, { mode: 0o600 });
    const retry = h.controller.completeTurn(pending.requestId, session.sessionCapability);
    assert(retry.ok && retry.actions.includes("erased_recovered_raw_exchange"), "retry heals crash residue");
    equal(h.exchange.pendingIds(), [], "crash residue erased");

    h.exchange.createRequest({
      tenantRef: "a".repeat(64), sessionRef: "b".repeat(64), sequence: 9,
      prompt: "orphan", scenarioId: "demo.north", regionEvidenceSha256: "c".repeat(64),
      regionEvidenceExpiresAtMs: now + 60_000,
    });
    now += 60_001;
    const swept = h.exchange.sweepExpired();
    equal(swept.metrics.expired_requests_erased, 1, "one expired orphan erased");
    equal(h.exchange.pendingIds(), [], "orphan bytes erased");
  } finally { h.cleanup(); }
});

test("expired durable observations are not replayed as fresh evidence", () => {
  let now = 5_000;
  const h = harness({ now: () => now });
  try {
    const session = h.controller.startSession("tenant-a", "session-a");
    for (let index = 0; index < 3; index++) {
      const pending = h.controller.submitPrompt(session.sessionRef, `old north ${index}`, "demo.north", session.sessionCapability);
      assert(pending.requestId, "request id");
      fulfill(h.exchange, pending.requestId, `old response ${index}`);
      assert(h.controller.completeTurn(pending.requestId, session.sessionCapability).ok, "old turn complete");
      now += 1;
    }
    now += 60_001;
    const pending = h.controller.submitPrompt(session.sessionRef, "fresh south", "demo.south", session.sessionCapability);
    assert(pending.requestId, "fresh request id");
    fulfill(h.exchange, pending.requestId, "fresh response");
    const completed = h.controller.completeTurn(pending.requestId, session.sessionCapability);
    equal(completed.assessment?.status, "INSUFFICIENT_EVIDENCE", "expired history must stay expired");
    equal(completed.assessment?.gridSize, 1, "only fresh observation is replayed");
  } finally { h.cleanup(); }
});

test("durable state rejects unknown raw fields and recovers a dead stale lock", () => {
  const h = harness();
  try {
    const session = h.controller.startSession("tenant-low-entropy", "session-low-entropy");
    const oldBareRef = createHash("sha256").update("drawbridge:session-ref:v1\0tenant-low-entropy\0session-low-entropy").digest("hex");
    assert(session.sessionRef !== oldBareRef, "session reference must be keyed");
    const statePath = join(h.store.root, `${session.sessionRef}.json`);
    const state = JSON.parse(readFileSync(statePath, "utf8")) as Record<string, unknown>;
    state.rawPrompt = "must never persist";
    writeFileSync(statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 });
    throws(() => h.store.loadSession(session.sessionRef, session.sessionCapability), "session_store_contract_invalid", "unknown durable field");
    delete state.rawPrompt;
    state.schema = "tfb.drawbridge.runtime_session.v1";
    writeFileSync(statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 });
    throws(() => h.store.loadSession(session.sessionRef, session.sessionCapability), "session_store_contract_invalid", "legacy public-hash schema fails closed");
    state.schema = "tfb.drawbridge.runtime_session.v2";
    writeFileSync(statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 });
    writeFileSync(join(h.store.root, `${session.sessionRef}.lock`), JSON.stringify({ pid: 999_999_999, createdAtMs: 0, token: "d".repeat(32) }), { mode: 0o600 });
    const pending = h.controller.submitPrompt(session.sessionRef, "after crash", "demo.north", session.sessionCapability);
    assert(pending.ok, "dead lock should be recovered");
  } finally { h.cleanup(); }
});

test("an active lock is not removed during stale-lock recovery", () => {
  const h = harness();
  try {
    const session = h.controller.startSession("tenant-a", "session-a");
    const lockPath = join(h.store.root, `${session.sessionRef}.lock`);
    const lock = JSON.stringify({ pid: process.pid, createdAtMs: Date.now(), token: "a".repeat(32) });
    writeFileSync(lockPath, lock, { mode: 0o600 });
    const pending = h.controller.submitPrompt(session.sessionRef, "blocked by active owner", "demo.north", session.sessionCapability);
    assert(!pending.ok && pending.holds.includes("session_state_commit_failed"), "active lock holds writer");
    assert(existsSync(lockPath) && readFileSync(lockPath, "utf8") === lock, "active lock remains owned");
  } finally { h.cleanup(); }
});

test("durable receipts have a hard bound and the session has an explicit erasure path", () => {
  const h = harness({ maxReceipts: 2, receiptTtlMs: 60_000 });
  try {
    const session = h.controller.startSession("tenant-a", "session-a");
    for (let index = 0; index < 3; index++) {
      const pending = h.controller.submitPrompt(session.sessionRef, `bounded receipt ${index}`, index % 2 ? "demo.south" : "demo.north", session.sessionCapability);
      assert(pending.requestId, "request id");
      fulfill(h.exchange, pending.requestId, `response ${index}`);
      assert(h.controller.completeTurn(pending.requestId, session.sessionCapability).ok, "turn complete");
    }
    const state = h.store.loadSession(session.sessionRef, session.sessionCapability);
    equal(state.receipts.length, 2, "receipt ceiling");
    equal(state.retiredThroughSequence, 1, "retention floor advances");
    assert(h.store.eraseSession(session.sessionRef, session.sessionCapability), "explicit erasure reports removal");
    throws(() => h.store.loadSession(session.sessionRef, session.sessionCapability), "ENOENT", "erased session is absent");
  } finally { h.cleanup(); }
});

test("attestation failure leaves no durable receipt and keeps raw exchange recoverable", () => {
  const h = harness({ attestor: () => { throw new Error("xpc unavailable"); } });
  try {
    const session = h.controller.startSession("tenant-a", "session-a");
    const pending = h.controller.submitPrompt(session.sessionRef, "attest this", "demo.north", session.sessionCapability);
    assert(pending.requestId, "request id");
    fulfill(h.exchange, pending.requestId, "response");
    const result = h.controller.completeTurn(pending.requestId, session.sessionCapability);
    assert(!result.ok && result.holds.includes("attestation_failed"), "attestation hold");
    equal(h.store.loadSession(session.sessionRef, session.sessionCapability).receipts.length, 0, "no half receipt");
    assert(h.exchange.pendingIds().includes(pending.requestId), "exchange retained for bounded recovery");
  } finally { h.cleanup(); }
});

test("attestation persists only a fixed-domain digest and never reflects prompt or response", () => {
  const promptCanary = "SECRETPROMPTCANARY123";
  const responseCanary = "SECRETRESPONSECANARY456";
  const reflectedOutput = `${promptCanary}|${responseCanary}`;
  let attestorInput = Buffer.alloc(0);
  const h = harness({
    attestor: (payloadDigest: Buffer) => {
      attestorInput = Buffer.from(payloadDigest);
      return reflectedOutput;
    },
  });
  try {
    const session = h.controller.startSession("tenant-attestation-redaction", "session-attestation-redaction");
    const pending = h.controller.submitPrompt(session.sessionRef, promptCanary, "demo.north", session.sessionCapability);
    assert(pending.requestId, "request id");
    assert(fulfill(h.exchange, pending.requestId, responseCanary).ok, "response accepted");
    const completed = h.controller.completeTurn(pending.requestId, session.sessionCapability);
    assert(completed.ok && typeof completed.attestationReference === "string", "attested turn completes with a reference");
    const expectedReference = `attestation-sha256:${createHash("sha256")
      .update("drawbridge:attestation-output:v1\0", "utf8")
      .update(reflectedOutput, "utf8")
      .digest("hex")}`;
    equal(completed.attestationReference, expectedReference, "only the fixed-domain content address is returned");
    equal(attestorInput.length, 32, "attestor receives one canonical digest only");
    assert(!attestorInput.toString("utf8").includes(promptCanary) && !attestorInput.toString("utf8").includes(responseCanary),
      "attestor input cannot reflect either raw canary");
    const durableBytes = readFileSync(join(h.store.root, `${session.sessionRef}.json`), "utf8");
    assert(!durableBytes.includes(promptCanary) && !durableBytes.includes(responseCanary) && !durableBytes.includes(reflectedOutput),
      "durable state contains no raw prompt, response, or attestor output");
    const durable = h.store.loadSession(session.sessionRef, session.sessionCapability);
    equal(durable.receipts[0]?.attestationReference, expectedReference, "durable receipt stores only the digest reference");
    equal(completed.metrics.model_provider_network_calls, 0, "network metric is scoped to the model-provider transport");
    equal(completed.metrics.attestation_callback_transport_measured, false, "callback transport is explicitly unmeasured");
  } finally { h.cleanup(); }
});

test("oversized attestor output is rejected before durable receipt admission", () => {
  const h = harness({ attestor: () => "a".repeat(4_097) });
  try {
    const session = h.controller.startSession("tenant-attestation-bound", "session-attestation-bound");
    const pending = h.controller.submitPrompt(session.sessionRef, "bounded attestation", "demo.north", session.sessionCapability);
    assert(pending.requestId, "request id");
    fulfill(h.exchange, pending.requestId, "response");
    const completed = h.controller.completeTurn(pending.requestId, session.sessionCapability);
    assert(!completed.ok && completed.holds.includes("attestation_output_invalid"), "oversized output holds closed");
    equal(h.store.loadSession(session.sessionRef, session.sessionCapability).receipts.length, 0, "invalid attestation is never durable");
  } finally { h.cleanup(); }
});

test("industrial bridge console discloses stand-in, observe-only, receipts and synthetic evidence", () => {
  const html = renderDrawbridgeConsole();
  for (const text of ["ChatGPT agent stand-in", "OBSERVE ONLY", "Receipt reference", "Synthetic demo evidence"]) {
    assert(html.includes(text), `UI missing ${text}`);
  }
  assert(!html.includes("linear-gradient(135deg, #7"), "generic purple gradient forbidden");
});

test("browser and authenticated agent API traverse the same controller end to end", async () => {
  const h = harness();
  const agentToken = "agent-token-".padEnd(40, "x");
  try {
    const page = dispatchDrawbridgeHttp(h.controller, agentToken, { method: "GET", path: "/" });
    assert(page.status === 200 && typeof page.body === "string" && page.body.includes("Drawbridge Control Room"), "browser surface");
    const script = dispatchDrawbridgeHttp(h.controller, agentToken, { method: "GET", path: "/drawbridge.js" });
    const scriptText = script.body as string;
    for (const required of ["/api/sessions", "/api/prompts", "PENDING_AGENT_RESPONSE", "syntheticDemoOnly"]) {
      assert(scriptText.includes(required), `browser script missing ${required}`);
    }
    const favicon = dispatchDrawbridgeHttp(h.controller, agentToken, { method: "GET", path: "/favicon.ico" });
    assert(favicon.status === 204 && favicon.body === "", "browser favicon request stays console-clean");

    const session = dispatchDrawbridgeHttp(h.controller, agentToken, {
      method: "POST", path: "/api/sessions", body: { tenantId: "browser-tenant", sessionId: "browser-session" },
    }).body as Record<string, unknown>;
    assert(session.ok && typeof session.sessionRef === "string", "API session");
    const pending = dispatchDrawbridgeHttp(h.controller, agentToken, {
      method: "POST", path: "/api/prompts",
      body: { sessionRef: session.sessionRef, prompt: "browser bridge prompt", scenarioId: "demo.north" },
      sessionCapability: session.sessionCapability as string,
    }).body as Record<string, unknown>;
    assert(pending.ok && typeof pending.requestId === "string", "API pending turn");

    const unauthorized = dispatchDrawbridgeHttp(h.controller, agentToken, {
      method: "GET", path: `/api/agent/requests/${pending.requestId}`,
    });
    equal(unauthorized.status, 401, "raw agent request requires custody token");
    const request = dispatchDrawbridgeHttp(h.controller, agentToken, {
      method: "GET", path: `/api/agent/requests/${pending.requestId}`, authorization: `Bearer ${agentToken}`,
    }).body as Record<string, unknown>;
    equal((request.request as Record<string, unknown>).prompt, "browser bridge prompt", "agent receives exact request bytes");

    const response = "ChatGPT agent stand-in browser response";
    const responseSha256 = createHash("sha256").update(response).digest("hex");
    const supplied = dispatchDrawbridgeHttp(h.controller, agentToken, {
      method: "POST", path: "/api/agent/responses", authorization: `Bearer ${agentToken}`,
      body: { requestId: pending.requestId, provider: "chatgpt-agent-standin", response, responseSha256 },
    }).body as Record<string, unknown>;
    assert(supplied.ok, "agent response accepted");
    const completed = dispatchDrawbridgeHttp(h.controller, agentToken, {
      method: "POST", path: `/api/turns/${pending.requestId}/complete`, body: {},
      sessionCapability: session.sessionCapability as string,
    }).body as Record<string, unknown>;
    assert(completed.ok, "API completion");
    equal(completed.response, response, "browser receives response");
    equal((completed.authority as Record<string, unknown>).actionCeiling, "OBSERVE_ONLY", "browser authority");
    assert(typeof completed.receiptReference === "string", "receipt reference");
    equal(completed.syntheticDemoOnly, true, "synthetic disclosure");
    equal(h.store.loadSession(session.sessionRef as string, session.sessionCapability as string).receipts.length, 1, "same controller committed receipt");

    await throwsAsync(
      () => requestLoopbackJson("https://example.com/provider", { method: "POST", body: { planted: true } }),
      "loopback_endpoint_required",
      "planted provider network call",
    );
  } finally {
    h.cleanup();
  }
});

test("persisted bootstrap restarts with stable opaque producer identity", () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "drawbridge-bootstrap-")));
  try {
    const first = createDrawbridgeRuntime(root, { exchangeTtlMs: 60_000, receiptTtlMs: 60_000 });
    const session = first.controller.startSession("tenant-a", "session-a");
    const pending = first.controller.submitPrompt(session.sessionRef, "first persisted turn", "bridge.north", session.sessionCapability);
    assert(pending.requestId, "request id");
    fulfill(first.exchange, pending.requestId, "first response");
    assert(first.controller.completeTurn(pending.requestId, session.sessionCapability).ok, "first complete");
    first.close();

    const restarted = createDrawbridgeRuntime(root, { exchangeTtlMs: 60_000, receiptTtlMs: 60_000 });
    const same = restarted.controller.startSession("tenant-a", "session-a", session.sessionResumeToken);
    equal(same.sessionRef, session.sessionRef, "stable keyed session reference");
    const second = restarted.controller.submitPrompt(same.sessionRef, "second persisted turn", "bridge.south", same.sessionCapability);
    equal(second.sequence, 2, "monotonic restart sequence");
    restarted.close();
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("bootstrap rejects group or world writable state roots without permission mutation", () => {
  const parent = realpathSync(mkdtempSync(join(tmpdir(), "drawbridge-state-root-mode-")));
  try {
    for (const mode of [0o770, 0o777]) {
      const stateRoot = join(parent, `state-${mode.toString(8)}`);
      mkdirSync(stateRoot, { mode: 0o700 });
      chmodSync(stateRoot, mode);
      throws(() => createDrawbridgeRuntime(stateRoot), "drawbridge_state_root_mode_0700_required", `mode ${mode.toString(8)} held`);
      equal(statSync(stateRoot).mode & 0o777, mode, `mode ${mode.toString(8)} is not silently rewritten`);
      equal(readdirSync(stateRoot), [], "no child custody path is created under an unsafe state root");
    }
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

test("bootstrap anchors state root and custody leaves against post-start replacement", () => {
  const parent = realpathSync(mkdtempSync(join(tmpdir(), "drawbridge-root-anchor-")));
  const rootPath = join(parent, "runtime-root");
  const displacedRoot = join(parent, "runtime-root-displaced");
  let runtime: ReturnType<typeof createDrawbridgeRuntime> | undefined;
  try {
    runtime = createDrawbridgeRuntime(rootPath);
    renameSync(rootPath, displacedRoot);
    mkdirSync(rootPath, { mode: 0o700 });
    const rootHealth = runtime.controller.health();
    assert(!rootHealth.ok && rootHealth.holds.includes("runtime_custody_changed"), "replaced state-root inode holds every runtime operation");
    runtime.close();
    runtime = undefined;
  } finally {
    runtime?.close();
    rmSync(parent, { recursive: true, force: true });
  }

  const leafParent = realpathSync(mkdtempSync(join(tmpdir(), "drawbridge-leaf-anchor-")));
  const leafRoot = join(leafParent, "runtime-root");
  let leafRuntime: ReturnType<typeof createDrawbridgeRuntime> | undefined;
  try {
    leafRuntime = createDrawbridgeRuntime(leafRoot);
    const exchangePath = join(leafRoot, "exchange");
    renameSync(exchangePath, join(leafRoot, "exchange-displaced"));
    mkdirSync(exchangePath, { mode: 0o700 });
    const leafHealth = leafRuntime.controller.health();
    assert(!leafHealth.ok && leafHealth.holds.includes("runtime_custody_changed"), "replaced exchange leaf inode holds runtime health");
    const mutation = leafRuntime.controller.startSession("tenant-anchor", "session-anchor");
    assert(!mutation.ok && mutation.holds.includes("runtime_custody_changed"), "replaced leaf also holds mutations before state access");
    throws(() => leafRuntime?.exchange.createRequest({
      tenantRef: "a".repeat(64), sessionRef: "b".repeat(64), sequence: 1,
      prompt: "must not land", scenarioId: "bridge.north", regionEvidenceSha256: "c".repeat(64), regionEvidenceExpiresAtMs: Date.now() + 1_000,
    }), "exchange_root_identity_changed", "exported exchange mutator wears the same leaf anchor");

    const sessionsPath = join(leafRoot, "sessions");
    renameSync(sessionsPath, join(leafRoot, "sessions-displaced"));
    mkdirSync(sessionsPath, { mode: 0o700 });
    throws(() => leafRuntime?.store.sessionIdentity("tenant-direct", "session-direct"), "session_store_root_identity_changed",
      "exported store identity path wears the session leaf anchor");
  } finally {
    leafRuntime?.close();
    rmSync(leafParent, { recursive: true, force: true });
  }
});

test("CLI agent response computes the exact digest and only calls the loopback API seam", async () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "drawbridge-cli-")));
  try {
    const responsePath = join(root, "response.txt");
    const tokenPath = join(root, "agent-token");
    writeFileSync(responsePath, "exact ChatGPT stand-in bytes\n", { mode: 0o600 });
    writeFileSync(tokenPath, `${"t".repeat(32)}\n`, { mode: 0o600 });
    const requestId = "a".repeat(64);
    const responseSha256 = createHash("sha256").update("exact ChatGPT stand-in bytes\n").digest("hex");
    let captured: { endpoint: string; options: unknown } | undefined;
    const output: string[] = [];
    const exitCode = await runDrawbridgeCli([
      "agent-respond", requestId, "--response-file", responsePath,
      "--url", "http://127.0.0.1:4317", "--token-file", tokenPath,
    ], {
      requestJson: async (endpoint, options) => {
        captured = { endpoint, options };
        return {
          op: "drawbridge.runtime.submit_agent_response", ok: true,
          actions: ["validated_content_addressed_agent_exchange"], skips: [], errors: [], holds: [],
          metrics: {}, next: "continue", authority: OBSERVE_ONLY_AUTHORITY,
          requestId, responseSha256, provider: "chatgpt-agent-standin",
        };
      },
      writeOut: (line) => output.push(line),
      writeError: (line) => output.push(line),
    });
    equal(exitCode, 0, "CLI exit");
    assert(captured?.endpoint === "http://127.0.0.1:4317/api/agent/responses", "loopback API endpoint");
    const body = (captured.options as { body: Record<string, unknown> }).body;
    equal(body.provider, "chatgpt-agent-standin", "provider identity");
    equal(body.response, "exact ChatGPT stand-in bytes\n", "exact response bytes");
    equal(body.responseSha256, responseSha256, "response digest");
    assert(!output.join("\n").includes("exact ChatGPT stand-in bytes"), "CLI receipt must not echo raw response");
    assert(!existsSync(responsePath), "accepted response file must be erased");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("CLI closes every command argument schema before side effects", () => {
  const id = "a".repeat(64);
  const healthy: string[][] = [
    ["help"],
    ["--help"],
    ["serve", "--port", "4317", "--state-dir", "/tmp/drawbridge-state", "--token-file", "/tmp/token"],
    ["retention-sweep", "--state-dir", "/tmp/drawbridge-state"],
    ["agent-request", id, "--url", "http://127.0.0.1:4317", "--token-file", "/tmp/token"],
    ["agent-respond", id, "--response-file", "/tmp/response", "--token-file", "/tmp/token"],
    ["complete", id, "--session-token-file", "/tmp/session-token"],
    ["status", id, "--session-token-file", "/tmp/session-token"],
    ["erase", id, "--session-token-file", "/tmp/session-token"],
  ];
  for (const argv of healthy) parseAndValidateDrawbridgeArguments(argv);

  const wounded: Array<[string[], string]> = [
    [["serve", "--state-dri", "/tmp/intended", "--token-file", "/tmp/token"], "serve_argv_invalid"],
    [["serve", "unexpected", "--token-file", "/tmp/token"], "serve_argv_invalid"],
    [["retention-sweep", "unexpected"], "retention_sweep_argv_invalid"],
    [["agent-request", id, "--response-file", "/tmp/response"], "agent_request_argv_invalid"],
    [["agent-respond", id, "--state-dir", "/tmp/state"], "agent_respond_argv_invalid"],
    [["complete", id, "--token-file", "/tmp/token"], "complete_argv_invalid"],
    [["status", id, "extra"], "status_argv_invalid"],
    [["erase", id, "--unknown", "value"], "erase_argv_invalid"],
    [["unknown", id], "drawbridge_cli_command_unknown"],
  ];
  for (const [argv, error] of wounded) {
    throws(() => parseAndValidateDrawbridgeArguments(argv), error, `${argv[0]} malformed contract holds`);
  }
  throws(
    () => parseAndValidateDrawbridgeArguments(["serve", "--port", "4317", "--port", "4318"]),
    "duplicate_cli_flag_forbidden",
    "duplicate flag holds before side effects",
  );
  throws(
    () => parseAndValidateDrawbridgeArguments(["serve", "--token", "raw-secret"]),
    "secret_argv_forbidden",
    "raw secret flag is named before runtime startup",
  );
});

test("CLI preserves the sole response file unless the admission receipt is exactly bound", async () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "drawbridge-cli-false-ack-")));
  try {
    const tokenPath = join(root, "agent-token");
    writeFileSync(tokenPath, `${"t".repeat(32)}\n`, { mode: 0o600 });
    const requestId = "a".repeat(64);
    const response = "response custody canary";
    const responseSha256 = createHash("sha256").update(response).digest("hex");
    const valid = {
      op: "drawbridge.runtime.submit_agent_response", ok: true,
      actions: ["validated_content_addressed_agent_exchange"], skips: [], errors: [], holds: [],
      metrics: {}, next: "continue", authority: OBSERVE_ONLY_AUTHORITY,
      requestId, responseSha256, provider: "chatgpt-agent-standin",
    };
    const woundedReceipts: Array<[string, Record<string, unknown>]> = [
      ["wrong-op", { ...valid, op: "unrelated.local.service" }],
      ["wrong-request", { ...valid, requestId: "b".repeat(64) }],
      ["wrong-digest", { ...valid, responseSha256: "b".repeat(64) }],
      ["wrong-provider", { ...valid, provider: "other-provider" }],
      ["authority-escalation", { ...valid, authority: { ...OBSERVE_ONLY_AUTHORITY, activationAuthorized: true } }],
      ["missing-action", { ...valid, actions: [] }],
      ["hidden-hold", { ...valid, holds: ["not_admitted"] }],
      ["hidden-error", { ...valid, errors: ["not_admitted"] }],
    ];
    for (const [label, receipt] of woundedReceipts) {
      const responsePath = join(root, `${label}.txt`);
      writeFileSync(responsePath, response, { mode: 0o600 });
      const errors: string[] = [];
      const exitCode = await runDrawbridgeCli([
        "agent-respond", requestId, "--response-file", responsePath, "--token-file", tokenPath,
      ], {
        requestJson: async () => receipt,
        writeOut: () => undefined,
        writeError: (line) => errors.push(line),
      });
      equal(exitCode, 1, `${label} receipt held`);
      assert(existsSync(responsePath) && readFileSync(responsePath, "utf8") === response,
        `${label} cannot erase the sole response file`);
      assert(errors.join("\n").includes("agent_response_receipt_binding_invalid"), `${label} names binding hold`);
    }

    const completedRetryPath = join(root, "completed-idempotent.txt");
    writeFileSync(completedRetryPath, response, { mode: 0o600 });
    const completedRetryExit = await runDrawbridgeCli([
      "agent-respond", requestId, "--response-file", completedRetryPath, "--token-file", tokenPath,
    ], {
      requestJson: async () => ({ ...valid, actions: ["duplicate_completed_response_noop"] }),
      writeOut: () => undefined,
      writeError: () => undefined,
    });
    equal(completedRetryExit, 0, "content-bound completed retry receipt is accepted");
    assert(!existsSync(completedRetryPath), "lost-ack retry erases the sole response file after bound acknowledgement");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("independent retention sweep retires overdue raw exchange while HTTP runtime is stopped", async () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "drawbridge-retention-sweep-")));
  let runtime: ReturnType<typeof createDrawbridgeRuntime> | undefined;
  try {
    runtime = createDrawbridgeRuntime(root, { exchangeTtlMs: 1 });
    const session = runtime.controller.startSession("tenant-janitor", "session-janitor");
    const pending = runtime.controller.submitPrompt(
      session.sessionRef, "janitor raw canary", "bridge.north", session.sessionCapability,
    );
    assert(pending.requestId && runtime.exchange.pendingIds().includes(pending.requestId), "raw request exists before runtime stop");
    const rawPath = join(root, "exchange", `${pending.requestId}.request.json`);
    assert(readFileSync(rawPath, "utf8").includes("janitor raw canary"), "pre-sweep canary proves plaintext custody");
    runtime.close();
    runtime = undefined;
    await pause(5);

    const output: string[] = [];
    const exitCode = await runDrawbridgeCli(["retention-sweep", "--state-dir", root], {
      writeOut: (line) => output.push(line),
      writeError: (line) => output.push(line),
    });
    equal(exitCode, 0, "independent sweep exit");
    const receipt = JSON.parse(output.at(-1) ?? "{}") as Record<string, unknown>;
    equal(receipt.op, "drawbridge.cli.retention_sweep", "independent sweep op");
    assert(Array.isArray(receipt.actions) && receipt.actions.includes("ran_independent_retention_sweep"), "sweep narrates owner");
    assert(!existsSync(rawPath), "overdue raw request erased while HTTP runtime stayed stopped");

    runtime = createDrawbridgeRuntime(root);
    const health = runtime.controller.health();
    equal(health.metrics.pendingCount, 0, "expired durable pending row retired");
    equal(health.metrics.raw_exchange_plaintext_pending, false, "post-sweep plaintext narration is false");
  } finally {
    runtime?.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test("CLI rejects live custody secrets in argv and requires owner-only token files", async () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "drawbridge-cli-token-custody-")));
  try {
    let called = false;
    const errors: string[] = [];
    const dependencies = {
      requestJson: async () => { called = true; return { ok: true }; },
      writeOut: () => undefined,
      writeError: (line: string) => errors.push(line),
    };
    equal(await runDrawbridgeCli([
      "agent-request", "a".repeat(64), "--token", "t".repeat(32),
    ], dependencies), 1, "raw argv token refused");
    assert(!called && errors.join("\n").includes("secret_argv_forbidden"), "secret never reaches the request seam");

    const sharedToken = join(root, "shared-token");
    writeFileSync(sharedToken, `${"t".repeat(32)}\n`, { mode: 0o644 });
    chmodSync(sharedToken, 0o644);
    equal(await runDrawbridgeCli([
      "agent-request", "a".repeat(64), "--token-file", sharedToken,
    ], dependencies), 1, "shared token file refused");
    assert(!called && errors.join("\n").includes("agent_custody_token_file_mode_0600_required"), "mode hold named");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("CLI response-file custody rejects symlinks and non-owner-only mode without residue mutation", async () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "drawbridge-cli-custody-")));
  try {
    const tokenPath = join(root, "agent-token");
    writeFileSync(tokenPath, `${"t".repeat(32)}\n`, { mode: 0o600 });
    const target = join(root, "target.txt");
    const linked = join(root, "linked.txt");
    writeFileSync(target, "raw answer", { mode: 0o600 });
    symlinkSync(target, linked);
    let called = false;
    const dependencies = {
      requestJson: async () => { called = true; return { ok: true }; },
      writeOut: () => undefined,
      writeError: () => undefined,
    };
    equal(await runDrawbridgeCli([
      "agent-respond", "a".repeat(64), "--response-file", linked, "--token-file", tokenPath,
    ], dependencies), 1, "symlink response held");
    assert(!called && readFileSync(target, "utf8") === "raw answer", "symlink target untouched");

    const actualDirectory = join(root, "actual");
    const linkedDirectory = join(root, "linked-directory");
    mkdirSync(actualDirectory, { mode: 0o700 });
    const nested = join(actualDirectory, "nested.txt");
    writeFileSync(nested, "ancestor raw answer", { mode: 0o600 });
    symlinkSync(actualDirectory, linkedDirectory);
    equal(await runDrawbridgeCli([
      "agent-respond", "a".repeat(64), "--response-file", join(linkedDirectory, "nested.txt"), "--token-file", tokenPath,
    ], dependencies), 1, "symlink ancestor held");
    assert(!called && readFileSync(nested, "utf8") === "ancestor raw answer", "ancestor symlink target untouched");

    const shared = join(root, "shared.txt");
    writeFileSync(shared, "shared raw answer", { mode: 0o644 });
    chmodSync(shared, 0o644);
    equal(await runDrawbridgeCli([
      "agent-respond", "a".repeat(64), "--response-file", shared, "--token-file", tokenPath,
    ], dependencies), 1, "shared-mode response held");
    assert(!called && existsSync(shared) && (statSync(shared).mode & 0o777) === 0o644, "shared response untouched");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("persisted secret files require owner-only single-inode custody", () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "drawbridge-secret-custody-")));
  try {
    createDrawbridgeRuntime(root);
    const producerKey = join(root, ".producer-key");
    chmodSync(producerKey, 0o644);
    throws(() => createDrawbridgeRuntime(root), "producer_secret_mode_0600_required", "producer key mode");
    equal(statSync(producerKey).mode & 0o777, 0o644, "producer key mode unchanged");

    chmodSync(producerKey, 0o600);
    const referenceKey = join(root, "sessions", ".reference-key");
    chmodSync(referenceKey, 0o644);
    throws(() => createDrawbridgeRuntime(root), "reference_secret_mode_0600_required", "reference key mode");
    equal(statSync(referenceKey).mode & 0o777, 0o644, "reference key mode unchanged");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("health holds when durable session state is corrupt", () => {
  const h = harness();
  try {
    const session = h.controller.startSession("tenant-a", "session-a");
    const statePath = join(h.store.root, `${session.sessionRef}.json`);
    const state = JSON.parse(readFileSync(statePath, "utf8")) as Record<string, unknown>;
    state.rawPrompt = "corrupt health canary";
    writeFileSync(statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 });
    const health = dispatchDrawbridgeHttp(h.controller, "t".repeat(32), { method: "GET", path: "/api/health" });
    equal(health.status, 503, "corrupt health status");
    const body = health.body as Record<string, unknown>;
    assert(body.ok === false && (body.holds as string[]).includes("runtime_integrity_check_failed"), "corrupt health hold");
  } finally { h.cleanup(); }
});

test("health reconciles exact durable and raw request identities rather than counts", () => {
  const missing = harness();
  try {
    const session = missing.controller.startSession("tenant-health", "missing-raw");
    const pending = missing.controller.submitPrompt(session.sessionRef, "missing raw", "demo.north", session.sessionCapability);
    assert(pending.requestId, "pending request id");
    rmSync(join(missing.exchange.root, `${pending.requestId}.request.json`));
    const health = missing.controller.health();
    assert(!health.ok && health.holds.includes("runtime_pending_request_missing"), "missing raw request must hold health");
  } finally { missing.cleanup(); }

  const orphan = harness();
  try {
    const raw = orphan.exchange.createRequest({
      tenantRef: "a".repeat(64), sessionRef: "b".repeat(64), sequence: 1,
      prompt: "orphan raw", scenarioId: "demo.north", regionEvidenceSha256: "c".repeat(64),
      regionEvidenceExpiresAtMs: Date.now() + 60_000,
    });
    const health = orphan.controller.health();
    assert(!health.ok && health.holds.includes("runtime_orphan_raw_request_recovered"), "orphan raw request must be named");
    assert(!orphan.exchange.pendingIds().includes(raw.requestId), "orphan raw request is erased during recovery");
    assert(orphan.controller.health().ok, "health returns green only after recovered state is rechecked");
  } finally { orphan.cleanup(); }

  const substituted = harness();
  try {
    const session = substituted.controller.startSession("tenant-health", "substituted-raw");
    const pending = substituted.controller.submitPrompt(session.sessionRef, "registered", "demo.north", session.sessionCapability);
    assert(pending.requestId, "registered request id");
    rmSync(join(substituted.exchange.root, `${pending.requestId}.request.json`));
    const replacement = substituted.exchange.createRequest({
      tenantRef: "d".repeat(64), sessionRef: "e".repeat(64), sequence: 1,
      prompt: "substitution", scenarioId: "demo.south", regionEvidenceSha256: "f".repeat(64),
      regionEvidenceExpiresAtMs: Date.now() + 60_000,
    });
    const health = substituted.controller.health();
    assert(!health.ok, "equal counts with different ids must hold");
    assert(health.holds.includes("runtime_pending_request_missing"), "registered id absence named");
    assert(health.holds.includes("runtime_orphan_raw_request_recovered"), "substituted id named and recovered");
    assert(replacement.requestId !== pending.requestId, "control must use different raw id");
  } finally { substituted.cleanup(); }

  const crashRecovery = harness();
  let restarted: ExternalAgentExchange | undefined;
  try {
    crashRecovery.exchange.close();
    const temporary = join(crashRecovery.exchange.root, `.${"9".repeat(64)}.request.json.999999999.${"8".repeat(12)}.tmp`);
    writeFileSync(temporary, "crash residue", { mode: 0o600 });
    restarted = new ExternalAgentExchange(crashRecovery.exchange.root, { ttlMs: 60_000 });
    const controller = new DrawbridgeRuntimeController({
      exchange: restarted,
      store: crashRecovery.store,
      regions: fixtures,
      producerSecret: Buffer.alloc(32, 9),
    });
    const firstHealth = controller.health();
    assert(!firstHealth.ok && firstHealth.holds.includes("runtime_exchange_crash_state_recovered"), "startup crash recovery is surfaced once");
    assert(controller.health().ok, "recovered startup state is green only after acknowledgement");
  } finally {
    restarted?.close();
    crashRecovery.cleanup();
  }
});

test("lock recovery never steals a live owner and recovers stale partial metadata", () => {
  let now = 100_000;
  const h = harness({ now: () => now, staleLockMs: 10 });
  try {
    const session = h.controller.startSession("tenant-lock", "session-lock");
    const lockPath = join(h.store.root, `${session.sessionRef}.lock`);
    const live = JSON.stringify({ pid: process.pid, createdAtMs: 0, token: "a".repeat(32) });
    writeFileSync(lockPath, live, { mode: 0o600 });
    const held = h.controller.submitPrompt(session.sessionRef, "live owner", "demo.north", session.sessionCapability);
    assert(!held.ok && held.holds.includes("session_state_commit_failed"), "aged live owner still holds contender");
    equal(readFileSync(lockPath, "utf8"), live, "live lock bytes preserved");

    rmSync(lockPath);
    writeFileSync(lockPath, "{", { mode: 0o600 });
    utimesSync(lockPath, new Date(0), new Date(0));
    const recovered = h.controller.submitPrompt(session.sessionRef, "partial crash metadata", "demo.north", session.sessionCapability);
    assert(recovered.ok, "stale partial lock metadata is quarantined and recovered");
  } finally { h.cleanup(); }
});

test("hard-link publication crash residue is recovered only as one authentic dead-owner pair", () => {
  const h = harness();
  let restarted: RedactedSessionStore | undefined;
  try {
    const session = h.controller.startSession("tenant-link-crash", "session-link-crash");
    h.store.close();
    const nonce = "a".repeat(12);
    const temporary = join(h.store.root, `${session.sessionRef}.lock.999999999.${nonce}.locktmp`);
    const final = join(h.store.root, `${session.sessionRef}.lock`);
    writeFileSync(temporary, `${JSON.stringify({ pid: 999999999, createdAtMs: 0, token: "b".repeat(32) })}\n`, { mode: 0o600 });
    linkSync(temporary, final);
    equal(statSync(temporary).nlink, 2, "publication crash pair has two authentic links");
    restarted = new RedactedSessionStore(h.store.root);
    assert(!existsSync(temporary) && !existsSync(final), "authentic dead-owner temp and final are retired together");
    assert(restarted.loadSession(session.sessionRef, session.sessionCapability).sessionRef === session.sessionRef, "durable state remains available");
  } finally {
    restarted?.close();
    h.cleanup();
  }
});

test("lock retirement and state commit fence a forced ABA replacement", () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "drawbridge-lock-aba-")));
  const stateRoot = join(root, "state");
  let recoveryReplacement = "";
  try {
    mkdirSync(stateRoot, { mode: 0o700 });
    const seed = new RedactedSessionStore(stateRoot);
    const exchange = new ExternalAgentExchange(join(root, "exchange"));
    const seedController = new DrawbridgeRuntimeController({
      exchange, store: seed, regions: fixtures, producerSecret: Buffer.alloc(32, 9),
    });
    const seeded = seedController.startSession("tenant-aba", "session-aba");
    seed.close();
    const final = join(stateRoot, `${seeded.sessionRef}.lock`);
    writeFileSync(final, `${JSON.stringify({ pid: 999999999, createdAtMs: 0, token: "c".repeat(32) })}\n`, { mode: 0o600 });
    recoveryReplacement = `${JSON.stringify({ pid: process.pid, createdAtMs: Date.now(), token: "d".repeat(32) })}\n`;
    throws(() => new RedactedSessionStore(stateRoot, {
      beforeRecoveryRetire: (lockPath: string) => {
        rmSync(lockPath);
        writeFileSync(lockPath, recoveryReplacement, { mode: 0o600 });
      },
    } as never), "session_store_recovery_fence_lost", "replacement between recovery check and retire");
    equal(readFileSync(final, "utf8"), recoveryReplacement, "replacement live lock survives failed recovery");
    rmSync(final);

    let armed = false;
    let commitReplacement = "";
    const store = new RedactedSessionStore(stateRoot, {
      beforeStateCommit: (lockPath: string) => {
        if (!armed) return;
        rmSync(lockPath);
        commitReplacement = `${JSON.stringify({ pid: process.pid, createdAtMs: Date.now(), token: "e".repeat(32) })}\n`;
        writeFileSync(lockPath, commitReplacement, { mode: 0o600 });
      },
    } as never);
    const controller = new DrawbridgeRuntimeController({
      exchange, store, regions: fixtures, producerSecret: Buffer.alloc(32, 9),
    });
    const durableBefore = readFileSync(join(stateRoot, `${seeded.sessionRef}.json`), "utf8");
    armed = true;
    const submitted = controller.submitPrompt(seeded.sessionRef, "must not cross lost fence", "demo.north", seeded.sessionCapability);
    assert(!submitted.ok && submitted.holds.includes("session_state_commit_failed"), "lost commit fence holds before publication");
    equal(readFileSync(final, "utf8"), commitReplacement, "replacement live lock survives failed commit");
    rmSync(final);
    equal(readFileSync(join(stateRoot, `${seeded.sessionRef}.json`), "utf8"), durableBefore, "lost-owner candidate leaves prior durable bytes unchanged");
    equal(store.loadSession(seeded.sessionRef, seeded.sessionCapability).pending.length, 0, "lost-fence candidate never commits");
    store.close();
    exchange.close();
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("one recovery claimant owns retirement through the final comparison window", () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "drawbridge-lock-claim-owner-")));
  const stateRoot = join(root, "state");
  let contenderHeld = false;
  let replacement = "";
  try {
    mkdirSync(stateRoot, { mode: 0o700 });
    const seed = new RedactedSessionStore(stateRoot);
    const session = seed.startSession("tenant-claim-owner", "session-claim-owner");
    seed.close();
    const final = join(stateRoot, `${session.state.sessionRef}.lock`);
    writeFileSync(final, `${JSON.stringify({ pid: 999999999, createdAtMs: 0, token: "6".repeat(32) })}\n`, { mode: 0o600 });
    replacement = `${JSON.stringify({ pid: process.pid, createdAtMs: Date.now(), token: "7".repeat(32) })}\n`;

    throws(() => new RedactedSessionStore(stateRoot, {
      afterRecoveryFenceCheck: (lockPath: string) => {
        throws(() => new RedactedSessionStore(stateRoot), "session_store_recovery_busy", "second recoverer cannot share the first claimant's hard link");
        contenderHeld = true;
        rmSync(lockPath);
        writeFileSync(lockPath, replacement, { mode: 0o600 });
      },
    } as never), "session_store_recovery_fence_lost", "replacement after the final comparison is detected");

    assert(contenderHeld, "concurrent recovery attempt reached the exclusive-claim gate");
    equal(readFileSync(final, "utf8"), replacement, "replacement live lock survives the exact comparison-to-retirement window");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("dead-owner takeover cannot rename an ABA replacement owner", () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "drawbridge-owner-takeover-aba-")));
  const stateRoot = join(root, "state");
  let replacementOwner = "";
  let contenderHeld = false;
  try {
    mkdirSync(stateRoot, { mode: 0o700 });
    const seed = new RedactedSessionStore(stateRoot);
    const session = seed.startSession("tenant-owner-aba", "session-owner-aba");
    seed.close();
    const lockPath = join(stateRoot, `${session.state.sessionRef}.lock`);
    const lockBytes = `${JSON.stringify({ pid: 999999999, createdAtMs: 0, token: "a".repeat(32) })}\n`;
    writeFileSync(lockPath, lockBytes, { mode: 0o600 });
    const observed = statSync(lockPath);
    const claimId = createHash("sha256")
      .update("drawbridge:session-lock-recovery-claim:v1\0", "utf8")
      .update(session.state.sessionRef, "utf8")
      .update(`\0${observed.dev}\0${observed.ino}\0`, "utf8")
      .update(lockBytes, "utf8")
      .digest("hex");
    const claimPath = join(stateRoot, `${session.state.sessionRef}.recovery.${claimId}`);
    const ownerPath = `${claimPath}.owner`;
    linkSync(lockPath, claimPath);
    writeFileSync(ownerPath, `${JSON.stringify({
      schema: "tfb.drawbridge.session_lock_recovery_owner.v1",
      claimId,
      pid: 999999999,
      createdAtMs: 0,
      token: "b".repeat(32),
    })}\n`, { mode: 0o600 });

    throws(() => new RedactedSessionStore(stateRoot, {
      afterRecoveryOwnerTakeover: (path: string) => {
        rmSync(path);
        replacementOwner = `${JSON.stringify({
          schema: "tfb.drawbridge.session_lock_recovery_owner.v1",
          claimId,
          pid: process.pid,
          createdAtMs: Date.now(),
          token: "c".repeat(32),
        })}\n`;
        writeFileSync(path, replacementOwner, { mode: 0o600 });
        throws(() => new RedactedSessionStore(stateRoot), "session_store_recovery_busy", "B cannot take over while A owns the fixed takeover link");
        contenderHeld = true;
      },
    } as never), "session_store_recovery_fence_lost", "A refuses to retire C's replacement owner");

    assert(contenderHeld, "B reached the fixed exclusive takeover fence");
    equal(readFileSync(ownerPath, "utf8"), replacementOwner, "C replacement owner remains at the canonical owner path");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("state publication rolls back both final-check race windows byte exactly", () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "drawbridge-state-publish-fence-")));
  const stateRoot = join(root, "state");
  const exchange = new ExternalAgentExchange(join(root, "exchange"));
  try {
    mkdirSync(stateRoot, { mode: 0o700 });
    const seed = new RedactedSessionStore(stateRoot);
    const seedController = new DrawbridgeRuntimeController({
      exchange, store: seed, regions: fixtures, producerSecret: Buffer.alloc(32, 9),
    });
    const session = seedController.startSession("tenant-publish-fence", "session-publish-fence");
    seed.close();
    const statePath = join(stateRoot, `${session.sessionRef}.json`);
    const lockPath = join(stateRoot, `${session.sessionRef}.lock`);
    const durableBefore = readFileSync(statePath, "utf8");

    let preRenameArmed = false;
    const preRenameReplacement = `${JSON.stringify({ pid: process.pid, createdAtMs: Date.now(), token: "8".repeat(32) })}\n`;
    const preRenameStore = new RedactedSessionStore(stateRoot, {
      afterStateFenceCheck: (path: string) => {
        if (!preRenameArmed) return;
        rmSync(path);
        writeFileSync(path, preRenameReplacement, { mode: 0o600 });
      },
    } as never);
    const preRenameController = new DrawbridgeRuntimeController({
      exchange, store: preRenameStore, regions: fixtures, producerSecret: Buffer.alloc(32, 9),
    });
    preRenameArmed = true;
    const beforeRename = preRenameController.submitPrompt(session.sessionRef, "lose ownership before rename", "demo.north", session.sessionCapability);
    assert(!beforeRename.ok && beforeRename.holds.includes("session_state_commit_failed"), "pre-rename ownership loss holds publication");
    equal(readFileSync(lockPath, "utf8"), preRenameReplacement, "pre-rename replacement lock survives");
    equal(readFileSync(statePath, "utf8"), durableBefore, "pre-rename loss leaves prior durable bytes exact");
    rmSync(lockPath);
    preRenameStore.close();

    let postRenameArmed = false;
    const postRenameReplacement = `${JSON.stringify({ pid: process.pid, createdAtMs: Date.now(), token: "9".repeat(32) })}\n`;
    const postRenameStore = new RedactedSessionStore(stateRoot, {
      afterStatePublish: (path: string) => {
        if (!postRenameArmed) return;
        rmSync(path);
        writeFileSync(path, postRenameReplacement, { mode: 0o600 });
      },
    } as never);
    const postRenameController = new DrawbridgeRuntimeController({
      exchange, store: postRenameStore, regions: fixtures, producerSecret: Buffer.alloc(32, 9),
    });
    postRenameArmed = true;
    const afterRename = postRenameController.submitPrompt(session.sessionRef, "lose ownership after rename", "demo.north", session.sessionCapability);
    assert(!afterRename.ok && afterRename.holds.includes("session_state_commit_failed"), "post-rename ownership loss holds publication");
    equal(readFileSync(lockPath, "utf8"), postRenameReplacement, "post-rename replacement lock survives");
    equal(readFileSync(statePath, "utf8"), durableBefore, "post-rename loss restores prior durable bytes exact");
    rmSync(lockPath);
    equal(postRenameStore.loadSession(session.sessionRef, session.sessionCapability).pending.length, 0, "rolled-back candidate is never selected");
    postRenameStore.close();
  } finally {
    exchange.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test("crash-left state transaction restores the exact prior generation before selection", () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "drawbridge-state-transaction-crash-")));
  const stateRoot = join(root, "state");
  let restarted: RedactedSessionStore | undefined;
  try {
    mkdirSync(stateRoot, { mode: 0o700 });
    const seed = new RedactedSessionStore(stateRoot);
    const session = seed.startSession("tenant-transaction-crash", "session-transaction-crash");
    seed.close();
    const sessionRef = session.state.sessionRef;
    const final = join(stateRoot, `${sessionRef}.json`);
    const priorBytes = readFileSync(final, "utf8");
    const original = statSync(final);
    const nonce = "d".repeat(12);
    const candidateName = `${sessionRef}.json.999999999.${nonce}.tmp`;
    const priorName = `${sessionRef}.json.999999999.${nonce}.prior`;
    const candidatePath = join(stateRoot, candidateName);
    const priorPath = join(stateRoot, priorName);
    const markerPath = join(stateRoot, `${sessionRef}.json.999999999.${nonce}.txn`);
    const candidateState = { ...session.state, writerFenceToken: "e".repeat(32), nextSequence: 2 };
    writeFileSync(candidatePath, `${JSON.stringify(candidateState, null, 2)}\n`, { mode: 0o600 });
    const candidate = statSync(candidatePath);
    writeFileSync(markerPath, `${JSON.stringify({
      schema: "tfb.drawbridge.session_state_transaction.v1",
      sessionRef,
      pid: 999999999,
      lockToken: "e".repeat(32),
      candidateName,
      candidateDev: String(candidate.dev),
      candidateIno: String(candidate.ino),
      priorName,
      stateExisted: true,
      originalDev: String(original.dev),
      originalIno: String(original.ino),
    })}\n`, { mode: 0o600 });
    linkSync(final, priorPath);
    renameSync(candidatePath, final);

    restarted = new RedactedSessionStore(stateRoot);
    equal(readFileSync(final, "utf8"), priorBytes, "restart rolls the unconfirmed candidate back to byte-exact prior state");
    assert(!readdirSync(stateRoot).some((name) => name.includes(`${nonce}.txn`) || name.endsWith(`${nonce}.prior`)), "transaction marker and prior link retire together");
    equal(restarted.loadSession(sessionRef, session.sessionCapability).nextSequence, 1, "unconfirmed candidate is never selected");
  } finally {
    restarted?.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test("same-inode commit-marker alias crash rolls back once and retires both names", () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "drawbridge-marker-alias-crash-")));
  const stateRoot = join(root, "state");
  let restarted: RedactedSessionStore | undefined;
  try {
    mkdirSync(stateRoot, { mode: 0o700 });
    const seed = new RedactedSessionStore(stateRoot);
    const session = seed.startSession("tenant-marker-alias", "session-marker-alias");
    seed.close();
    const final = join(stateRoot, `${session.state.sessionRef}.json`);
    const priorBytes = readFileSync(final, "utf8");
    const priorSha256 = createHash("sha256").update(priorBytes).digest("hex");
    const childScript = `
      import { readFileSync, rmSync, writeFileSync } from "node:fs";
      import { RedactedSessionStore } from "./src/drawbridge-runtime/store.ts";
      const stateRoot = process.env.DRAWBRIDGE_TEST_STATE_ROOT;
      const resumeToken = process.env.DRAWBRIDGE_TEST_RESUME_TOKEN;
      if (!stateRoot || !resumeToken) process.exit(90);
      const store = new RedactedSessionStore(stateRoot, {
        beforeCommitMarkerRename: (markerPath) => {
          const bytes = readFileSync(markerPath, "utf8");
          rmSync(markerPath);
          writeFileSync(markerPath, bytes, { mode: 0o600 });
        },
        afterCommitMarkerRestoreLink: () => process.exit(23),
      });
      store.startSession("tenant-marker-alias", "session-marker-alias", resumeToken);
      process.exit(91);
    `;
    const child = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", childScript], {
      cwd: process.cwd(),
      encoding: "utf8",
      env: {
        ...process.env,
        DRAWBRIDGE_TEST_STATE_ROOT: stateRoot,
        DRAWBRIDGE_TEST_RESUME_TOKEN: session.sessionResumeToken,
      },
    });
    equal(child.status, 23, `child exits at the exact restore-link boundary: ${child.stderr}`);
    const aliases = readdirSync(stateRoot)
      .filter((name) => name.startsWith(`${session.state.sessionRef}.json.`) && (name.endsWith(".txn") || name.endsWith(".txn.committing")))
      .sort();
    equal(aliases.length, 2, "crash leaves exactly the base and committing transaction aliases");
    const firstAlias = statSync(join(stateRoot, aliases[0]));
    const secondAlias = statSync(join(stateRoot, aliases[1]));
    assert(firstAlias.dev === secondAlias.dev && firstAlias.ino === secondAlias.ino && firstAlias.nlink === 2 && secondAlias.nlink === 2,
      "aliases are the exact same two-link inode");

    restarted = new RedactedSessionStore(stateRoot);
    equal(createHash("sha256").update(readFileSync(final)).digest("hex"), priorSha256, "restart restores the byte-exact prior SHA");
    assert(!readdirSync(stateRoot).some((name) => name.includes(".txn")), "restart retires both transaction alias names");
    equal(restarted.loadSession(session.state.sessionRef, session.sessionCapability).capabilityNonce, session.state.capabilityNonce,
      "crash-left capability rotation never becomes authoritative");
  } finally {
    restarted?.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test("store startup recovers only exact dead-owner state and lock temporaries", () => {
  const h = harness();
  let restarted: RedactedSessionStore | undefined;
  try {
    const session = h.controller.startSession("tenant-store-crash", "session-store-crash");
    h.store.close();
    const stateTemporary = join(h.store.root, `${session.sessionRef}.json.999999999.${"a".repeat(12)}.tmp`);
    const lockTemporary = join(h.store.root, `${session.sessionRef}.lock.999999999.${"b".repeat(12)}.locktmp`);
    writeFileSync(stateTemporary, "redacted partial state", { mode: 0o600 });
    writeFileSync(lockTemporary, "partial lock", { mode: 0o600 });
    restarted = new RedactedSessionStore(h.store.root);
    assert(!existsSync(stateTemporary) && !existsSync(lockTemporary), "dead-owner store temporaries recovered at startup");
  } finally {
    restarted?.close();
    h.cleanup();
  }
});

test("idle deadline owners erase raw requests, receipts, and crash temporary files", async () => {
  const h = harness({ exchangeTtlMs: 1_000, receiptTtlMs: 10, regionEvidenceTtlMs: 2_000 });
  try {
    const direct = h.exchange.createRequest({
      tenantRef: "a".repeat(64), sessionRef: "b".repeat(64), sequence: 9,
      prompt: "idle raw", scenarioId: "demo.north", regionEvidenceSha256: "c".repeat(64),
      regionEvidenceExpiresAtMs: Date.now() + 1_000,
    });
    await pause(1_100);
    assert(!h.exchange.pendingIds().includes(direct.requestId), "raw request erased without later traffic");

    const session = h.controller.startSession("tenant-retention", "session-retention");
    const pending = h.controller.submitPrompt(session.sessionRef, "receipt deadline", "demo.north", session.sessionCapability);
    assert(pending.requestId, "request id");
    assert(fulfill(h.exchange, pending.requestId, "receipt response").ok, "response accepted");
    assert(h.controller.completeTurn(pending.requestId, session.sessionCapability).ok, "receipt committed");
    await pause(40);
    equal(h.store.loadSession(session.sessionRef, session.sessionCapability).receipts.length, 0, "receipt erased without later session access");

    const liveTemporary = join(h.exchange.root, `.${"c".repeat(64)}.request.json.${process.pid}.${"d".repeat(12)}.tmp`);
    writeFileSync(liveTemporary, "LIVE_OWNER_CANARY", { mode: 0o600 });
    h.exchange.sweepExpired();
    assert(existsSync(liveTemporary), "live-owner exchange temporary is never stolen");
    rmSync(liveTemporary);

    const temporary = join(h.exchange.root, `.${"d".repeat(64)}.request.json.999999999.${"e".repeat(12)}.tmp`);
    writeFileSync(temporary, "RAW_PROMPT_CANARY", { mode: 0o600 });
    h.exchange.close();
    const restarted = new ExternalAgentExchange(h.exchange.root, { ttlMs: 1_000 });
    try { assert(!existsSync(temporary), "owned crash temporary erased at startup"); }
    finally { restarted.close(); }
  } finally { h.cleanup(); }
});

test("session and pending admission refuse before bounded ceilings", () => {
  const h = harness({ maxSessions: 2, maxPending: 2 });
  try {
    const first = h.controller.startSession("tenant-capacity", "session-1");
    const second = h.controller.startSession("tenant-capacity", "session-2");
    assert(h.controller.submitPrompt(first.sessionRef, "one", "demo.north", first.sessionCapability).ok, "first active session");
    assert(h.controller.submitPrompt(second.sessionRef, "two", "demo.north", second.sessionCapability).ok, "second active session");
    const third = h.controller.startSession("tenant-capacity", "session-3");
    assert(!third.ok && third.holds.includes("session_store_capacity_reached"), "third active session refused before write");
    equal(h.store.audit().sessionCount, 2, "session ceiling preserved");

    const oneMore = h.controller.submitPrompt(first.sessionRef, "one more", "demo.north", first.sessionCapability);
    assert(oneMore.ok, "second pending turn admitted");
    const overPending = h.controller.submitPrompt(first.sessionRef, "too many", "demo.north", first.sessionCapability);
    assert(!overPending.ok && overPending.errors.includes("session_pending_capacity_reached"), "pending ceiling refuses before write");
    equal(h.store.loadSession(first.sessionRef, first.sessionCapability).pending.length, 2, "pending ceiling preserved");
  } finally { h.cleanup(); }
});

test("expired durable pending turns release global session capacity without bearer return", () => {
  let now = 10_000;
  const h = harness({ now: () => now, maxSessions: 2, exchangeTtlMs: 1_000, regionEvidenceTtlMs: 2_000 });
  try {
    for (const id of ["one", "two"]) {
      const session = h.controller.startSession(`tenant-expiry-${id}`, `session-expiry-${id}`);
      const pending = h.controller.submitPrompt(session.sessionRef, `expire ${id}`, "demo.north", session.sessionCapability);
      assert(pending.ok, `pending ${id} created`);
    }
    now += 2_001;
    const health = h.controller.health();
    assert(health.ok, "expiry reconciliation heals raw and durable state together");
    equal(health.metrics.pendingCount, 0, "no expired durable pending rows remain");
    equal(health.metrics.sessionCount, 0, "sessions emptied by expiry are reclaimed");
    const admitted = h.controller.startSession("tenant-expiry-three", "session-expiry-three");
    assert(admitted.ok, "capacity is available without either discarded bearer capability");
  } finally { h.cleanup(); }
});

test("completion revalidates request and region deadlines after attestation", () => {
  let now = 1_000;
  const h = harness({
    now: () => now,
    exchangeTtlMs: 100,
    regionEvidenceTtlMs: 100,
    attestor: () => { now = 5_000; return "attestation:test"; },
  });
  try {
    const session = h.controller.startSession("tenant-attestor", "session-attestor");
    const pending = h.controller.submitPrompt(session.sessionRef, "deadline crossing", "demo.north", session.sessionCapability);
    assert(pending.requestId, "request id");
    assert(fulfill(h.exchange, pending.requestId, "on-time response").ok, "response accepted before deadline");
    const result = h.controller.completeTurn(pending.requestId, session.sessionCapability);
    assert(!result.ok && result.holds.includes("request_expired_after_attestation"), "post-attestor request expiry holds");
    const state = h.store.loadSession(session.sessionRef, session.sessionCapability);
    equal(state.receipts.length, 0, "no expired receipt committed");
    equal(state.pending.length, 0, "expired pending turn retired");
  } finally { h.cleanup(); }
});

test("completion fences the exact pending generation again after attestation", () => {
  let statePath = "";
  const h = harness({
    attestor: () => {
      const state = JSON.parse(readFileSync(statePath, "utf8")) as { pending: Array<{ observation: { querySimhash: string } }> };
      state.pending[0].observation.querySimhash = "f".repeat(16);
      writeFileSync(statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 });
      return "attestation:fenced";
    },
  });
  try {
    const session = h.controller.startSession("tenant-fence", "session-fence");
    statePath = join(h.store.root, `${session.sessionRef}.json`);
    const pending = h.controller.submitPrompt(session.sessionRef, "fence pending state", "demo.north", session.sessionCapability);
    assert(pending.requestId, "request id");
    assert(fulfill(h.exchange, pending.requestId, "fenced response").ok, "response accepted");
    const completed = h.controller.completeTurn(pending.requestId, session.sessionCapability);
    assert(!completed.ok && completed.holds.includes("request_state_changed_after_attestation"), "post-attestor pending substitution held");
    equal(h.store.loadSession(session.sessionRef, session.sessionCapability).receipts.length, 0, "substituted pending state cannot commit a receipt");
  } finally { h.cleanup(); }
});

test("an expired oldest turn is retired so the next still-live turn can complete", () => {
  let now = 1_000;
  const h = harness({ now: () => now, exchangeTtlMs: 100, regionEvidenceTtlMs: 1_000 });
  try {
    const session = h.controller.startSession("tenant-expiry", "session-expiry");
    const first = h.controller.submitPrompt(session.sessionRef, "expires first", "demo.north", session.sessionCapability);
    assert(first.requestId, "first request id");
    now = 1_050;
    const second = h.controller.submitPrompt(session.sessionRef, "still live", "demo.south", session.sessionCapability);
    assert(second.requestId, "second request id");
    assert(fulfill(h.exchange, second.requestId, "live response").ok, "second response accepted");
    now = 1_101;
    const expired = h.controller.completeTurn(first.requestId, session.sessionCapability);
    assert(!expired.ok && expired.holds.includes("request_expired"), "first turn expires and retires");
    assert(h.controller.completeTurn(second.requestId, session.sessionCapability).ok, "later live turn completes after retirement");
    const state = h.store.loadSession(session.sessionRef, session.sessionCapability);
    equal(state.pending.length, 0, "no poisoned pending turns remain");
    equal(state.receipts.length, 1, "later receipt committed");
  } finally { h.cleanup(); }
});

test("browser mutation and status routes require the exact session capability", () => {
  const h = harness();
  const agentToken = "agent-token-".padEnd(40, "x");
  try {
    const created = dispatchDrawbridgeHttp(h.controller, agentToken, {
      method: "POST", path: "/api/sessions", body: { tenantId: "cap-tenant", sessionId: "cap-session" },
    });
    equal(created.status, 200, "new session status");
    const session = created.body as Record<string, unknown>;
    assert(typeof session.sessionRef === "string" && typeof session.sessionCapability === "string"
      && typeof session.sessionResumeToken === "string", "ephemeral capability and scoped resume token returned");
    const body = { sessionRef: session.sessionRef, prompt: "capability bound", scenarioId: "demo.north" };
    equal(dispatchDrawbridgeHttp(h.controller, agentToken, { method: "POST", path: "/api/prompts", body }).status, 401, "missing capability refused");
    equal(dispatchDrawbridgeHttp(h.controller, agentToken, {
      method: "POST", path: "/api/prompts", body, sessionCapability: "0".repeat(64),
    }).status, 403, "wrong capability refused");
    const admitted = dispatchDrawbridgeHttp(h.controller, agentToken, {
      method: "POST", path: "/api/prompts", body, sessionCapability: session.sessionCapability as string,
    });
    equal(admitted.status, 202, "exact capability admits prompt");
    const requestId = (admitted.body as Record<string, unknown>).requestId as string;
    equal(dispatchDrawbridgeHttp(h.controller, agentToken, { method: "GET", path: `/api/sessions/${session.sessionRef}` }).status, 401, "status capability required");
    equal(dispatchDrawbridgeHttp(h.controller, agentToken, {
      method: "POST", path: `/api/turns/${requestId}/complete`, body: {}, sessionCapability: "0".repeat(64),
    }).status, 403, "completion capability bound to request session");
    equal(dispatchDrawbridgeHttp(h.controller, agentToken, {
      method: "DELETE", path: `/api/sessions/${session.sessionRef}`,
    }).status, 401, "erasure capability required");

    const reopened = dispatchDrawbridgeHttp(h.controller, agentToken, {
      method: "POST", path: "/api/sessions", body: { tenantId: "cap-tenant", sessionId: "cap-session" },
    });
    equal(reopened.status, 409, "known identity cannot mint another capability");
    const resumed = dispatchDrawbridgeHttp(h.controller, agentToken, {
      method: "POST", path: "/api/sessions",
      body: { tenantId: "cap-tenant", sessionId: "cap-session", resumeToken: session.sessionResumeToken },
    });
    equal(resumed.status, 200, "scoped resume token reacquires an ephemeral capability");
    const resumedBody = resumed.body as Record<string, unknown>;
    assert(resumedBody.sessionCapability !== session.sessionCapability, "resume rotates the ephemeral mutation capability");
    equal(dispatchDrawbridgeHttp(h.controller, agentToken, {
      method: "GET", path: `/api/sessions/${session.sessionRef}`, sessionCapability: session.sessionCapability as string,
    }).status, 403, "pre-resume capability is rejected after rotation");
    const resumedStatus = dispatchDrawbridgeHttp(h.controller, agentToken, {
      method: "GET", path: `/api/sessions/${session.sessionRef}`, sessionCapability: resumedBody.sessionCapability as string,
    });
    equal(resumedStatus.status, 200, "rotated capability authorizes the resumed session");
    equal((resumedStatus.body as Record<string, unknown>).actionablePendingRequestId, requestId, "status names the oldest actionable pending turn");
    const doubleSubmit = dispatchDrawbridgeHttp(h.controller, agentToken, {
      method: "POST", path: "/api/prompts", sessionCapability: resumedBody.sessionCapability as string,
      body: { sessionRef: session.sessionRef, prompt: "must recover first", scenarioId: "demo.south" },
    });
    equal(doubleSubmit.status, 409, "browser API refuses a second prompt behind an unresolved turn");
    assert((doubleSubmit.body as Record<string, unknown>).holds instanceof Array
      && ((doubleSubmit.body as Record<string, unknown>).holds as string[]).includes("session_pending_turn_requires_recovery"), "single-flight recovery hold named");
    equal(dispatchDrawbridgeHttp(h.controller, agentToken, {
      method: "DELETE", path: `/api/sessions/${session.sessionRef}`, sessionCapability: resumedBody.sessionCapability as string,
    }).status, 200, "authorized erasure succeeds");
    const recreated = dispatchDrawbridgeHttp(h.controller, agentToken, {
      method: "POST", path: "/api/sessions", body: { tenantId: "cap-tenant", sessionId: "cap-session" },
    });
    equal(recreated.status, 200, "erased identity creates a fresh authority generation");
    const fresh = recreated.body as Record<string, unknown>;
    assert(fresh.sessionCapability !== session.sessionCapability, "erasure revokes the old mutation capability");
    equal(dispatchDrawbridgeHttp(h.controller, agentToken, {
      method: "GET", path: `/api/sessions/${fresh.sessionRef}`, sessionCapability: session.sessionCapability as string,
    }).status, 403, "old capability cannot cross the recreated generation");
  } finally { h.cleanup(); }
});

test("exported controller and store chokepoints reject omitted capabilities", () => {
  const h = harness();
  try {
    const session = h.controller.startSession("tenant-mandatory-cap", "session-mandatory-cap");
    const statusWithoutCapability = (h.controller.sessionStatus as unknown as (sessionRef: string) => { ok: boolean; holds: string[] })(session.sessionRef);
    assert(!statusWithoutCapability.ok && statusWithoutCapability.holds.includes("session_capability_required"), "controller status requires capability");
    const submitWithoutCapability = (h.controller.submitPrompt as unknown as (
      sessionRef: string, prompt: string, scenarioId: string,
    ) => { ok: boolean; holds: string[] })(session.sessionRef, "must not admit", "demo.north");
    assert(!submitWithoutCapability.ok && submitWithoutCapability.holds.includes("session_capability_required"), "controller mutation requires capability");
    equal(h.exchange.pendingIds(), [], "missing capability cannot emit raw exchange");
    throws(
      () => (h.store.loadSession as unknown as (sessionRef: string) => unknown)(session.sessionRef),
      "session_capability_required",
      "store status requires capability",
    );
    throws(
      () => (h.store.findRequest as unknown as (requestId: string) => unknown)("0".repeat(64)),
      "session_capability_required",
      "store request status requires capability",
    );
    throws(
      () => (h.store.eraseSession as unknown as (sessionRef: string) => unknown)(session.sessionRef),
      "session_capability_required",
      "store mutation requires capability",
    );
    throws(
      () => (h.store.addPending as unknown as (sessionRef: string, pending: unknown) => unknown)(session.sessionRef, {}),
      "session_capability_required",
      "store pending admission requires capability",
    );
    throws(
      () => (h.store.complete as unknown as (sessionRef: string, requestId: string, receipt: unknown) => unknown)(
        session.sessionRef, "0".repeat(64), {},
      ),
      "session_capability_required",
      "store completion requires capability",
    );
    throws(
      () => (h.store.abandonThrough as unknown as (sessionRef: string, requestId: string) => unknown)(
        session.sessionRef, "0".repeat(64),
      ),
      "session_capability_required",
      "store retirement requires capability",
    );
    assert(h.controller.sessionStatus(session.sessionRef, session.sessionCapability).ok, "exact capability still authorizes status");
  } finally { h.cleanup(); }
});

test("CLI response file refuses a regular-file swap before opening", async () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "drawbridge-cli-swap-")));
  try {
    const responsePath = join(root, "response.txt");
    const replacement = join(root, "replacement.txt");
    const tokenPath = join(root, "agent-token");
    writeFileSync(responsePath, "approved bytes", { mode: 0o600 });
    writeFileSync(replacement, "substituted bytes", { mode: 0o600 });
    writeFileSync(tokenPath, `${"t".repeat(32)}\n`, { mode: 0o600 });
    let called = false;
    const exit = await runDrawbridgeCli([
      "agent-respond", "a".repeat(64), "--response-file", responsePath, "--token-file", tokenPath,
    ], {
      beforeResponseFileOpen: () => {
        rmSync(responsePath);
        renameSync(replacement, responsePath);
      },
      requestJson: async () => { called = true; return { ok: true }; },
      writeOut: () => undefined,
      writeError: () => undefined,
    });
    equal(exit, 1, "regular-file substitution held");
    assert(!called, "substituted bytes never cross API seam");
    equal(readFileSync(responsePath, "utf8"), "substituted bytes", "replacement left untouched");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("strict HTTP JSON parser rejects duplicate keys at every depth", () => {
  throws(() => parseStrictJson('{"tenantId":"first","tenantId":"second","sessionId":"s"}'), "request_body_duplicate_key:tenantId", "duplicate root key");
  throws(() => parseStrictJson('{"outer":{"response":"first","response":"second"}}'), "request_body_duplicate_key:response", "duplicate nested key");
  equal(parseStrictJson('{"tenantId":"t","sessionId":"s","nested":[{"x":1}]}'), {
    tenantId: "t", sessionId: "s", nested: [{ x: 1 }],
  }, "valid strict JSON remains semantically identical");
});

test("loopback HTTP rejects cross-site API fetches and ambiguous JSON media types", () => {
  const h = harness();
  try {
    const denied = dispatchDrawbridgeHttp(h.controller, "t".repeat(32), {
      method: "GET", path: "/api/health", secFetchSite: "cross-site",
    });
    equal(denied.status, 403, "cross-site Fetch Metadata is rejected before reconciliation");
    assert((denied.body as RuntimeResult).holds.includes("cross_site_request_forbidden"), "cross-site hold named");
    assert(isExactJsonMediaType("application/json") && isExactJsonMediaType("application/json; charset=utf-8"), "exact JSON types accepted");
    assert(!isExactJsonMediaType("application/jsonp") && !isExactJsonMediaType("application/json; charset=iso-8859-1"),
      "prefix and alternate-charset types rejected");
  } finally { h.cleanup(); }
});

test("loopback server and client expose bounded denial-of-service deadlines", async () => {
  const h = harness();
  const server = createDrawbridgeHttpServer({ controller: h.controller, agentToken: "t".repeat(32) });
  try {
    equal(server.requestTimeout, 10_000, "request deadline");
    equal(server.headersTimeout, 5_000, "header deadline");
    equal(server.keepAliveTimeout, 2_000, "keep-alive deadline");
    equal(server.maxConnections, 32, "connection ceiling");
    equal(server.maxRequestsPerSocket, 32, "per-socket request ceiling");
    await throwsAsync(
      () => requestLoopbackJson("http://127.0.0.1:4317/api/health", { timeoutMs: 31_000 }),
      "loopback_timeout_out_of_range",
      "client deadline is bounded before network I/O",
    );
  } finally { h.cleanup(); }
});

test("runtime source contains no Ollama or OpenRouter transport", () => {
  const sourceRoot = new URL("../src/drawbridge-runtime/", import.meta.url);
  const files = readdirSync(sourceRoot, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".ts"));
  const text = files.map((entry) => readFileSync(new URL(entry.name, sourceRoot), "utf8")).join("\n").toLowerCase();
  assert(!text.includes("ollama"), "Ollama transport present");
  assert(!text.includes("openrouter"), "OpenRouter transport present");
  assert(!text.includes("api/generate"), "model HTTP route present");
});

let passed = 0;
for (const item of tests) {
  try {
    await item.run();
    passed++;
    console.log(`ok - ${item.name}`);
  } catch (error) {
    console.error(`not ok - ${item.name}: ${error instanceof Error ? error.message : String(error)}`);
  }
}
console.log(`${passed}/${tests.length} drawbridge e2e tests passed`);
if (passed !== tests.length) process.exitCode = 1;
