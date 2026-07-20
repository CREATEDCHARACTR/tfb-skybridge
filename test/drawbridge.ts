import { produceInferenceObservation } from "../src/behavior/extraction/producer";
import { ShadowExtractionObserver } from "../src/behavior/extraction/shadow";
import type { InferenceObservation } from "../src/behavior/extraction/types";

type Case = { name: string; fn: () => void };
const cases: Case[] = [];
function test(name: string, fn: () => void) { cases.push({ name, fn }); }
function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}
function equal(actual: unknown, expected: unknown, message: string) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${message}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}
function throws(fn: () => unknown, expected: string) {
  try { fn(); } catch (error) {
    assert(error instanceof Error && error.message === expected, `expected ${expected}, got ${String(error)}`);
    return;
  }
  throw new Error(`expected ${expected}, no throw`);
}

const secret = Buffer.alloc(32, 7);

test("producer emits only five fixed-width opaque fields", () => {
  const result = produceInferenceObservation({
    tenantId: "tenant-canary",
    sessionId: "session-canary",
    sequence: 1n,
    rawQuery: "raw-query-canary alpha beta gamma",
    regionLabel: "region-canary",
  }, secret);

  assert(result.ok && result.observation, "producer should emit an observation");
  equal(Object.keys(result.observation).sort(), [
    "querySimhash", "regionToken", "sequence", "sessionToken", "tenantToken",
  ], "observation field contract");
  for (const value of Object.values(result.observation)) {
    assert(/^[0-9a-f]{16}$/.test(value), `not uint64 hex: ${value}`);
  }
  const serialized = JSON.stringify(result);
  for (const canary of ["raw-query-canary", "tenant-canary", "session-canary", "region-canary"]) {
    assert(!serialized.includes(canary), `raw canary escaped: ${canary}`);
  }
  assert(result.metrics.raw_payload_retained === false, "raw retention must be false");
});

test("producer is deterministic and domain-separates opaque tokens", () => {
  const input = { tenantId: "t1", sessionId: "s1", sequence: 9n, rawQuery: "alpha beta gamma", regionLabel: "r1" };
  const first = produceInferenceObservation(input, secret);
  const second = produceInferenceObservation(input, secret);
  assert(first.ok && first.observation && second.ok && second.observation, "expected observations");
  equal(first.observation, second.observation, "deterministic output");

  const other = produceInferenceObservation({ ...input, tenantId: "t2", sessionId: "s2", regionLabel: "r2" }, secret);
  assert(other.ok && other.observation, "expected other observation");
  assert(first.observation.tenantToken !== other.observation.tenantToken, "tenant tokens must separate");
  assert(first.observation.sessionToken !== other.observation.sessionToken, "session tokens must separate");
  assert(first.observation.regionToken !== other.observation.regionToken, "region tokens must separate");
  assert(first.observation.querySimhash !== other.observation.querySimhash, "query sketches must be tenant scoped");
});

test("producer fails closed on incomplete or unsafe inputs", () => {
  const base = {
    tenantId: "raw-tenant-error-canary",
    sessionId: "raw-session-error-canary",
    sequence: 1n,
    rawQuery: "raw-query-error-canary",
    regionLabel: "raw-region-error-canary",
  };
  const badSecret = produceInferenceObservation(base, Buffer.alloc(8));
  const missingRegion = produceInferenceObservation({ ...base, regionLabel: "" }, secret);
  const missingQuery = produceInferenceObservation({ ...base, rawQuery: "" }, secret);
  const overflow = produceInferenceObservation({ ...base, sequence: 1n << 64n }, secret);
  for (const result of [badSecret, missingRegion, missingQuery, overflow]) {
    assert(!result.ok && result.observation === undefined, "invalid input must not emit");
    assert(result.metrics.raw_payload_retained === false, "invalid path must not retain raw payload");
    const serialized = JSON.stringify(result);
    for (const canary of [base.tenantId, base.sessionId, base.rawQuery, base.regionLabel]) {
      assert(!serialized.includes(canary), `invalid path leaked raw canary: ${canary}`);
    }
  }
});

const observation = (seq: number, sketch: number, region: number): InferenceObservation => ({
  tenantToken: "0000000000000001",
  sessionToken: "0000000000000002",
  sequence: seq.toString(16).padStart(16, "0"),
  querySimhash: sketch.toString(16).padStart(16, "0"),
  regionToken: region.toString(16).padStart(16, "0"),
});

test("shadow observer emits candidate evidence without authority", () => {
  let now = 0;
  const observer = new ShadowExtractionObserver({
    maxWindow: 16,
    maxCandidatesPerObservation: 8,
    hammingThreshold: 3,
    minGridSize: 4,
    minRegionCount: 2,
    maxPartitions: 4,
    ttlMs: 1_000,
  }, () => now);
  let result;
  for (const [seq, sketch, region] of [[1, 0, 1], [2, 1, 1], [3, 3, 2], [4, 2, 2]]) {
    result = observer.observe(observation(seq, sketch, region));
    now += 10;
  }
  assert(result?.ok && result.assessment, "observation should succeed");
  equal(result.assessment.status, "CANDIDATE_EVIDENCE", "candidate status");
  equal([result.metrics.authority_granted, result.metrics.action_ceiling], [false, "OBSERVE_ONLY"], "authority boundary");
  const serialized = JSON.stringify(result);
  for (const field of ["tenantToken", "sessionToken", "querySimhash", "regionToken"]) {
    assert(!serialized.includes(field), `result leaked input field name ${field}`);
  }
});

test("time expiry removes observations and graph links before scoring", () => {
  let now = 0;
  const observer = new ShadowExtractionObserver({
    maxWindow: 4,
    maxCandidatesPerObservation: 2,
    hammingThreshold: 64,
    minGridSize: 2,
    minRegionCount: 1,
    maxPartitions: 2,
    ttlMs: 100,
  }, () => now);
  observer.observe(observation(1, 1, 1));
  now = 50;
  observer.observe(observation(2, 2, 2));
  now = 151;
  const result = observer.observe(observation(1, 3, 3));

  assert(result.ok && result.assessment, "expired partition may begin a fresh sequence");
  equal(result.assessment.reason, "grid_size_below_floor", "expired links must not count");
  equal(result.metrics.partition_event_count, 1, "only fresh observation remains");
  equal(result.metrics.events_expired_total, 2, "expiry count");
});

test("time expiry deletes quiet state without another observation", () => {
  let now = 0;
  let callback: (() => void) | undefined;
  let delay = -1;
  const observer = new ShadowExtractionObserver({ ttlMs: 100 }, () => now, {
    schedule(next, delayMs) {
      callback = next;
      delay = delayMs;
      return Symbol("timer");
    },
    cancel() {
      callback = undefined;
    },
  });

  const admitted = observer.observe(observation(1, 1, 1));
  assert(admitted.ok, "observation should be admitted with an expiry timer");
  equal(delay, 100, "timer should bind to the retention deadline");
  assert(callback, "expiry callback must be scheduled");

  now = 100;
  callback();
  const status = observer.retentionStatus();
  equal(status.metrics.retained_events_total, 0, "quiet expired event must be deleted");
  equal(status.metrics.active_partitions, 0, "empty partition must be deleted");
  equal(status.metrics.events_expired_total, 1, "autonomous expiry count");
});

test("scheduler failure refuses retention", () => {
  const observer = new ShadowExtractionObserver({ ttlMs: 100 }, () => 0, {
    schedule() { throw new Error("timer unavailable"); },
    cancel() {},
  });
  const result = observer.observe(observation(1, 1, 1));
  assert(!result.ok, "observation must not be retained without its expiry boundary");
  equal(result.errors, ["expiry_scheduler_unavailable"], "scheduler failure reason");
  equal(observer.retentionStatus().metrics.retained_events_total, 0, "failed admission must leave no state");
});

test("scheduler rearm failure discards already-retained state", () => {
  let now = 0;
  let callback: (() => void) | undefined;
  let schedules = 0;
  const observer = new ShadowExtractionObserver({ ttlMs: 100 }, () => now, {
    schedule(next) {
      schedules++;
      if (schedules > 1) throw new Error("timer unavailable");
      callback = next;
      return Symbol("timer");
    },
    cancel() {},
  });

  assert(observer.observe(observation(1, 1, 1)).ok, "first observation should be admitted");
  now = 50;
  assert(observer.observe(observation(2, 2, 2)).ok, "later observation shares the earlier timer");
  now = 100;
  assert(callback, "first expiry callback must exist");
  callback();

  const status = observer.retentionStatus();
  equal(status.metrics.retained_events_total, 0, "unprotected retained state must be discarded");
  equal(status.metrics.retention_fail_closed_discards_total, 1, "discard must narrate itself");
});

test("cancelled stale timer cannot discard state protected by its replacement", () => {
  let now = 0;
  const callbacks: Array<() => void> = [];
  let schedules = 0;
  const observer = new ShadowExtractionObserver({ ttlMs: 100 }, () => now, {
    schedule(next) {
      schedules++;
      if (schedules > 2) throw new Error("unexpected stale callback rearm");
      callbacks.push(next);
      return Symbol(`timer-${schedules}`);
    },
    cancel() {
      // Deliberately leave the callback runnable to model an already-queued timer.
    },
  });
  observer.observe(observation(1, 1, 1));
  observer.observe({ ...observation(1, 2, 2), sessionToken: "0000000000000003" });
  observer.erasePartition("0000000000000001", "0000000000000002");
  equal(schedules, 2, "erasure should replace the timer for remaining state");

  callbacks[0]();
  equal(observer.retentionStatus().metrics.retained_events_total, 1, "stale callback must be inert");
  equal(observer.retentionStatus().metrics.retention_fail_closed_discards_total, 0, "stale callback must not trigger fail-closed discard");
  observer.close();
});

test("access-time pruning replaces an already-due timer before new admission", () => {
  let now = 0;
  let schedules = 0;
  const observer = new ShadowExtractionObserver({ ttlMs: 100 }, () => now, {
    schedule() {
      schedules++;
      return Symbol(`timer-${schedules}`);
    },
    cancel() {},
  });
  observer.observe(observation(1, 1, 1));
  now = 101;
  observer.observeBoundary({ seq: 2, kind: "host-message", bytes: 0, ts: new Date(now).toISOString() });
  observer.observe(observation(1, 2, 2));
  equal(schedules, 2, "new state must not rely on an already-due timer");
  observer.close();
});

test("partition erasure removes one session without leaking its tokens", () => {
  const observer = new ShadowExtractionObserver({ ttlMs: 1_000 }, () => 0);
  observer.observe(observation(1, 1, 1));
  const other = { ...observation(1, 2, 2), sessionToken: "0000000000000003" };
  observer.observe(other);

  const erased = observer.erasePartition("0000000000000001", "0000000000000002");
  assert(erased.ok, "partition erasure should succeed");
  equal(erased.metrics.events_erased, 1, "one event should be erased");
  equal(erased.metrics.retained_events_total, 1, "unrelated partition should remain");
  equal(erased.metrics.erasure_scope, "logical_in_process_reference_removal", "erasure scope");
  equal(erased.metrics.memory_zeroization_verified, false, "logical erasure must not claim memory zeroization");
  equal(erased.metrics.erasure_witness_kind, "operation_result_count_only", "bounded erasure witness");
  const serialized = JSON.stringify(erased);
  assert(!serialized.includes("0000000000000001"), "tenant token must not escape in erasure result");
  assert(!serialized.includes("0000000000000002"), "session token must not escape in erasure result");

  const restarted = observer.observe(observation(1, 3, 3));
  assert(restarted.ok, "erased session may begin a fresh sequence");
  observer.close();
});

test("close erases all state and permanently refuses new observations", () => {
  let cancelled = 0;
  const observer = new ShadowExtractionObserver({ ttlMs: 1_000 }, () => 0, {
    schedule() { return Symbol("timer"); },
    cancel() { cancelled++; },
  });
  observer.observe(observation(1, 1, 1));
  const closed = observer.close();
  assert(closed.ok, "close should succeed");
  equal(closed.metrics.events_erased, 1, "close should narrate erased state");
  equal(closed.metrics.retained_events_total, 0, "close must empty retention");
  equal(closed.metrics.erasure_scope, "logical_in_process_reference_removal", "close erasure scope");
  equal(closed.metrics.memory_zeroization_verified, false, "close must not claim memory zeroization");
  equal(cancelled, 1, "close should cancel the live timer");
  const rejected = observer.observe(observation(2, 2, 2));
  equal(rejected.errors, ["observer_closed"], "closed observer must reject reuse");
  equal(observer.retentionStatus().metrics.retained_events_total, 0, "closed observer remains empty");
});

test("missing inference observation is insufficient, never benign or actionable", () => {
  const observer = new ShadowExtractionObserver(undefined, () => 0);
  const result = observer.observeBoundary({ seq: 1, kind: "host-message", bytes: 10, ts: new Date(0).toISOString() });
  assert(result.ok, "missing optional evidence is an observed hold");
  equal(result.assessment, {
    status: "INSUFFICIENT_EVIDENCE",
    reason: "inference_observation_missing",
    signalId: "drawbridge.extraction.region_spread.v1-research",
    authority: "none",
  }, "missing evidence assessment");
  equal([result.metrics.authority_granted, result.metrics.action_ceiling], [false, "OBSERVE_ONLY"], "missing evidence authority");
});

test("resource and retention configuration is exact-integer, coherent, and hard-bounded", () => {
  equal(new ShadowExtractionObserver().config, {
    maxWindow: 128,
    maxCandidatesPerObservation: 16,
    hammingThreshold: 12,
    minGridSize: 4,
    minRegionCount: 2,
    maxPartitions: 256,
    ttlMs: 300_000,
  }, "conservative production defaults");
  throws(() => new ShadowExtractionObserver({ maxWindow: 129 }), "maxWindow_exceeds_hard_ceiling");
  throws(() => new ShadowExtractionObserver({ maxCandidatesPerObservation: 17 }), "maxCandidatesPerObservation_exceeds_hard_ceiling");
  throws(() => new ShadowExtractionObserver({ maxPartitions: 257 }), "maxPartitions_exceeds_hard_ceiling");
  throws(() => new ShadowExtractionObserver({ ttlMs: 3_600_001 }), "ttlMs_exceeds_hard_ceiling");
  throws(() => new ShadowExtractionObserver({ ttlMs: 1.5 }), "ttlMs_must_be_int");
  throws(() => new ShadowExtractionObserver({ maxWindow: 4, maxCandidatesPerObservation: 4, minGridSize: 5 }), "minGridSize_exceeds_window");
  throws(() => new ShadowExtractionObserver({ minGridSize: 4, minRegionCount: 5 }), "minRegionCount_exceeds_grid_size");
});

let passed = 0;
for (const entry of cases) {
  try {
    entry.fn();
    passed++;
    process.stdout.write(`ok   ${entry.name}\n`);
  } catch (error) {
    process.stdout.write(`FAIL ${entry.name}: ${error instanceof Error ? error.message : String(error)}\n`);
  }
}
process.stdout.write(`${passed}/${cases.length} passed\n`);
if (passed !== cases.length) process.exit(1);
