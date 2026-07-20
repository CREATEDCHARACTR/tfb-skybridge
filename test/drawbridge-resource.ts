import { performance } from "node:perf_hooks";
import { ShadowExtractionObserver } from "../src/behavior/extraction/shadow";
import type { InferenceObservation } from "../src/behavior/extraction/types";

const HEAP_DELTA_BUDGET_BYTES = 128 * 1024 * 1024;
const FILL_LATENCY_BUDGET_MS = 10_000;
const scheduler = {
  schedule() { return Symbol("resource-probe-timer"); },
  cancel() {},
};

function hex(value: number): string {
  return value.toString(16).padStart(16, "0");
}

function observation(partition: number, sequence: number): InferenceObservation {
  return {
    tenantToken: hex(1),
    sessionToken: hex(partition + 1),
    sequence: hex(sequence),
    querySimhash: hex(sequence),
    regionToken: hex((sequence % 2) + 1),
  };
}

global.gc?.();
const beforeHeap = process.memoryUsage().heapUsed;
const started = performance.now();
const observer = new ShadowExtractionObserver(undefined, () => 0, scheduler);
let admissionErrors = 0;
for (let partition = 0; partition < observer.config.maxPartitions; partition++) {
  for (let sequence = 1; sequence <= observer.config.maxWindow; sequence++) {
    if (!observer.observe(observation(partition, sequence)).ok) admissionErrors++;
  }
}
const elapsedMs = performance.now() - started;
global.gc?.();
const retainedHeap = process.memoryUsage().heapUsed;
const heapDeltaBytes = Math.max(0, retainedHeap - beforeHeap);
const status = observer.retentionStatus();
const expectedEvents = observer.config.maxPartitions * observer.config.maxWindow;
const errors: string[] = [];
if (admissionErrors !== 0) errors.push("resource_probe_admission_failed");
if (status.metrics.retained_events_total !== expectedEvents) errors.push("retained_event_count_mismatch");
if (status.metrics.active_partitions !== observer.config.maxPartitions) errors.push("active_partition_count_mismatch");
if (heapDeltaBytes > HEAP_DELTA_BUDGET_BYTES) errors.push("default_profile_heap_budget_exceeded");
if (elapsedMs > FILL_LATENCY_BUDGET_MS) errors.push("default_profile_fill_latency_budget_exceeded");
const close = observer.close();
if (!close.ok || close.metrics.retained_events_total !== 0) errors.push("resource_probe_close_failed");

const result = {
  op: "drawbridge.extraction.hard_resource_probe",
  ok: errors.length === 0,
  actions: ["filled_hard_object_ceiling", "measured_heap_after_gc", "closed_observer"],
  skips: [
    "production_traffic_not_replayed",
    "gc_pause_distribution_not_measured",
  ],
  errors,
  metrics: {
    node: process.version,
    gc_exposed: typeof global.gc === "function",
    max_window: observer.config.maxWindow,
    max_candidates_per_observation: observer.config.maxCandidatesPerObservation,
    max_partitions: observer.config.maxPartitions,
    expected_retained_events: expectedEvents,
    measured_retained_events: status.metrics.retained_events_total,
    heap_delta_bytes_after_gc: heapDeltaBytes,
    heap_delta_budget_bytes: HEAP_DELTA_BUDGET_BYTES,
    fill_elapsed_ms: Number(elapsedMs.toFixed(3)),
    fill_latency_budget_ms: FILL_LATENCY_BUDGET_MS,
    admission_errors: admissionErrors,
    authority_granted: false,
    action_ceiling: "OBSERVE_ONLY",
  },
  next: "Treat this as a local hard-object-profile regression gate, not a production capacity claim across runtimes or traffic distributions.",
};

process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
if (!result.ok) process.exit(1);
