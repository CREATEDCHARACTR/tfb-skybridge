import type { DrawbridgeResult, InferenceBoundaryEvent, InferenceObservation, ShadowAssessment } from "./types";
import { isInferenceObservation } from "./producer";

const HARD_MAX_WINDOW = 128;
const HARD_MAX_CANDIDATES = 16;
const HARD_MAX_PARTITIONS = 256;
const HARD_MAX_TTL_MS = 3_600_000;
const SIGNAL_ID = "drawbridge.extraction.region_spread.v1-research" as const;
const HEX64 = /^[0-9a-f]{16}$/;

export interface ShadowExtractionConfig {
  maxWindow: number;
  maxCandidatesPerObservation: number;
  hammingThreshold: number;
  minGridSize: number;
  minRegionCount: number;
  maxPartitions: number;
  ttlMs: number;
}

export interface ExpiryScheduler {
  schedule(callback: () => void, delayMs: number): unknown;
  cancel(handle: unknown): void;
}

const SYSTEM_EXPIRY_SCHEDULER: ExpiryScheduler = {
  schedule(callback, delayMs) {
    const handle = setTimeout(callback, delayMs);
    handle.unref();
    return handle;
  },
  cancel(handle) {
    clearTimeout(handle as ReturnType<typeof setTimeout>);
  },
};

const DEFAULT_CONFIG: ShadowExtractionConfig = {
  maxWindow: 128,
  maxCandidatesPerObservation: 16,
  hammingThreshold: 12,
  minGridSize: 4,
  minRegionCount: 2,
  maxPartitions: 256,
  ttlMs: 300_000,
};

interface RetainedObservation {
  observation: InferenceObservation;
  expiresAt: number;
}

interface Partition {
  events: RetainedObservation[];
  edges: Map<string, Set<string>>;
}

function validateConfig(config: ShadowExtractionConfig): void {
  for (const name of Object.keys(DEFAULT_CONFIG) as Array<keyof ShadowExtractionConfig>) {
    if (typeof config[name] !== "number" || !Number.isInteger(config[name])) throw new Error(`${name}_must_be_int`);
  }
  if (config.maxWindow < 2) throw new Error("maxWindow_must_be_at_least_2");
  if (config.maxWindow > HARD_MAX_WINDOW) throw new Error("maxWindow_exceeds_hard_ceiling");
  if (config.maxCandidatesPerObservation < 1 || config.maxCandidatesPerObservation > config.maxWindow) {
    throw new Error("maxCandidatesPerObservation_out_of_range");
  }
  if (config.maxCandidatesPerObservation > HARD_MAX_CANDIDATES) {
    throw new Error("maxCandidatesPerObservation_exceeds_hard_ceiling");
  }
  if (config.hammingThreshold < 0 || config.hammingThreshold > 64) throw new Error("hammingThreshold_out_of_range");
  if (config.minGridSize < 2) throw new Error("minGridSize_must_be_at_least_2");
  if (config.minGridSize > config.maxWindow) throw new Error("minGridSize_exceeds_window");
  if (config.minRegionCount < 1) throw new Error("minRegionCount_must_be_positive");
  if (config.minRegionCount > config.minGridSize) throw new Error("minRegionCount_exceeds_grid_size");
  if (config.maxPartitions < 1) throw new Error("maxPartitions_must_be_positive");
  if (config.maxPartitions > HARD_MAX_PARTITIONS) throw new Error("maxPartitions_exceeds_hard_ceiling");
  if (config.ttlMs < 1) throw new Error("ttlMs_must_be_positive");
  if (config.ttlMs > HARD_MAX_TTL_MS) throw new Error("ttlMs_exceeds_hard_ceiling");
}

function hamming(left: string, right: string): number {
  let value = BigInt(`0x${left}`) ^ BigInt(`0x${right}`);
  let count = 0;
  while (value) {
    value &= value - 1n;
    count++;
  }
  return count;
}

function assessment(status: ShadowAssessment["status"], reason: string, gridSize?: number, regionCount?: number): ShadowAssessment {
  return {
    status,
    reason,
    signalId: SIGNAL_ID,
    authority: "none",
    ...(gridSize === undefined ? {} : { gridSize }),
    ...(regionCount === undefined ? {} : { regionCount }),
  };
}

export class ShadowExtractionObserver {
  readonly config: ShadowExtractionConfig;
  private readonly now: () => number;
  private readonly scheduler: ExpiryScheduler;
  private readonly partitions = new Map<string, Partition>();
  private expiryTimer: unknown;
  private expiryDeadline: number | undefined;
  private timerGeneration = 0;
  private closed = false;
  private eventsExpiredTotal = 0;
  private windowEvictionsTotal = 0;
  private partitionsEvictedTotal = 0;
  private retentionFailClosedDiscardsTotal = 0;

  constructor(
    config: Partial<ShadowExtractionConfig> = {},
    now: () => number = Date.now,
    scheduler: ExpiryScheduler = SYSTEM_EXPIRY_SCHEDULER,
  ) {
    this.config = Object.freeze({ ...DEFAULT_CONFIG, ...config });
    validateConfig(this.config);
    this.now = now;
    this.scheduler = scheduler;
  }

  private ensureExpiryScheduled(expiresAt: number): boolean {
    if (this.expiryDeadline !== undefined && this.expiryDeadline <= expiresAt && this.expiryDeadline > this.now()) {
      return true;
    }
    const generation = this.timerGeneration + 1;
    let handle: unknown;
    try {
      handle = this.scheduler.schedule(() => {
        if (generation !== this.timerGeneration) return;
        this.expiryTimer = undefined;
        this.expiryDeadline = undefined;
        if (this.closed) return;
        this.pruneExpired(this.now());
        if (!this.armNextExpiry()) this.discardAllRetainedState();
      }, Math.max(0, expiresAt - this.now()));
    } catch {
      return false;
    }
    if (this.expiryTimer !== undefined) {
      try {
        this.scheduler.cancel(this.expiryTimer);
      } catch {
        try {
          this.scheduler.cancel(handle);
        } catch {
          // The untracked replacement callback is generation-inert.
        }
        return false;
      }
    }
    this.timerGeneration = generation;
    this.expiryTimer = handle;
    this.expiryDeadline = expiresAt;
    return true;
  }

  private armNextExpiry(): boolean {
    let earliest: number | undefined;
    for (const partition of this.partitions.values()) {
      for (const retained of partition.events) {
        if (earliest === undefined || retained.expiresAt < earliest) earliest = retained.expiresAt;
      }
    }
    return earliest === undefined || this.ensureExpiryScheduled(earliest);
  }

  private discardAllRetainedState(): void {
    const retainedCount = this.clearAllRetainedState();
    this.retentionFailClosedDiscardsTotal += retainedCount;
  }

  private clearAllRetainedState(): number {
    const retainedCount = [...this.partitions.values()]
      .reduce((total, partition) => total + partition.events.length, 0);
    for (const partition of this.partitions.values()) {
      partition.events.length = 0;
      partition.edges.clear();
    }
    this.partitions.clear();
    return retainedCount;
  }

  private resetExpirySchedule(): void {
    this.timerGeneration++;
    if (this.expiryTimer !== undefined) {
      try {
        this.scheduler.cancel(this.expiryTimer);
      } catch {
        // A stale callback is harmless: callbacks re-check `closed` and current state.
      }
    }
    this.expiryTimer = undefined;
    this.expiryDeadline = undefined;
    if (!this.closed && !this.armNextExpiry()) this.discardAllRetainedState();
  }

  private pruneAndReconcile(now: number): void {
    this.pruneExpired(now);
    if (this.expiryDeadline !== undefined && this.expiryDeadline <= now) this.resetExpirySchedule();
  }

  private removeEvent(partition: Partition, sequence: string): void {
    const neighbors = partition.edges.get(sequence) ?? new Set<string>();
    partition.edges.delete(sequence);
    for (const neighbor of neighbors) partition.edges.get(neighbor)?.delete(sequence);
  }

  private pruneExpired(now: number): void {
    for (const [key, partition] of [...this.partitions]) {
      const alive: RetainedObservation[] = [];
      for (const retained of partition.events) {
        if (retained.expiresAt <= now) {
          this.removeEvent(partition, retained.observation.sequence);
          this.eventsExpiredTotal++;
        } else {
          alive.push(retained);
        }
      }
      partition.events = alive;
      if (alive.length === 0) this.partitions.delete(key);
    }
  }

  private state(key: string): Partition {
    const existing = this.partitions.get(key);
    if (existing) {
      this.partitions.delete(key);
      this.partitions.set(key, existing);
      return existing;
    }
    if (this.partitions.size >= this.config.maxPartitions) {
      const oldest = this.partitions.keys().next().value as string | undefined;
      if (oldest !== undefined) this.partitions.delete(oldest);
      this.partitionsEvictedTotal++;
    }
    const created: Partition = { events: [], edges: new Map() };
    this.partitions.set(key, created);
    return created;
  }

  private component(partition: Partition, start: string): Set<string> {
    const seen = new Set<string>();
    const pending = [start];
    while (pending.length && seen.size < this.config.maxWindow) {
      const current = pending.pop() as string;
      if (seen.has(current)) continue;
      seen.add(current);
      for (const neighbor of partition.edges.get(current) ?? []) if (!seen.has(neighbor)) pending.push(neighbor);
    }
    return seen;
  }

  private metrics(partition: Partition | undefined, comparisons: number): Record<string, unknown> {
    const retainedEdges = partition
      ? [...partition.edges.values()].reduce((total, neighbors) => total + neighbors.size, 0) / 2
      : 0;
    return {
      partition_event_count: partition?.events.length ?? 0,
      comparisons,
      comparison_ceiling: this.config.maxCandidatesPerObservation,
      window_ceiling: this.config.maxWindow,
      active_partitions: this.partitions.size,
      partition_ceiling: this.config.maxPartitions,
      retained_edges: retainedEdges,
      events_expired_total: this.eventsExpiredTotal,
      window_evictions_total: this.windowEvictionsTotal,
      partitions_evicted_total: this.partitionsEvictedTotal,
      retention_fail_closed_discards_total: this.retentionFailClosedDiscardsTotal,
      retention_ttl_ms: this.config.ttlMs,
      retained_events_total: [...this.partitions.values()]
        .reduce((total, retainedPartition) => total + retainedPartition.events.length, 0),
      raw_payload_retained: false,
      observer_closed: this.closed,
      authority_granted: false,
      action_ceiling: "OBSERVE_ONLY",
    };
  }

  retentionStatus(): DrawbridgeResult {
    return {
      op: "drawbridge.extraction.retention_status",
      ok: true,
      actions: ["reported_redacted_retention_counts"],
      skips: ["retained_identifiers_not_exposed", "retention_deadline_not_extended"],
      errors: [],
      metrics: this.metrics(undefined, 0),
      next: "Retained event count should return to zero after the configured TTL without new traffic.",
    };
  }

  private erasureMetrics(eventsErased: number): Record<string, unknown> {
    return {
      ...this.metrics(undefined, 0),
      events_erased: eventsErased,
      erasure_scope: "logical_in_process_reference_removal",
      erasure_witness_kind: "operation_result_count_only",
      memory_zeroization_verified: false,
    };
  }

  private result(ok: boolean, errors: string[], currentAssessment: ShadowAssessment, partition?: Partition, comparisons = 0): DrawbridgeResult {
    return {
      op: "drawbridge.extraction.shadow_observe",
      ok,
      actions: ok ? ["pruned_expired_state", "evaluated_bounded_shadow_evidence"] : [],
      skips: ["raw_payload_not_admitted", "policy_action_not_evaluated", "behavioral_monitor_not_modified"],
      errors,
      metrics: this.metrics(partition, comparisons),
      next: "Keep this evidence in shadow review; this observer cannot act or join the revocation monitor.",
      assessment: currentAssessment,
    };
  }

  observeBoundary(event: InferenceBoundaryEvent): DrawbridgeResult {
    if (this.closed) {
      return this.result(false, ["observer_closed"], assessment("INSUFFICIENT_EVIDENCE", "observer_closed"));
    }
    if (!event.inference) {
      this.pruneAndReconcile(this.now());
      return this.result(true, [], assessment("INSUFFICIENT_EVIDENCE", "inference_observation_missing"));
    }
    return this.observe(event.inference);
  }

  observe(observation: InferenceObservation): DrawbridgeResult {
    if (this.closed) {
      return this.result(false, ["observer_closed"], assessment("INSUFFICIENT_EVIDENCE", "observer_closed"));
    }
    const now = this.now();
    this.pruneAndReconcile(now);
    if (!isInferenceObservation(observation)) {
      return this.result(false, ["observation_contract_invalid"], assessment("INSUFFICIENT_EVIDENCE", "observation_contract_invalid"));
    }
    const expiresAt = now + this.config.ttlMs;
    if (!this.ensureExpiryScheduled(expiresAt)) {
      return this.result(false, ["expiry_scheduler_unavailable"], assessment("INSUFFICIENT_EVIDENCE", "expiry_scheduler_unavailable"));
    }
    const key = `${observation.tenantToken}:${observation.sessionToken}`;
    const partition = this.state(key);
    const prior = partition.events.at(-1)?.observation;
    if (prior && BigInt(`0x${observation.sequence}`) <= BigInt(`0x${prior.sequence}`)) {
      return this.result(false, ["sequence_not_monotonic"], assessment("INSUFFICIENT_EVIDENCE", "sequence_not_monotonic"), partition);
    }
    if (partition.events.length >= this.config.maxWindow) {
      const evicted = partition.events.shift();
      if (evicted) this.removeEvent(partition, evicted.observation.sequence);
      this.windowEvictionsTotal++;
    }
    const candidates = partition.events.slice(-this.config.maxCandidatesPerObservation);
    partition.edges.set(observation.sequence, new Set());
    for (const retained of candidates) {
      const candidate = retained.observation;
      if (candidate.querySimhash === observation.querySimhash) continue;
      if (hamming(candidate.querySimhash, observation.querySimhash) <= this.config.hammingThreshold) {
        partition.edges.get(observation.sequence)?.add(candidate.sequence);
        const reverse = partition.edges.get(candidate.sequence) ?? new Set<string>();
        reverse.add(observation.sequence);
        partition.edges.set(candidate.sequence, reverse);
      }
    }
    partition.events.push({ observation, expiresAt });
    const component = this.component(partition, observation.sequence);
    const bySequence = new Map(partition.events.map((retained) => [retained.observation.sequence, retained.observation]));
    const regions = new Set([...component].map((sequence) => bySequence.get(sequence)?.regionToken).filter(Boolean));
    const gridSize = component.size;
    const regionCount = regions.size;
    const currentAssessment = gridSize < this.config.minGridSize
      ? assessment("INSUFFICIENT_EVIDENCE", "grid_size_below_floor", gridSize, regionCount)
      : regionCount < this.config.minRegionCount
        ? assessment("INSUFFICIENT_EVIDENCE", "region_spread_below_floor", gridSize, regionCount)
        : assessment("CANDIDATE_EVIDENCE", "region_spread_candidate_observed", gridSize, regionCount);
    return this.result(true, [], currentAssessment, partition, candidates.length);
  }

  erasePartition(tenantToken: string, sessionToken: string): DrawbridgeResult {
    if (!HEX64.test(tenantToken) || !HEX64.test(sessionToken)) {
      return {
        op: "drawbridge.extraction.erase_partition",
        ok: false,
        actions: [],
        skips: ["invalid_partition_identity_not_used"],
        errors: ["partition_identity_contract_invalid"],
        metrics: this.metrics(undefined, 0),
        next: "Supply the two opaque uint64-hex partition tokens; raw identifiers are not accepted.",
      };
    }
    this.pruneAndReconcile(this.now());
    const partition = this.partitions.get(`${tenantToken}:${sessionToken}`);
    const eventsErased = partition?.events.length ?? 0;
    if (partition) {
      partition.events.length = 0;
      partition.edges.clear();
      this.partitions.delete(`${tenantToken}:${sessionToken}`);
    }
    this.resetExpirySchedule();
    const expiryRebound = this.expiryTimer !== undefined;
    return {
      op: "drawbridge.extraction.erase_partition",
      ok: true,
      actions: partition ? ["erased_partition_state", ...(expiryRebound ? ["rebound_expiry_timer"] : [])] : [],
      skips: partition
        ? ["partition_identity_not_exposed", ...(expiryRebound ? [] : ["expiry_timer_not_needed_no_remaining_state"])]
        : ["partition_absent_nothing_to_erase"],
      errors: [],
      metrics: this.erasureMetrics(eventsErased),
      next: "The selected session's sketches and graph links are no longer retained by this observer.",
    };
  }

  close(): DrawbridgeResult {
    if (this.closed) {
      return {
        op: "drawbridge.extraction.close",
        ok: true,
        actions: [],
        skips: ["observer_already_closed"],
        errors: [],
        metrics: this.erasureMetrics(0),
        next: "The observer remains closed and cannot retain new observations.",
      };
    }
    this.closed = true;
    this.timerGeneration++;
    const timerWasScheduled = this.expiryTimer !== undefined;
    if (timerWasScheduled) {
      try {
        this.scheduler.cancel(this.expiryTimer);
      } catch {
        // The stale callback returns immediately because `closed` is now true.
      }
    }
    this.expiryTimer = undefined;
    this.expiryDeadline = undefined;
    const eventsErased = this.clearAllRetainedState();
    return {
      op: "drawbridge.extraction.close",
      ok: true,
      actions: [...(timerWasScheduled ? ["cancelled_expiry_timer"] : []), "erased_all_retained_state", "closed_observer"],
      skips: ["retained_identifiers_not_exposed", ...(timerWasScheduled ? [] : ["expiry_timer_not_present"])],
      errors: [],
      metrics: this.erasureMetrics(eventsErased),
      next: "Create a new observer instance before accepting any future shadow observations.",
    };
  }
}
