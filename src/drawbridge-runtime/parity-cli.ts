import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync } from "node:fs";
import { isAbsolute, join, parse, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  ShadowExtractionObserver,
  type ExpiryScheduler,
  type ShadowExtractionConfig,
} from "../behavior/extraction/shadow";
import type { DrawbridgeResult, InferenceObservation } from "../behavior/extraction/types";

const CORPUS_SCHEMA = "tfb.drawbridge.cross_language_parity_corpus.v1" as const;
const REPORT_SCHEMA = "tfb.drawbridge.typescript_parity_report.v1" as const;
const SEMANTIC_AUTHORITY = "typescript_shadow_extraction_observer" as const;
const REFERENCE_IMPLEMENTATION = "python_bounded_session_scorer" as const;
const MAX_CORPUS_BYTES = 1_048_576;
export const FROZEN_CORPUS_SHA256 = "2bcb90bf631cdd266b9a4c201c258d23421c12b746f39197db0cb9694cc73380";
const FROZEN_CASE_IDS = [
  "same_region_component",
  "different_region_component",
  "exact_repeat_is_not_an_edge",
  "hamming_boundary",
  "tenant_and_session_partitions",
  "window_eviction",
  "candidate_eviction",
  "partition_lru_eviction",
  "uint64_extremes",
  "monotonic_rejection",
] as const;
const FROZEN_COVERAGE = new Set([
  "same_regions", "different_regions", "exact_repeats", "boundary_hamming", "partitions",
  "window_eviction", "candidate_eviction", "partition_eviction", "uint64_extremes",
  "monotonic_rejection", "failure_state",
]);
const FROZEN_TURN_COUNT = 33;
const HEX64 = /^[0-9a-f]{16}$/;
const SHA256 = /^[0-9a-f]{64}$/;

const ROOT_KEYS = [
  "schema",
  "status",
  "semantic_authority",
  "reference_implementation",
  "time_semantics",
  "authority",
  "cases",
] as const;
const CASE_KEYS = ["case_id", "coverage", "config", "observations", "expected"] as const;
const CONFIG_KEYS = [
  "max_window",
  "max_candidates_per_observation",
  "hamming_threshold",
  "min_grid_size",
  "min_region_count",
  "max_partitions",
] as const;
const OBSERVATION_KEYS = ["tenantToken", "sessionToken", "sequence", "querySimhash", "regionToken"] as const;
const EXPECTED_KEYS = ["ok", "errors", "status", "reason", "grid_size", "region_count"] as const;

export interface ParityConfig {
  max_window: number;
  max_candidates_per_observation: number;
  hamming_threshold: number;
  min_grid_size: number;
  min_region_count: number;
  max_partitions: number;
}

export interface NormalizedParityTurn {
  ok: boolean;
  errors: string[];
  status: "CANDIDATE_EVIDENCE" | "INSUFFICIENT_EVIDENCE";
  reason: string;
  grid_size: number | null;
  region_count: number | null;
}

export interface ParityCase {
  case_id: string;
  coverage: string[];
  config: ParityConfig;
  observations: InferenceObservation[];
  expected: NormalizedParityTurn[];
}

export interface ParityCorpus {
  schema: typeof CORPUS_SCHEMA;
  status: "FROZEN_FOR_REVIEW";
  semantic_authority: typeof SEMANTIC_AUTHORITY;
  reference_implementation: typeof REFERENCE_IMPLEMENTATION;
  time_semantics: {
    mode: "fixed";
    now_ms: number;
    typescript_ttl_ms: number;
  };
  authority: {
    action_ceiling: "OBSERVE_ONLY";
    integration_authorized: false;
    activation_authorized: false;
    production_claim_authorized: false;
  };
  cases: ParityCase[];
}

export interface TypeScriptParityReport {
  schema: typeof REPORT_SCHEMA;
  ok: boolean;
  corpus_sha256: string;
  authority: {
    semantic_authority: typeof SEMANTIC_AUTHORITY;
    reference_implementation: typeof REFERENCE_IMPLEMENTATION;
    action_ceiling: "OBSERVE_ONLY";
  };
  cases: Array<{ case_id: string; turns: NormalizedParityTurn[] }>;
  errors: string[];
}

function objectValue(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label}_object_required`);
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const closed = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(closed)) throw new Error(`corpus_keys_invalid:${label}`);
}

function integer(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isInteger(value)) throw new Error(`${label}_must_be_int`);
  return value;
}

function stringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.some((item) => typeof item !== "string" || !item)) {
    throw new Error(`${label}_invalid`);
  }
  if (new Set(value).size !== value.length) throw new Error(`${label}_duplicate`);
  return [...value] as string[];
}

function parseJsonWithoutDuplicateKeys(raw: string): unknown {
  let index = 0;
  const whitespace = () => {
    while (index < raw.length && (raw[index] === " " || raw[index] === "\t" || raw[index] === "\n" || raw[index] === "\r")) index++;
  };
  const stringValue = (): string => {
    if (raw[index] !== '"') throw new Error("parity_corpus_json_invalid");
    const start = index++;
    let escaped = false;
    while (index < raw.length) {
      const character = raw[index++];
      if (escaped) { escaped = false; continue; }
      if (character === "\\") { escaped = true; continue; }
      if (character === '"') {
        try { return JSON.parse(raw.slice(start, index)) as string; }
        catch { throw new Error("parity_corpus_json_invalid"); }
      }
    }
    throw new Error("parity_corpus_json_invalid");
  };
  const value = (): unknown => {
    whitespace();
    if (raw[index] === "{") {
      index++;
      whitespace();
      const object = Object.create(null) as Record<string, unknown>;
      const keys = new Set<string>();
      if (raw[index] === "}") { index++; return object; }
      while (index < raw.length) {
        whitespace();
        const key = stringValue();
        if (keys.has(key)) throw new Error(`duplicate_json_key:${key}`);
        keys.add(key);
        whitespace();
        if (raw[index++] !== ":") throw new Error("parity_corpus_json_invalid");
        object[key] = value();
        whitespace();
        const separator = raw[index++];
        if (separator === "}") return object;
        if (separator !== ",") throw new Error("parity_corpus_json_invalid");
      }
      throw new Error("parity_corpus_json_invalid");
    }
    if (raw[index] === "[") {
      index++;
      whitespace();
      const array: unknown[] = [];
      if (raw[index] === "]") { index++; return array; }
      while (index < raw.length) {
        array.push(value());
        whitespace();
        const separator = raw[index++];
        if (separator === "]") return array;
        if (separator !== ",") throw new Error("parity_corpus_json_invalid");
      }
      throw new Error("parity_corpus_json_invalid");
    }
    if (raw[index] === '"') return stringValue();
    for (const [literal, literalValue] of [["true", true], ["false", false], ["null", null]] as const) {
      if (raw.startsWith(literal, index)) { index += literal.length; return literalValue; }
    }
    const number = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u.exec(raw.slice(index))?.[0];
    if (!number) throw new Error("parity_corpus_json_invalid");
    index += number.length;
    const parsed = Number(number);
    if (!Number.isFinite(parsed)) throw new Error("parity_corpus_json_invalid");
    return parsed;
  };
  const parsed = value();
  whitespace();
  if (index !== raw.length) throw new Error("parity_corpus_json_invalid");
  return parsed;
}

function parseConfig(value: unknown, ttlMs: number): ParityConfig {
  const record = objectValue(value, "config");
  exactKeys(record, CONFIG_KEYS, "config");
  const config: ParityConfig = {
    max_window: integer(record.max_window, "max_window"),
    max_candidates_per_observation: integer(record.max_candidates_per_observation, "max_candidates_per_observation"),
    hamming_threshold: integer(record.hamming_threshold, "hamming_threshold"),
    min_grid_size: integer(record.min_grid_size, "min_grid_size"),
    min_region_count: integer(record.min_region_count, "min_region_count"),
    max_partitions: integer(record.max_partitions, "max_partitions"),
  };
  const observer = new ShadowExtractionObserver(toShadowConfig(config, ttlMs), () => 0, INERT_SCHEDULER);
  observer.close();
  return config;
}

function parseObservation(value: unknown): InferenceObservation {
  const record = objectValue(value, "observation");
  exactKeys(record, OBSERVATION_KEYS, "observation");
  for (const field of OBSERVATION_KEYS) {
    if (typeof record[field] !== "string" || !HEX64.test(record[field] as string)) {
      throw new Error(`observation_${field}_uint64_hex_required`);
    }
  }
  return {
    tenantToken: record.tenantToken as string,
    sessionToken: record.sessionToken as string,
    sequence: record.sequence as string,
    querySimhash: record.querySimhash as string,
    regionToken: record.regionToken as string,
  };
}

function parseExpected(value: unknown): NormalizedParityTurn {
  const record = objectValue(value, "expected");
  exactKeys(record, EXPECTED_KEYS, "expected");
  if (typeof record.ok !== "boolean") throw new Error("expected_ok_boolean_required");
  if (!Array.isArray(record.errors) || record.errors.some((item) => typeof item !== "string" || !item)) {
    throw new Error("expected_errors_invalid");
  }
  if (record.status !== "CANDIDATE_EVIDENCE" && record.status !== "INSUFFICIENT_EVIDENCE") {
    throw new Error("expected_status_invalid");
  }
  if (typeof record.reason !== "string" || !record.reason) throw new Error("expected_reason_invalid");
  for (const field of ["grid_size", "region_count"] as const) {
    if (record[field] !== null && (typeof record[field] !== "number" || !Number.isInteger(record[field]) || record[field] < 1)) {
      throw new Error(`expected_${field}_invalid`);
    }
  }
  return {
    ok: record.ok,
    errors: [...record.errors] as string[],
    status: record.status,
    reason: record.reason,
    grid_size: record.grid_size as number | null,
    region_count: record.region_count as number | null,
  };
}

export function parseParityCorpus(raw: string | Buffer): ParityCorpus {
  let parsed: unknown;
  try {
    parsed = parseJsonWithoutDuplicateKeys(Buffer.isBuffer(raw) ? raw.toString("utf8") : raw);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("duplicate_json_key:")) throw error;
    throw new Error("parity_corpus_json_invalid");
  }
  const root = objectValue(parsed, "corpus");
  exactKeys(root, ROOT_KEYS, "root");
  if (root.schema !== CORPUS_SCHEMA) throw new Error("parity_corpus_schema_invalid");
  if (root.status !== "FROZEN_FOR_REVIEW") throw new Error("parity_corpus_status_invalid");
  if (root.semantic_authority !== SEMANTIC_AUTHORITY) throw new Error("parity_semantic_authority_invalid");
  if (root.reference_implementation !== REFERENCE_IMPLEMENTATION) throw new Error("parity_reference_implementation_invalid");

  const time = objectValue(root.time_semantics, "time_semantics");
  exactKeys(time, ["mode", "now_ms", "typescript_ttl_ms"], "time_semantics");
  if (time.mode !== "fixed") throw new Error("parity_time_mode_invalid");
  const nowMs = integer(time.now_ms, "now_ms");
  const ttlMs = integer(time.typescript_ttl_ms, "typescript_ttl_ms");
  if (nowMs < 0) throw new Error("now_ms_out_of_range");
  if (ttlMs < 1 || ttlMs > 3_600_000) throw new Error("typescript_ttl_ms_out_of_range");

  const authority = objectValue(root.authority, "authority");
  exactKeys(authority, ["action_ceiling", "integration_authorized", "activation_authorized", "production_claim_authorized"], "authority");
  if (authority.action_ceiling !== "OBSERVE_ONLY"
    || authority.integration_authorized !== false
    || authority.activation_authorized !== false
    || authority.production_claim_authorized !== false) {
    throw new Error("parity_authority_boundary_invalid");
  }

  if (!Array.isArray(root.cases) || root.cases.length !== FROZEN_CASE_IDS.length) {
    throw new Error("parity_frozen_case_count_invalid");
  }
  const seenCaseIds = new Set<string>();
  const observedCoverage = new Set<string>();
  let turnCount = 0;
  const cases = root.cases.map((value, caseIndex): ParityCase => {
    const record = objectValue(value, "case");
    exactKeys(record, CASE_KEYS, "case");
    if (typeof record.case_id !== "string" || !/^[a-z0-9_]+$/.test(record.case_id)) throw new Error("parity_case_id_invalid");
    if (seenCaseIds.has(record.case_id)) throw new Error("parity_case_id_duplicate");
    seenCaseIds.add(record.case_id);
    if (record.case_id !== FROZEN_CASE_IDS[caseIndex]) throw new Error("parity_frozen_case_ids_invalid");
    const coverage = stringArray(record.coverage, "parity_case_coverage");
    for (const item of coverage) observedCoverage.add(item);
    const config = parseConfig(record.config, ttlMs);
    if (!Array.isArray(record.observations) || record.observations.length === 0) throw new Error("parity_case_observations_required");
    if (!Array.isArray(record.expected) || record.expected.length !== record.observations.length) {
      throw new Error("parity_case_expected_length_mismatch");
    }
    turnCount += record.observations.length;
    return {
      case_id: record.case_id,
      coverage,
      config,
      observations: record.observations.map(parseObservation),
      expected: record.expected.map(parseExpected),
    };
  });
  if (observedCoverage.size !== FROZEN_COVERAGE.size
    || [...FROZEN_COVERAGE].some((item) => !observedCoverage.has(item))) {
    throw new Error("parity_frozen_coverage_invalid");
  }
  if (turnCount !== FROZEN_TURN_COUNT) throw new Error("parity_frozen_turn_count_invalid");

  return {
    schema: CORPUS_SCHEMA,
    status: "FROZEN_FOR_REVIEW",
    semantic_authority: SEMANTIC_AUTHORITY,
    reference_implementation: REFERENCE_IMPLEMENTATION,
    time_semantics: { mode: "fixed", now_ms: nowMs, typescript_ttl_ms: ttlMs },
    authority: {
      action_ceiling: "OBSERVE_ONLY",
      integration_authorized: false,
      activation_authorized: false,
      production_claim_authorized: false,
    },
    cases,
  };
}

const INERT_SCHEDULER: ExpiryScheduler = {
  schedule() {
    return Symbol("parity-fixed-time-expiry");
  },
  cancel() {},
};

function toShadowConfig(config: ParityConfig, ttlMs: number): ShadowExtractionConfig {
  return {
    maxWindow: config.max_window,
    maxCandidatesPerObservation: config.max_candidates_per_observation,
    hammingThreshold: config.hamming_threshold,
    minGridSize: config.min_grid_size,
    minRegionCount: config.min_region_count,
    maxPartitions: config.max_partitions,
    ttlMs,
  };
}

function normalizeResult(result: DrawbridgeResult): NormalizedParityTurn {
  if (!result.assessment) throw new Error("typescript_assessment_missing");
  return {
    ok: result.ok,
    errors: [...result.errors],
    status: result.assessment.status,
    reason: result.assessment.reason,
    grid_size: result.assessment.gridSize ?? null,
    region_count: result.assessment.regionCount ?? null,
  };
}

function executeParsedParityCorpus(corpus: ParityCorpus): TypeScriptParityReport {
  const errors: string[] = [];
  const cases = corpus.cases.map((entry) => {
    const observer = new ShadowExtractionObserver(
      toShadowConfig(entry.config, corpus.time_semantics.typescript_ttl_ms),
      () => corpus.time_semantics.now_ms,
      INERT_SCHEDULER,
    );
    let turns: NormalizedParityTurn[];
    try {
      turns = entry.observations.map((observation) => normalizeResult(observer.observe(observation)));
    } finally {
      observer.close();
    }
    for (let index = 0; index < turns.length; index++) {
      if (JSON.stringify(turns[index]) !== JSON.stringify(entry.expected[index])) {
        errors.push(`typescript_authority_drift:${entry.case_id}:turn_${index + 1}`);
      }
    }
    return { case_id: entry.case_id, turns };
  });
  return {
    schema: REPORT_SCHEMA,
    ok: errors.length === 0,
    corpus_sha256: FROZEN_CORPUS_SHA256,
    authority: {
      semantic_authority: SEMANTIC_AUTHORITY,
      reference_implementation: REFERENCE_IMPLEMENTATION,
      action_ceiling: "OBSERVE_ONLY",
    },
    cases,
    errors,
  };
}

export function executeParityBytes(raw: string | Buffer): TypeScriptParityReport {
  const bytes = Buffer.isBuffer(raw) ? Buffer.from(raw) : Buffer.from(raw, "utf8");
  if (bytes.length < 1 || bytes.length > MAX_CORPUS_BYTES) throw new Error("parity_corpus_size_out_of_range");
  const digest = createHash("sha256").update(bytes).digest("hex");
  if (!SHA256.test(digest) || digest !== FROZEN_CORPUS_SHA256) {
    throw new Error("frozen_corpus_sha256_mismatch");
  }
  return executeParsedParityCorpus(parseParityCorpus(bytes));
}

interface CustodiedPathEntry {
  path: string;
  dev: number;
  ino: number;
  size: number;
  mtimeMs: number;
  directory: boolean;
  descriptor: number | null;
}

function closeCustodiedPath(chain: CustodiedPathEntry[]): void {
  for (const entry of [...chain].reverse()) {
    if (entry.descriptor !== null) closeSync(entry.descriptor);
  }
}

function custodiedPath(path: string): CustodiedPathEntry[] {
  const resolved = resolve(path);
  if (!isAbsolute(resolved)) throw new Error("parity_corpus_absolute_path_required");
  if (typeof constants.O_NOFOLLOW !== "number" || typeof constants.O_DIRECTORY !== "number") {
    throw new Error("parity_corpus_safe_open_unavailable");
  }
  const root = parse(resolved).root;
  let current = root;
  const chain: CustodiedPathEntry[] = [];
  const parts = resolved.slice(root.length).split("/").filter(Boolean);
  try {
    for (let index = 0; index < parts.length; index++) {
      current = join(current, parts[index]);
      const status = lstatSync(current);
      if (status.isSymbolicLink()) {
        throw new Error(index === parts.length - 1 ? "parity_corpus_symlink_forbidden" : "parity_corpus_ancestor_symlink_forbidden");
      }
      const directory = index < parts.length - 1;
      if (directory ? !status.isDirectory() : !status.isFile()) {
        throw new Error(directory ? "parity_corpus_ancestor_directory_required" : "parity_corpus_regular_file_required");
      }
      let descriptor: number | null = null;
      if (directory) {
        const openedDescriptor = openSync(current, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
        try {
          const opened = fstatSync(openedDescriptor);
          if (!opened.isDirectory() || opened.dev !== status.dev || opened.ino !== status.ino) {
            throw new Error("parity_corpus_ancestor_identity_changed");
          }
          descriptor = openedDescriptor;
        } catch (error) {
          closeSync(openedDescriptor);
          throw error;
        }
      }
      chain.push({
        path: current,
        dev: status.dev,
        ino: status.ino,
        size: status.size,
        mtimeMs: status.mtimeMs,
        directory,
        descriptor,
      });
    }
    return chain;
  } catch (error) {
    closeCustodiedPath(chain);
    throw error;
  }
}

function recheckCustodiedPath(chain: CustodiedPathEntry[]): void {
  for (const expected of chain) {
    const current = lstatSync(expected.path);
    if (current.isSymbolicLink() || current.dev !== expected.dev || current.ino !== expected.ino
      || (expected.directory ? !current.isDirectory() : !current.isFile())) {
      throw new Error("parity_corpus_path_identity_changed");
    }
    if (expected.descriptor !== null) {
      const opened = fstatSync(expected.descriptor);
      if (!opened.isDirectory() || opened.dev !== expected.dev || opened.ino !== expected.ino) {
        throw new Error("parity_corpus_ancestor_identity_changed");
      }
    }
  }
}

function readBoundedCorpus(path: string): Buffer {
  const resolved = resolve(path);
  const chain = custodiedPath(resolved);
  let descriptor: number | null = null;
  try {
    const custodiedFinal = chain.at(-1);
    if (!custodiedFinal || custodiedFinal.directory) throw new Error("parity_corpus_final_custody_missing");
    const before = lstatSync(resolved);
    if (
      !before.isFile()
      || before.isSymbolicLink()
      || before.dev !== custodiedFinal.dev
      || before.ino !== custodiedFinal.ino
      || before.size !== custodiedFinal.size
      || before.mtimeMs !== custodiedFinal.mtimeMs
    ) {
      throw new Error("parity_corpus_path_identity_changed");
    }
    if (before.size < 1 || before.size > MAX_CORPUS_BYTES) throw new Error("parity_corpus_size_out_of_range");
    descriptor = openSync(resolved, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = fstatSync(descriptor);
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) {
      throw new Error("parity_corpus_identity_changed");
    }
    const bytes = readFileSync(descriptor);
    if (bytes.length !== opened.size || bytes.length > MAX_CORPUS_BYTES) throw new Error("parity_corpus_read_size_invalid");
    const after = fstatSync(descriptor);
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs) {
      throw new Error("parity_corpus_identity_changed");
    }
    recheckCustodiedPath(chain);
    return bytes;
  } finally {
    if (descriptor !== null) closeSync(descriptor);
    closeCustodiedPath(chain);
  }
}

export function runParityFile(path: string): TypeScriptParityReport {
  const bytes = readBoundedCorpus(path);
  return executeParityBytes(bytes);
}

export function parseParityArgs(argv: string[]): { corpusPath: string } {
  if (argv.length !== 2 || argv[0] !== "--corpus" || !argv[1]) throw new Error("parity_cli_argv_invalid");
  return { corpusPath: resolve(argv[1]) };
}

export function main(argv: string[] = process.argv.slice(2)): number {
  try {
    const { corpusPath } = parseParityArgs(argv);
    const report = runParityFile(corpusPath);
    process.stdout.write(`${JSON.stringify(report)}\n`);
    return report.ok ? 0 : 1;
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "parity_cli_failed"}\n`);
    return 2;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  process.exitCode = main();
}
