import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  executeParityBytes,
  parseParityArgs,
  parseParityCorpus,
  runParityFile,
} from "../src/drawbridge-runtime/parity-cli";

type TestCase = { name: string; run: () => void };
const tests: TestCase[] = [];
const test = (name: string, run: TestCase["run"]) => tests.push({ name, run });
const assert: (value: unknown, message: string) => asserts value = (value, message) => {
  if (!value) throw new Error(message);
};
const equal = (actual: unknown, expected: unknown, message: string) => {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${message}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
};
const throws = (run: () => unknown, expected: string, message: string) => {
  try {
    run();
  } catch (error) {
    assert(error instanceof Error && error.message.includes(expected), `${message}: ${String(error)}`);
    return;
  }
  throw new Error(`${message}: did not throw`);
};

const corpusPath = fileURLToPath(new URL("./fixtures/drawbridge_parity_corpus_v1.json", import.meta.url));
const corpusText = readFileSync(corpusPath, "utf8");

test("frozen corpus covers every required semantic boundary", () => {
  const corpus = parseParityCorpus(corpusText);
  const coverage = new Set(corpus.cases.flatMap((entry) => entry.coverage));
  for (const required of [
    "same_regions",
    "different_regions",
    "exact_repeats",
    "boundary_hamming",
    "partitions",
    "window_eviction",
    "candidate_eviction",
    "partition_eviction",
    "uint64_extremes",
    "monotonic_rejection",
    "failure_state",
  ]) {
    assert(coverage.has(required), `missing coverage: ${required}`);
  }
  equal(corpus.time_semantics, { mode: "fixed", now_ms: 0, typescript_ttl_ms: 3_600_000 }, "fixed time contract");
});

test("TypeScript authority exactly matches every frozen normalized turn", () => {
  const corpus = parseParityCorpus(corpusText);
  const first = executeParityBytes(corpusText);
  const second = executeParityBytes(corpusText);

  assert(first.ok, `authority drift: ${first.errors.join(",")}`);
  equal(first, second, "deterministic report");
  equal(first.cases.length, corpus.cases.length, "case count");
  for (const [index, resultCase] of first.cases.entries()) {
    equal(resultCase.case_id, corpus.cases[index].case_id, "case identity");
    equal(resultCase.turns, corpus.cases[index].expected, `frozen turns for ${resultCase.case_id}`);
  }
  const digestMutation = corpusText.replace('"now_ms": 0', '"now_ms": 1');
  throws(() => executeParityBytes(digestMutation), "frozen_corpus_sha256_mismatch", "exact frozen corpus digest");
});

test("corpus validation is closed at every object boundary", () => {
  const base = JSON.parse(corpusText) as Record<string, unknown>;
  throws(() => parseParityCorpus(JSON.stringify({ ...base, surprise: true })), "corpus_keys_invalid:root", "root key closure");

  const caseMutation = structuredClone(base) as { cases: Array<Record<string, unknown>> };
  caseMutation.cases[0].surprise = true;
  throws(() => parseParityCorpus(JSON.stringify(caseMutation)), "corpus_keys_invalid:case", "case key closure");

  const observationMutation = structuredClone(base) as { cases: Array<{ observations: Array<Record<string, unknown>> }> };
  observationMutation.cases[0].observations[0].rawQuery = "must not be admitted";
  throws(() => parseParityCorpus(JSON.stringify(observationMutation)), "corpus_keys_invalid:observation", "observation key closure");

  const expectedMutation = structuredClone(base) as { cases: Array<{ expected: Array<Record<string, unknown>> }> };
  expectedMutation.cases[0].expected[0].authority = "none";
  throws(() => parseParityCorpus(JSON.stringify(expectedMutation)), "corpus_keys_invalid:expected", "expected key closure");

  const oneCase = structuredClone(base) as { cases: unknown[] };
  oneCase.cases = oneCase.cases.slice(0, 1);
  throws(() => parseParityCorpus(JSON.stringify(oneCase)), "parity_frozen_case_count_invalid", "frozen case count");

  const duplicate = corpusText.replace(
    '"status": "FROZEN_FOR_REVIEW",',
    '"status": "NOT_FROZEN",\n  "status": "FROZEN_FOR_REVIEW",',
  );
  throws(() => parseParityCorpus(duplicate), "duplicate_json_key:status", "duplicate key rejection");
  const nestedDuplicate = corpusText.replace(
    '"max_window": 8,',
    '"max_window": 999,\n        "max_window": 8,',
  );
  throws(() => parseParityCorpus(nestedDuplicate), "duplicate_json_key:max_window", "nested duplicate key rejection");
});

test("CLI accepts one exact corpus flag and report output is closed", () => {
  equal(parseParityArgs(["--corpus", corpusPath]), { corpusPath }, "exact argv");
  for (const argv of [[], [corpusPath], ["--corpus", corpusPath, "extra"], ["--corpus"], ["--unknown", corpusPath]]) {
    throws(() => parseParityArgs(argv), "parity_cli_argv_invalid", `invalid argv ${JSON.stringify(argv)}`);
  }
  const report = runParityFile(corpusPath);
  equal(Object.keys(report).sort(), ["authority", "cases", "corpus_sha256", "errors", "ok", "schema"], "report key closure");
  equal(Object.keys(report.authority).sort(), ["action_ceiling", "reference_implementation", "semantic_authority"], "authority key closure");
  for (const entry of report.cases) {
    equal(Object.keys(entry).sort(), ["case_id", "turns"], "case report key closure");
    for (const turn of entry.turns) {
      equal(Object.keys(turn).sort(), ["errors", "grid_size", "ok", "reason", "region_count", "status"], "turn key closure");
    }
  }
});

test("vendored frozen corpus is independent of the caller working directory", () => {
  const neutral = mkdtempSync(join(tmpdir(), "drawbridge-parity-neutral-"));
  const previous = process.cwd();
  try {
    process.chdir(neutral);
    const report = runParityFile(corpusPath);
    assert(report.ok, `module-relative corpus failed from neutral cwd: ${report.errors.join(",")}`);
  } finally {
    process.chdir(previous);
    rmSync(neutral, { recursive: true, force: true });
  }
});

test("frozen corpus custody rejects final and ancestor symlinks", () => {
  const root = mkdtempSync(join(fileURLToPath(new URL(".", import.meta.url)), ".drawbridge-parity-custody-"));
  try {
    const actual = join(root, "actual");
    mkdirSync(actual);
    const copied = join(actual, "corpus.json");
    copyFileSync(corpusPath, copied);
    const finalAlias = join(root, "final.json");
    symlinkSync(copied, finalAlias);
    throws(() => runParityFile(finalAlias), "parity_corpus_symlink_forbidden", "final symlink");
    const ancestorAlias = join(root, "ancestor");
    symlinkSync(actual, ancestorAlias, "dir");
    throws(() => runParityFile(join(ancestorAlias, "corpus.json")), "parity_corpus_ancestor_symlink_forbidden", "ancestor symlink");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

let passed = 0;
for (const entry of tests) {
  try {
    entry.run();
    passed++;
    process.stdout.write(`ok   ${entry.name}\n`);
  } catch (error) {
    process.stdout.write(`FAIL ${entry.name}: ${error instanceof Error ? error.message : String(error)}\n`);
  }
}
process.stdout.write(`${passed}/${tests.length} parity tests passed\n`);
if (passed !== tests.length) process.exitCode = 1;
