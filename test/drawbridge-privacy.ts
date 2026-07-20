import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { produceInferenceObservation } from "../src/behavior/extraction/producer";

const producerPath = fileURLToPath(new URL("../src/behavior/extraction/producer.ts", import.meta.url));
const sourceText = readFileSync(producerPath, "utf8");
const source = ts.createSourceFile(producerPath, sourceText, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TS);
const errors: string[] = [];
const bannedImports = new Set(["node:fs", "node:http", "node:https", "node:net", "node:dgram"]);
let catchClauses = 0;
let throwStatements = 0;
let loggingCalls = 0;
let dynamicErrorPayloads = 0;

function inspect(node: ts.Node): void {
  if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)
    && bannedImports.has(node.moduleSpecifier.text)) {
    errors.push(`producer_banned_import:${node.moduleSpecifier.text}`);
  }
  if (ts.isCatchClause(node)) catchClauses++;
  if (ts.isThrowStatement(node)) throwStatements++;
  if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
    const owner = node.expression.expression.getText(source);
    const method = node.expression.name.text;
    if (["console", "logger", "log"].includes(owner) && ["log", "warn", "error", "info", "debug"].includes(method)) {
      loggingCalls++;
    }
    if (owner === "errors" && method === "push"
      && node.arguments.some((argument) => !ts.isStringLiteral(argument))) {
      dynamicErrorPayloads++;
    }
  }
  ts.forEachChild(node, inspect);
}
inspect(source);
if (catchClauses) errors.push("producer_catch_path_requires_manual_leak_review");
if (throwStatements) errors.push("producer_throw_path_requires_manual_leak_review");
if (loggingCalls) errors.push("producer_logging_call_detected");
if (dynamicErrorPayloads) errors.push("producer_dynamic_error_payload_detected");

const canaries = [
  "privacy-tenant-canary",
  "privacy-session-canary",
  "privacy-query-canary",
  "privacy-region-canary",
];
const base = {
  tenantId: canaries[0],
  sessionId: canaries[1],
  sequence: 1n,
  rawQuery: canaries[2],
  regionLabel: canaries[3],
};
const secret = Buffer.alloc(32, 19);
const runtimeResults = [
  produceInferenceObservation(base, secret),
  produceInferenceObservation(base, Buffer.alloc(8)),
  produceInferenceObservation({ ...base, tenantId: "" }, secret),
  produceInferenceObservation({ ...base, sessionId: "" }, secret),
  produceInferenceObservation({ ...base, sequence: -1n }, secret),
  produceInferenceObservation({ ...base, rawQuery: "" }, secret),
  produceInferenceObservation({ ...base, regionLabel: "" }, secret),
];
let runtimeCanaryLeaks = 0;
for (const runtimeResult of runtimeResults) {
  const serialized = JSON.stringify(runtimeResult);
  runtimeCanaryLeaks += canaries.filter((canary) => serialized.includes(canary)).length;
}
if (runtimeCanaryLeaks) errors.push("producer_runtime_result_canary_leak_detected");

const result = {
  op: "drawbridge.extraction.producer_privacy_audit",
  ok: errors.length === 0,
  actions: ["parsed_producer_ast", "inspected_error_construction", "scanned_runtime_result_canaries"],
  skips: [
    "caller_logging_outside_producer_scope",
    "memory_forensics_not_performed",
    "privacy_safety_not_claimed",
    "reconstruction_resistance_not_measured",
  ],
  errors,
  metrics: {
    producer_sha256: createHash("sha256").update(sourceText).digest("hex"),
    catch_clauses: catchClauses,
    throw_statements: throwStatements,
    logging_calls: loggingCalls,
    dynamic_error_payloads: dynamicErrorPayloads,
    runtime_paths_scanned: runtimeResults.length,
    runtime_canary_leaks: runtimeCanaryLeaks,
    raw_payload_retained_claim_scope: "producer_return_values_only",
    authority_granted: false,
  },
  next: "Keep caller logs, crash reporters, heap memory, key custody, and reconstruction resistance outside this scoped return-value audit until separately measured.",
};

process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
if (!result.ok) process.exit(1);
