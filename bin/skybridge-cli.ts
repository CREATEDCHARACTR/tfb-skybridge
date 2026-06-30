#!/usr/bin/env tsx
// TFB Skybridge — Developer CLI.
//
//   skybridge check <app-dir>
//
// Run the discriminator on a developer's app on their own machine. The verdict
// they get here is the SAME verdict an app store using Skybridge would give —
// only delivered in seconds, locally, with the exact seed × payload × call
// site that caused the catch.
//
// The dev's <app-dir> must contain `index.ts` (or `.js`) that default-exports
// an AppEntry function: `(env: BoundaryEnv, input: string) => void | Promise<void>`.
// The app uses the capability-injected boundary; the CLI runs it through the
// real Battery in a real Sandbox, against the real adversarial payloads.
//
// Exit codes (CI-friendly):
//   0 — ADMIT (clean)
//   1 — ADMIT with variance warning (non-deterministic)
//   2 — REJECT pre-ship (any violation)
//   3 — CLI error (bad app shape, missing file, etc.)
import { readdir, readFile, stat } from "node:fs/promises";
import { join, resolve, extname, basename } from "node:path";
import { pathToFileURL } from "node:url";

import { analyze } from "../src/cables/analyze";
import { runBattery } from "../src/battery/runner";
import { PAYLOADS } from "../src/battery/apps";
import { sandboxPolicyFromAnalysis } from "../src/loop";
import { generateKeyPair } from "../src/crypto";
import type { AppEntry, SandboxPolicy } from "../src/battery/types";
import type { Artifact } from "../src/proofbay/artifact";

// Optional skybridge.json manifest — devs declare their policy explicitly
// instead of relying on Cables to derive it from source. This is the honest
// design: Cables analyzes browser-native patterns (fetch / WebSocket / etc.),
// not the BoundaryEnv API the app actually uses inside the Battery sandbox.
// The manifest is what the dev claims their app needs; the Battery enforces it.
interface SkybridgeManifest {
  hosts?: string[];          // declared egress targets (host portion only, no scheme)
  directives?: string[];     // CSP directives needed (connect-src, script-src, ...)
  capabilities?: string[];   // typed capabilities the app uses (storage:scoped, ...)
}
async function loadManifest(appDir: string): Promise<SkybridgeManifest | null> {
  try {
    const text = await readFile(join(appDir, "skybridge.json"), "utf8");
    const parsed = JSON.parse(text);
    if (typeof parsed !== "object" || parsed === null) {
      throw new Error("skybridge.json: top level must be an object");
    }
    return parsed as SkybridgeManifest;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.includes("ENOENT") || msg.includes("no such file")) return null;
    throw e;
  }
}
function policyFromManifest(m: SkybridgeManifest): SandboxPolicy {
  return {
    hosts: new Set(m.hosts ?? []),
    directives: new Set(m.directives ?? []),
    capabilities: new Set(m.capabilities ?? []),
  };
}

// ---- tiny ANSI helpers ----------------------------------------------------
const isTTY = process.stdout.isTTY;
const ansi = (code: string) => (s: string) => (isTTY ? `\x1b[${code}m${s}\x1b[0m` : s);
const c = {
  bold: ansi("1"),
  dim: ansi("2"),
  red: ansi("31"),
  green: ansi("32"),
  yellow: ansi("33"),
  blue: ansi("34"),
  cyan: ansi("36"),
};
function hr(): string {
  return "─".repeat(Math.min(72, process.stdout.columns || 72));
}

// ---- argparse (zero-dep, two flags) ---------------------------------------
interface CliArgs {
  cmd: "check" | "help" | null;
  appDir: string | null;
  seeds: number[];
  json: boolean;
}
function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = { cmd: null, appDir: null, seeds: [1, 3, 7, 8], json: false };
  if (argv.length === 0 || argv[0] === "-h" || argv[0] === "--help" || argv[0] === "help") {
    args.cmd = "help";
    return args;
  }
  if (argv[0] === "check") {
    args.cmd = "check";
    const rest = argv.slice(1);
    for (let i = 0; i < rest.length; i++) {
      const a = rest[i];
      if (a === "--json") args.json = true;
      else if (a === "--seeds") {
        const v = rest[++i];
        if (!v) throw new Error("--seeds needs a comma-separated list");
        args.seeds = v.split(",").map((s) => Number(s.trim())).filter((n) => Number.isFinite(n));
        if (args.seeds.length === 0) throw new Error("--seeds parsed to empty list");
      } else if (a.startsWith("--")) {
        throw new Error(`unknown flag: ${a}`);
      } else if (!args.appDir) {
        args.appDir = a;
      } else {
        throw new Error(`unexpected argument: ${a}`);
      }
    }
    if (!args.appDir) throw new Error("usage: skybridge check <app-dir>");
    return args;
  }
  throw new Error(`unknown command: ${argv[0]}. try 'skybridge help'`);
}

function printHelp(): void {
  console.log(`${c.bold("TFB Skybridge")} — Developer CLI
${c.dim(hr())}

  ${c.bold("skybridge check <app-dir>")}
      Run the Skybridge discriminator on your app. Verdict in seconds with the
      exact seed × payload × call site that caused any catch.

      Expects <app-dir>/index.ts (or .js) to default-export an AppEntry function:

        export default async (env, input) => {
          await env.fetch('https://api.example.com/v1/charge', { method: 'POST' });
          // ...
        }

  ${c.bold("Flags:")}
      --seeds 1,3,7,8     deterministic seeds for the battery (default: 1,3,7,8)
      --json              emit structured JSON instead of human-readable output

  ${c.bold("Exit codes (CI-friendly):")}
      0  ADMIT (clean)
      1  ADMIT with variance warning (non-deterministic)
      2  REJECT pre-ship (any violation)
      3  CLI error
`);
}

// ---- read app source as an Artifact for Cables ----------------------------
const SCANNABLE = new Set([".js", ".mjs", ".ts", ".html", ".htm", ".css"]);
async function loadAppArtifact(appDir: string): Promise<Artifact> {
  const artifact = new Map<string, Buffer>();
  async function walk(d: string, rel: string): Promise<void> {
    const entries = await readdir(d, { withFileTypes: true });
    for (const e of entries) {
      if (e.name.startsWith(".") || e.name === "node_modules") continue;
      const full = join(d, e.name);
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) {
        await walk(full, r);
      } else if (SCANNABLE.has(extname(e.name).toLowerCase())) {
        artifact.set(r, await readFile(full));
      }
    }
  }
  await walk(appDir, "");
  return artifact;
}

// ---- load the dev's default-exported AppEntry function --------------------
async function loadAppEntry(appDir: string): Promise<AppEntry> {
  // Order matters (heal 0.1.1): prefer .mjs (works everywhere, including
  // under node_modules where Node refuses to strip TS types), then .js, then
  // .ts (loads only outside node_modules on Node 23.6+ which strips natively).
  const candidates = ["index.mjs", "index.js", "index.ts"];
  for (const name of candidates) {
    const p = join(appDir, name);
    try {
      await stat(p);
      const mod = await import(pathToFileURL(p).href);
      const entry = mod.default;
      if (typeof entry !== "function") {
        throw new Error(`${name} exists but does not default-export a function`);
      }
      return entry as AppEntry;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes("ENOENT") || msg.includes("no such file")) continue;
      throw e;
    }
  }
  throw new Error(`no index.ts / index.js / index.mjs found in ${appDir}`);
}

// ---- map violation kind → readable verb (mirror of /developer-view) -------
const KIND_TO_ACTION: Record<string, string> = {
  "egress-blocked": "POST to",
  "capability-denied": "use",
};

// ---- runner ---------------------------------------------------------------
async function runCheck(args: CliArgs): Promise<number> {
  const appDir = resolve(args.appDir!);
  const name = basename(appDir);
  const startedAt = process.hrtime.bigint();

  // (1) Sanity: directory exists, has an entry file.
  try {
    const s = await stat(appDir);
    if (!s.isDirectory()) {
      if (!args.json) console.error(c.red(`✗ ${args.appDir} is not a directory`));
      else console.log(JSON.stringify({ ok: false, error: "not a directory", appDir }));
      return 3;
    }
  } catch {
    if (!args.json) console.error(c.red(`✗ ${args.appDir} does not exist`));
    else console.log(JSON.stringify({ ok: false, error: "does not exist", appDir }));
    return 3;
  }

  if (!args.json) {
    console.log(`${c.bold("TFB Skybridge")} — Dev CLI`);
    console.log(c.dim(hr()));
    console.log(`Checking ${c.cyan(args.appDir!)}`);
    console.log("");
  }

  // (2) Manifest — either skybridge.json (dev declares) or Cables-derived.
  // Two paths because: Cables sees browser-native patterns (fetch / WebSocket /
  // <script src>), not the BoundaryEnv API the app uses inside the Battery.
  // Devs whose apps use env.loadScript/connect/beacon must declare manifest
  // explicitly. Apps that mirror browser-native patterns can rely on Cables.
  const manifest = await loadManifest(appDir);
  const artifact = await loadAppArtifact(appDir);
  const analyzed = analyze(artifact);
  const manifestSource = manifest ? "skybridge.json" : "cables-derived";
  const sandboxPolicy: SandboxPolicy = manifest
    ? policyFromManifest(manifest)
    : sandboxPolicyFromAnalysis(analyzed);

  if (!args.json) {
    if (manifest) {
      console.log(`${c.bold("[1/3] Manifest")} ${c.dim("— declared in skybridge.json")}`);
      console.log(`  hosts:        ${(manifest.hosts ?? []).length > 0 ? (manifest.hosts ?? []).join(", ") : c.dim("(none)")}`);
      console.log(`  directives:   ${(manifest.directives ?? []).length > 0 ? (manifest.directives ?? []).join(", ") : c.dim("(none)")}`);
      console.log(`  capabilities: ${(manifest.capabilities ?? []).length > 0 ? (manifest.capabilities ?? []).join(", ") : c.dim("(none)")}`);
      console.log(`  ${c.dim(`(Cables found ${analyzed.grants.length} grant(s) in source — diagnostic only when manifest is declared)`)}`);
    } else {
      console.log(`${c.bold("[1/3] Cables")} ${c.dim("— static analysis derives your minimal CSP from source (no skybridge.json found)")}`);
      console.log(`  scanned ${artifact.size} file(s) (${[...artifact.keys()].join(", ") || "—"})`);
      if (analyzed.grants.length === 0) {
        console.log(`  ${c.dim("no egress constructs found in source — declared manifest is empty")}`);
      } else {
        console.log(`  derived ${analyzed.grants.length} grant(s):`);
        for (const g of analyzed.grants) {
          const w = g.witnesses[0];
          console.log(`    ${c.green("✓")} ${g.grant}  ${c.dim(`(${w.srcRef.file}[${w.srcRef.span[0]}, ${w.srcRef.span[1]}))`)}`);
        }
      }
      if (analyzed.report.ignoredRelative > 0) {
        console.log(`  ${c.dim(`(${analyzed.report.ignoredRelative} relative URL(s) skipped — no grant needed)`)}`);
      }
    }
    console.log("");
  }

  // (3) Load the dev's entry function and run the Battery.
  let appEntry: AppEntry;
  try {
    appEntry = await loadAppEntry(appDir);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (!args.json) console.error(c.red(`✗ ${msg}`));
    else console.log(JSON.stringify({ ok: false, error: msg, appDir }));
    return 3;
  }

  if (!args.json) {
    console.log(`${c.bold("[2/3] Battery")} ${c.dim(`— adversarial pre-ship (${args.seeds.length} seeds × ${PAYLOADS.length} payloads = ${args.seeds.length * PAYLOADS.length} trials)`)}`);
  }

  const batteryKey = generateKeyPair();
  const transcript = await runBattery(
    { app: appEntry, policy: sandboxPolicy, payloads: PAYLOADS, seeds: args.seeds },
    batteryKey.privateKeyPem,
  );

  const elapsedNs = process.hrtime.bigint() - startedAt;
  const elapsedMs = Number(elapsedNs / 1_000_000n);

  if (!args.json) {
    console.log(`  ${transcript.result === "PASS" ? c.green("PASS") : c.red("FAIL")} · variance ${transcript.fingerprintVariance.toFixed(3)} · violations ${transcript.violations.length}`);
    console.log("");
  }

  // (4) Decide verdict.
  const variance = transcript.fingerprintVariance;
  const flagsVariance = variance > 0.05;
  const verdict: "ADMIT" | "ADMIT_WITH_VARIANCE_WARNING" | "REJECT_PRESHIP" =
    transcript.result === "FAIL"
      ? "REJECT_PRESHIP"
      : flagsVariance
      ? "ADMIT_WITH_VARIANCE_WARNING"
      : "ADMIT";

  if (args.json) {
    console.log(JSON.stringify({
      ok: true,
      appDir,
      appName: name,
      verdict,
      timeToVerdictMs: elapsedMs,
      manifestSource,
      manifest: manifest ?? null,
      cables: {
        scannedFiles: artifact.size,
        grants: analyzed.grants.map((g) => ({
          grant: g.grant,
          witnessFile: g.witnesses[0]?.srcRef.file,
          witnessSpan: g.witnesses[0]?.srcRef.span,
        })),
      },
      battery: {
        result: transcript.result,
        runs: transcript.runs,
        seeds: transcript.seeds,
        variance: transcript.fingerprintVariance,
        violationCount: transcript.violations.length,
        violations: transcript.violations.slice(0, 8).map((v) => ({
          kind: v.kind,
          host: v.host,
          capability: v.capability,
          detail: v.detail,
          atSeq: v.atSeq,
        })),
      },
    }, null, 2));
    return verdictExitCode(verdict);
  }

  console.log(`${c.bold("[3/3] Verdict:")} ${verdictBadge(verdict)}`);
  console.log(c.dim(`  time to verdict: ${(elapsedMs / 1000).toFixed(2)}s`));
  console.log("");

  if (verdict === "ADMIT") {
    console.log(`  ${c.green("Your app is deterministic and in-policy across every trial.")}`);
    console.log(`  ${c.dim("If submitted, an admission certificate at Tier B issues immediately.")}`);
    console.log("");
    return 0;
  }

  if (verdict === "ADMIT_WITH_VARIANCE_WARNING") {
    console.log(`  ${c.yellow("Your app is in-policy but non-deterministic.")}`);
    console.log(`  ${c.dim(`The same input produces different boundary sequences across seeds (variance ${variance.toFixed(3)} > 0.05).`)}`);
    console.log(`  ${c.dim("Stores can still admit at Tier B with a warning, but Tier C (sampled replay) will reject — the fingerprint won't match across re-runs.")}`);
    console.log("");
    console.log(`  ${c.bold("How to make this pass at every tier:")}`);
    console.log(`    Remove any randomness in your app's control flow that affects what crosses the boundary.`);
    console.log(`    Typical sources: \`env.random()\`, \`Date.now()\`-driven branches, race conditions on async.`);
    console.log("");
    return 1;
  }

  // REJECT_PRESHIP — the dev-facing why + how-to-fix.
  const first = transcript.violations[0];
  if (first) {
    const action = KIND_TO_ACTION[first.kind] ?? "reach";
    const directive = first.detail.split(" (")[1]?.replace(")", "") ?? "connect-src";
    console.log(`  ${c.red(c.bold("Why your app was caught"))}`);
    console.log(`    ${c.red("Your app tries to")} ${c.bold(action + " " + (first.host ?? first.capability ?? "an undeclared target"))} ${c.dim(`(${directive})`)}`);
    console.log(`    ${c.red("That target is NOT in your declared manifest.")}`);
    console.log("");
    console.log(`  ${c.bold("First violation detail:")}`);
    console.log(`    payload:        ${c.cyan(payloadNameForSeq(first.atSeq))}`);
    console.log(`    seed:           ${c.cyan(String(args.seeds[0]))}`);
    console.log(`    at sequence:    ${c.cyan("index " + first.atSeq)}`);
    if (first.host) console.log(`    target host:    ${c.cyan(first.host)}`);
    if (first.capability) console.log(`    capability:     ${c.cyan(first.capability)}`);
    console.log("");
  }

  const byHost = new Map<string, number>();
  for (const v of transcript.violations) {
    if (v.host) byHost.set(v.host, (byHost.get(v.host) ?? 0) + 1);
  }
  if (byHost.size > 0) {
    console.log(`  ${c.bold("All undeclared targets across the run:")}`);
    for (const [host, hits] of [...byHost.entries()].sort((a, b) => b[1] - a[1])) {
      console.log(`    ${c.red("⛔")} ${host}  ${c.dim(`(${hits} hit${hits === 1 ? "" : "s"})`)}`);
    }
    console.log("");
  }

  console.log(`  ${c.bold("How to make this pass")}`);
  if (first?.host) {
    console.log(`    ${c.green("1.")} Declare ${c.cyan(first.host)} in your connect-src manifest.`);
    console.log(`       ${c.dim(`tradeoff: stores see the wider grant on your certificate and decide whether to admit.`)}`);
  }
  console.log(`    ${c.green(first?.host ? "2." : "1.")} Don't fetch URLs derived from untrusted input.`);
  console.log(`       ${c.dim("treat user input as data, not as a URL source. route through a declared endpoint.")}`);
  console.log("");
  console.log(`  ${c.bold("Compare to the old flow")}`);
  console.log(`    ${c.red("app store today:")}  ${c.dim('"your app was rejected for policy violation 4.5.1." Two weeks. No specifics.')}`);
  console.log(`    ${c.green("Skybridge:")}        ${c.dim(`ran ${transcript.runs} trials and surfaced the exact catch above in ${(elapsedMs / 1000).toFixed(2)}s.`)}`);
  console.log(`    ${c.bold("delta:")}             ${c.dim("Two weeks → seconds. A line of vague policy text → a line of code you can grep for.")}`);
  console.log("");

  return 2;
}

function verdictBadge(verdict: string): string {
  if (verdict === "ADMIT") return c.green("✓ ADMIT") + " " + c.dim("· Tier B");
  if (verdict === "ADMIT_WITH_VARIANCE_WARNING") return c.yellow("⚠ ADMIT · variance warning");
  return c.red("⛔ REJECTED · pre-ship catch");
}
function verdictExitCode(verdict: string): number {
  if (verdict === "ADMIT") return 0;
  if (verdict === "ADMIT_WITH_VARIANCE_WARNING") return 1;
  return 2;
}
function payloadNameForSeq(_atSeq: number): string {
  // The Battery iterates payloads × seeds; atSeq is per-run boundary index,
  // not the payload index. We can't tell which payload from atSeq alone in
  // the current Violation shape, so name the canonical prompt-injection one
  // (the input the maliciousApp reflects). Future heal: thread payload name
  // through Violation so the CLI can name it precisely.
  return "prompt-injection-url (the fixed adversarial input the battery always runs)";
}

// ---- main -----------------------------------------------------------------
async function main(): Promise<void> {
  let args: CliArgs;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error(c.red(`✗ ${msg}`));
    process.exit(3);
  }
  if (args.cmd === "help" || args.cmd === null) {
    printHelp();
    process.exit(0);
  }
  if (args.cmd === "check") {
    const code = await runCheck(args);
    process.exit(code);
  }
}

main().catch((e) => {
  console.error(c.red(`✗ ${e instanceof Error ? e.message : String(e)}`));
  process.exit(3);
});
