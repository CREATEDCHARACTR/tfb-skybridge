#!/usr/bin/env node
// verify-consumer-install — the detective control that would have caught
// the 0.1.0 → 0.1.1 bug (examples shipped as .ts which Node refuses to
// strip-types under node_modules/).
//
// Strategy: pack the current source into a tarball, install it into a clean
// /tmp dir as a real npm consumer would, then run the CLI from
// node_modules/.bin against the bundled examples and assert correct exit
// codes (0/1/2). This is the only test path that mirrors the consumer's
// actual reality — every other test runs from inside the source tree where
// Node strips .ts natively.
//
// Doctrine: any package that ships executable example code needs an
// install-then-run gate in prepublishOnly. The 0.1.0 bug survived the full
// prepublishOnly chain AND two independent persona audits because no layer
// reproduced the node_modules constraint. Wiring 0.1.2 closes that class.

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = join(__dirname, "..");
const PKG_NAME = JSON.parse(readFileSync(join(PKG_ROOT, "package.json"), "utf8")).name;

const EXPECTED = [
  { dir: "well-behaved-app", code: 0, label: "ADMIT" },
  { dir: "flaky-app",        code: 1, label: "ADMIT-with-variance" },
  { dir: "malicious-app",    code: 2, label: "REJECT-pre-ship" },
];

const cleanupPaths = [];
process.on("exit", () => {
  for (const path of cleanupPaths.reverse()) rmSync(path, { recursive: true, force: true });
});

function step(s) { process.stdout.write(`  ${s}\n`); }
function die(s) { process.stderr.write(`\nverify-consumer-install: FAIL — ${s}\n`); process.exit(1); }

console.log("verify-consumer-install: simulating a real consumer install + run");

// (1) rebuild and pack the current source into a tarball. The explicit build
// makes this gate independent of stale ignored dist bytes; --ignore-scripts
// keeps npm's lifecycle chatter from corrupting its documented JSON result.
step("building fresh distributable bytes");
let tarballName;
const npmCacheRoot = mkdtempSync(join(tmpdir(), "skybridge-npm-cache-"));
cleanupPaths.push(npmCacheRoot);
const npmEnv = { ...process.env, npm_config_cache: npmCacheRoot };
try {
  execFileSync("npm", ["run", "build"], {
    cwd: PKG_ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: npmEnv,
  });
  step("packing rebuilt source");
  // `npm pack --json` returns an array; the first entry's .filename is the tarball name
  const out = execFileSync("npm", ["pack", "--json", "--ignore-scripts"], {
    cwd: PKG_ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], env: npmEnv,
  });
  tarballName = JSON.parse(out)[0].filename;
} catch (e) {
  die(`npm pack failed: ${e.message}`);
}
const tarballPath = join(PKG_ROOT, tarballName);
cleanupPaths.push(tarballPath);

// (2) clean install into a fresh /tmp dir
const sandbox = mkdtempSync(join(tmpdir(), "skybridge-consumer-"));
cleanupPaths.push(sandbox);
step(`installing into ${sandbox}`);
writeFileSync(join(sandbox, "package.json"), JSON.stringify({
  name: "consumer-install-test",
  version: "1.0.0",
  private: true,
  type: "module",
}, null, 2));
try {
  execFileSync("npm", ["install", tarballPath, "--omit=dev", "--no-audit", "--no-fund", "--silent"], {
    cwd: sandbox, stdio: ["ignore", "pipe", "pipe"], env: npmEnv,
  });
} catch (e) {
  die(`npm install failed: ${e.message}`);
}

// (3) run the CLI from node_modules/.bin against the bundled examples
const cli = join(sandbox, "node_modules", ".bin", "tfb-skybridge");
let failed = 0;
for (const { dir, code, label } of EXPECTED) {
  const appPath = join(sandbox, "node_modules", PKG_NAME, "examples", dir);
  let exitCode;
  try {
    execFileSync(cli, ["check", appPath], { stdio: "ignore" });
    exitCode = 0;
  } catch (e) {
    exitCode = e.status ?? -1;
  }
  if (exitCode === code) {
    step(`✓ ${dir} → exit ${exitCode} (${label})`);
  } else {
    step(`✗ ${dir} → exit ${exitCode} (expected ${code} for ${label})`);
    failed++;
  }
}

// (4) exercise the installed Drawbridge module seam under native Node ESM.
try {
  const installedRoot = join(sandbox, "node_modules", PKG_NAME, "dist", "src", "behavior", "extraction");
  const producer = await import(pathToFileURL(join(installedRoot, "producer.js")).href);
  const shadow = await import(pathToFileURL(join(installedRoot, "shadow.js")).href);
  const produced = producer.produceInferenceObservation({
    tenantId: "consumer-tenant",
    sessionId: "consumer-session",
    sequence: 1n,
    rawQuery: "consumer install alpha beta gamma",
    regionLabel: "consumer-region",
  }, Buffer.alloc(32, 11));
  if (!produced.ok || !produced.observation) throw new Error("producer_did_not_emit");
  const observer = new shadow.ShadowExtractionObserver({ ttlMs: 1_000 });
  const observed = observer.observe(produced.observation);
  const closed = observer.close();
  if (!observed.ok || !closed.ok || closed.metrics.retained_events_total !== 0) {
    throw new Error("observer_lifecycle_failed");
  }
  step("✓ drawbridge modules → native ESM producer/observe/close");
} catch (e) {
  step(`✗ drawbridge modules → ${e.message}`);
  failed++;
}

// (5) execute the installed Drawbridge CLI through the package's real bin.
// This must not depend on the source-only `tsx` devDependency.
try {
  const installedPackage = JSON.parse(readFileSync(join(sandbox, "node_modules", PKG_NAME, "package.json"), "utf8"));
  if (installedPackage.bin?.["tfb-drawbridge"] !== "dist/src/drawbridge-runtime/cli.js"
    || installedPackage.scripts?.["drawbridge:serve"] !== "node dist/src/drawbridge-runtime/cli.js serve"
    || installedPackage.scripts?.["drawbridge:agent"] !== "node dist/src/drawbridge-runtime/cli.js"
    || installedPackage.scripts?.["drawbridge:janitor"] !== "node dist/src/drawbridge-runtime/cli.js retention-sweep") {
    throw new Error("drawbridge_package_entry_contract_invalid");
  }
  if (existsSync(join(sandbox, "node_modules", "tsx"))) {
    throw new Error("drawbridge_consumer_unexpected_dev_only_tsx");
  }
  const help = execFileSync("npm", ["exec", "--", "tfb-drawbridge", "--help"], {
    cwd: sandbox, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: npmEnv,
  });
  if (!help.includes("TFB Drawbridge · OBSERVE_ONLY demo") || !help.includes("No command calls a model provider.")) {
    throw new Error(`drawbridge_cli_help_contract_invalid:${JSON.stringify(help.slice(0, 500))}`);
  }
  step("✓ Drawbridge CLI → documented npm exec invocation, native Node, dev dependencies omitted");
} catch (e) {
  step(`✗ Drawbridge CLI → ${e.message}`);
  failed++;
}

// (6) cleanup
rmSync(sandbox, { recursive: true, force: true });
rmSync(tarballPath, { force: true });
rmSync(npmCacheRoot, { recursive: true, force: true });

if (failed > 0) {
  die(`${failed}/${EXPECTED.length + 2} consumer checks failed. Do NOT publish.`);
}
console.log(`verify-consumer-install: ALL ${EXPECTED.length + 2}/${EXPECTED.length + 2} pass. consumer install is real-world correct.`);
