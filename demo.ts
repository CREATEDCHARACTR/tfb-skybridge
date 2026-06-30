// TFB Skybridge — node-only end-to-end showcase.
//
// Walks the full pipeline without a browser:
//   1. Cables analyzes the sample source → grants + witnesses + CSP
//   2. Battery runs the well-behaved / malicious / flaky apps under PAYLOADS×seeds
//      and produces a signed transcript
//   3. Proof Bay issues an admission bundle, appends to the transparency log
//   4. The store verifies at Tier A, B, then C (with reproducer)
//   5. Span runs benign / drift / exfil sessions through the admitted envelope
//   6. Revocations are posted to the same log and verified
//   7. A host-side Monitor accepts a consistent log growth and rejects a forged one
//
// Run: `npm run demo` (tsx demo.ts)
import { analyze } from "./src/cables/analyze";
import { sampleSource, EXPECTED_GRANTS } from "./src/cables/sampleSource";
import { runBattery } from "./src/battery/runner";
import { PAYLOADS, wellBehavedApp, maliciousApp, flakyApp } from "./src/battery/apps";
import { generateKeyPair, signBytes } from "./src/crypto";
import { TransparencyLog } from "./src/merkle";
import { Monitor, issueSTH, signTreeHead } from "./src/monitor";
import { verifyAdmission } from "./src/proofbay/verify";
import type { StorePolicy, SignedIdentity } from "./src/proofbay/types";
import {
  admit,
  openSpan,
  sandboxPolicyFromAnalysis,
  postRevocation,
  verifyLoggedRevocation,
  hostDecision,
} from "./src/loop";
import { benignRun, driftRun, exfilRun } from "./src/runs";
import type { BoundaryEvent as SpanEvent } from "./src/span/types";

const HR = "─".repeat(72);
const BUL = "  •";

function section(title: string) {
  process.stdout.write(`\n${HR}\n  ${title}\n${HR}\n`);
}
function line(s: string) {
  process.stdout.write(`${BUL} ${s}\n`);
}

async function main() {
  // ---- keys + identities ------------------------------------------------
  const issuerKeys = generateKeyPair();
  const logKeys = generateKeyPair();
  const devKeys = generateKeyPair();
  const spanKeys = generateKeyPair();
  const batteryKeys = generateKeyPair();
  const issuer: SignedIdentity = { name: "TFB Proof Bay", publicKeyPem: issuerKeys.publicKeyPem };
  const developer: SignedIdentity = { name: "Acme Pay", publicKeyPem: devKeys.publicKeyPem };
  const log = new TransparencyLog("demo-log");

  const storePolicyB: StorePolicy = {
    tier: "B",
    trustedIssuers: [issuerKeys.publicKeyPem],
    trustedLogs: [logKeys.publicKeyPem],
    minBatteryVersion: "1.0.0",
    maxFingerprintVariance: 0.05,
  };

  // ---- 1. Cables --------------------------------------------------------
  section("1 · Cables — static analysis derives a minimal CSP from source");
  const analyzed = analyze(sampleSource());
  line(`scanned ${analyzed.artifact.size} files`);
  line(`emitted ${analyzed.grants.length} grants (each with ≥1 byte-span witness)`);
  for (const g of analyzed.grants) {
    const w = g.witnesses[0];
    line(`  - ${g.grant}  ←  ${w.srcRef.file}[${w.srcRef.span[0]}, ${w.srcRef.span[1]}) sha256=${w.srcRef.contentHash.slice(0, 12)}…`);
  }
  line(`ignored ${analyzed.report.ignoredRelative} relative URL(s) (no grant needed)`);
  const expectedOk = JSON.stringify(analyzed.cspPolicy) === JSON.stringify(EXPECTED_GRANTS);
  line(`cspPolicy matches EXPECTED_GRANTS? ${expectedOk ? "yes" : "NO"}`);

  // ---- 2. Battery (three apps) -----------------------------------------
  section("2 · Battery — adversarial pre-ship runs (payloads × seeds)");
  const sandboxPolicy = sandboxPolicyFromAnalysis(analyzed);
  const seeds = [1, 3, 7, 8];

  const wellTr = await runBattery({ app: wellBehavedApp, policy: sandboxPolicy, payloads: PAYLOADS, seeds }, batteryKeys.privateKeyPem);
  line(`well-behaved:  result=${wellTr.result}  violations=${wellTr.violations.length}  variance=${wellTr.fingerprintVariance.toFixed(3)}`);
  line(`               observed egress = [${wellTr.observedEgress.join(", ")}]`);

  const malTr = await runBattery({ app: maliciousApp, policy: sandboxPolicy, payloads: PAYLOADS, seeds }, batteryKeys.privateKeyPem);
  line(`malicious:     result=${malTr.result}  violations=${malTr.violations.length}  (first: ${malTr.violations[0]?.detail ?? "—"})`);

  const flakyTr = await runBattery({ app: flakyApp, policy: sandboxPolicy, payloads: PAYLOADS, seeds: [1, 2, 3, 4, 5, 6, 7, 8] }, batteryKeys.privateKeyPem);
  line(`flaky:         result=${flakyTr.result}  variance=${flakyTr.fingerprintVariance.toFixed(3)}  (non-determinism surfaced)`);

  // ---- 3. Proof Bay issues an admission bundle --------------------------
  section("3 · Proof Bay — bundle, sign, append to transparency log");
  const bundle = admit({
    analyzed,
    transcript: wellTr,
    appId: "acme-checkout",
    version: "1.0.0",
    developer,
    issuer,
    issuerPriv: issuerKeys.privateKeyPem,
    log,
    logPriv: logKeys.privateKeyPem,
  });
  line(`bundle issued for "${bundle.subject.appId}" v${bundle.subject.version}`);
  line(`artifactHash = ${bundle.subject.artifactHash.slice(0, 16)}…`);
  line(`logged at index ${bundle.issuance.transparencyReceipt?.leafIndex} (treeSize ${bundle.issuance.transparencyReceipt?.treeSize})`);

  // ---- 4. Verify at three tiers ----------------------------------------
  section("4 · Verify — three tiers of trust");
  const a = verifyAdmission(bundle, analyzed.artifact, { ...storePolicyB, tier: "A" });
  line(`Tier A (identity + transparency + freshness):  ${a.ok ? "ADMIT" : "REJECT " + a.reason}`);
  const b = verifyAdmission(bundle, analyzed.artifact, storePolicyB);
  line(`Tier B (+ witnesses + minimality + egress):    ${b.ok ? "ADMIT" : "REJECT " + b.reason}`);
  const c = verifyAdmission(bundle, analyzed.artifact, { ...storePolicyB, tier: "C" }, () => ({
    fingerprint: bundle.dynamicAttestation.fingerprint,
    observedEgress: bundle.dynamicAttestation.observedEgress,
  }));
  line(`Tier C (+ sampled re-derivation via reproducer): ${c.ok ? "ADMIT" : "REJECT " + c.reason}`);

  // ---- 5. Span — three runtime sessions --------------------------------
  section("5 · Span — runtime sessions against the admitted envelope");

  function runSession(name: string, events: SpanEvent[]): { verdict: string; revocation: ReturnType<typeof postRevocation> | null } {
    const span = openSpan(`demo-${name}`, bundle, spanKeys.privateKeyPem);
    for (const e of events) span.observe(e);
    const { head, revocation } = span.finalize();
    let logged: ReturnType<typeof postRevocation> | null = null;
    if (revocation) {
      logged = postRevocation(revocation, log, logKeys.privateKeyPem);
      const ok = verifyLoggedRevocation(logged, logKeys.publicKeyPem);
      line(`${name.padEnd(8)}  verdict=${head.verdict}  → revocation at log index ${logged.leafIndex} (verifies=${ok})`);
      line(`            reason: ${revocation.detail}`);
    } else {
      line(`${name.padEnd(8)}  verdict=${head.verdict}  no revocation`);
    }
    return { verdict: head.verdict, revocation: logged };
  }

  const benign = runSession("benign", benignRun());
  const drift = runSession("drift", driftRun());
  const exfil = runSession("exfil", exfilRun());

  // ---- 6. Host decisions -----------------------------------------------
  section("6 · Host decision — RENDER or STOP, per session");
  for (const [name, rev] of [["benign", benign.revocation], ["drift", drift.revocation], ["exfil", exfil.revocation]] as const) {
    const d = hostDecision(bundle, analyzed.artifact, storePolicyB, rev, logKeys.publicKeyPem);
    line(`${name.padEnd(8)} → ${d.decision}  (${d.reason})`);
  }

  // ---- 7. Host-side Monitor over the transparency log ------------------
  section("7 · Monitor — accept consistent growth, reject forged STH");
  const mon = new Monitor("demo-log", logKeys.publicKeyPem);
  const seedSth = issueSTH(log, logKeys.privateKeyPem, log.size);
  line(`seed STH: size=${seedSth.treeSize} root=${seedSth.rootHash.slice(0, 12)}…  accepted=${mon.update(seedSth, null)}`);

  // legitimate append: log gets a benign new entry
  log.append(Buffer.from("auxiliary entry"));
  const grown = issueSTH(log, logKeys.privateKeyPem);
  const proof = log.consistency(seedSth.treeSize, grown.treeSize);
  const ok = mon.update(grown, proof);
  line(`legit grow → size=${grown.treeSize} root=${grown.rootHash.slice(0, 12)}…  accepted=${ok}`);

  // forged: same size, lying root
  const fakeRoot = "ab".repeat(32);
  const forged = signTreeHead("demo-log", grown.treeSize, fakeRoot, logKeys.privateKeyPem);
  // Monitor's verifyConsistency rebuilds the new root from the latest accepted
  // root + the proof — a lying root won't match the rebuilt one.
  let rejected = false;
  try { rejected = !mon.update(forged, []); } catch { rejected = true; }
  line(`forged STH (split-view forgery attempt) → rejected=${rejected}`);

  // ---- summary ----------------------------------------------------------
  section("done");
  const allOk =
    a.ok && b.ok && c.ok &&
    expectedOk &&
    wellTr.result === "PASS" && malTr.result === "FAIL" && flakyTr.fingerprintVariance > 0 &&
    benign.verdict === "ADMITTED" &&
    drift.verdict === "DRIFT" &&
    exfil.verdict === "VIOLATION" &&
    ok && rejected;
  line(`overall: ${allOk ? "every claim checked out." : "SOMETHING REGRESSED — re-read the section above."}`);
  process.stdout.write("\n");
}

main().catch((e) => {
  console.error("demo crashed:", e);
  process.exit(1);
});
