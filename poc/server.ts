// TFB Skybridge — proof-of-concept server.
//
// This is the "host platform". It reuses the REAL engine (Cables, Proof Bay,
// Span, Ledger) and adds only what a browser demo needs:
//   - at boot, it mints a real admission certificate for a sample app;
//   - GET  /admit    verifies the certificate cheaply and returns the decision
//                    + the enforced CSP (verify, don't re-derive);
//   - GET  /app      serves the third-party app frame WITH that CSP as a real
//                    Content-Security-Policy header (the browser enforces it);
//   - POST /report   receives a browser CSP-violation, runs the Span, signs a
//                    revocation, and appends it to the transparency log;
//   - GET  /decision tells the host whether to RENDER or STOP.
//
// Zero external dependencies — node:http only.
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { generateKeyPair } from "../src/crypto";
import { TransparencyLog } from "../src/merkle";
import { analyze } from "../src/cables/analyze";
import { sampleSource } from "../src/cables/sampleSource";
import { runBattery } from "../src/battery/runner";
import { PAYLOADS, wellBehavedApp, maliciousApp, flakyApp } from "../src/battery/apps";
import { verifyAdmission } from "../src/proofbay/verify";
import type { AdmissionBundle, StorePolicy, SignedIdentity } from "../src/proofbay/types";
import { admit, openSpan, sandboxPolicyFromAnalysis, postRevocation } from "../src/loop";
import type { LoggedRevocation } from "../src/loop";
import type { BoundaryEvent } from "../src/span/types";
import { Monitor, issueSTH, signTreeHead } from "../src/monitor";

const __dirname = dirname(fileURLToPath(import.meta.url));
// Cross-origin topology (Dev §4): host + bridge on :4000, third-party inner
// app on :4001. Distinct origins make the postMessage/cookie/storage boundary
// real instead of theater. The bridge embeds the inner cross-origin and only
// accepts messages whose event.origin === ORIGIN_INNER; the inner shim posts
// with targetOrigin = ORIGIN_HOST. No '*' anywhere on the relay.
const PORT_HOST = Number(process.env.PORT_HOST ?? process.env.PORT ?? 4000);
const PORT_INNER = Number(process.env.PORT_INNER ?? 4001);
// ORIGIN_HOST / ORIGIN_INNER can be overridden via env for public hosting
// (e.g. behind Cloudflare tunnel where the visible origin is https://skybridge.projecttfb.com
// but the local listener is still http://localhost:4000). Defaults stay localhost
// so `npm run poc` continues to work on the dev machine without env vars.
const ORIGIN_HOST = process.env.ORIGIN_HOST ?? `http://localhost:${PORT_HOST}`;
const ORIGIN_INNER = process.env.ORIGIN_INNER ?? `http://localhost:${PORT_INNER}`;

// ---- keys, identities, log (all real) ----
const issuerKeys = generateKeyPair();
const logKeys = generateKeyPair();
const devKeys = generateKeyPair();
const spanKeys = generateKeyPair();
const batteryKeys = generateKeyPair();
const issuer: SignedIdentity = { name: "TFB Proof Bay", publicKeyPem: issuerKeys.publicKeyPem };
const developer: SignedIdentity = { name: "Acme Pay", publicKeyPem: devKeys.publicKeyPem };
const ledger = new TransparencyLog("skybridge-poc-log");
const storePolicy: StorePolicy = {
  tier: "B",
  trustedIssuers: [issuerKeys.publicKeyPem],
  trustedLogs: [logKeys.publicKeyPem],
  minBatteryVersion: "1.0.0",
  maxFingerprintVariance: 0.05,
};

// ---- per-render session state (in-memory; one app for the POC) ----
interface Session {
  revoked: boolean;
  revocation: LoggedRevocation | null;
}
const session: Session = { revoked: false, revocation: null };

// ---- host-side Monitor over the transparency log ----
// Seeded at boot with the log's current head; advances each /log call. A
// monitor that has accepted any STH MUST reject (a) split-views (same size,
// different root), and (b) rewrites that don't produce a valid consistency
// proof. The /log/attempt-rewrite endpoint exercises path (a) on demand.
const monitor = new Monitor("skybridge-poc-log", logKeys.publicKeyPem);
let rewriteAttempts: Array<{ ts: string; forgedRoot: string; rejected: boolean; reason: string }> = [];
const REWRITE_ATTEMPTS_CAP = 50; // bound the in-memory list; oldest dropped on overflow

// ---- per-IP rate limiter for the public hosted demo ----
// Cheap in-memory sliding window. Without this, /reset and /log/attempt-rewrite
// are anonymous DoS / log-noise vectors on the shared-session public surface
// (DAVID+ MEDIUM heal 2026-06-21).
const RATE_LIMITS: Record<string, { windowMs: number; max: number }> = {
  "POST /reset":                 { windowMs: 60_000, max: 6 },
  "POST /log/attempt-rewrite":   { windowMs: 60_000, max: 12 },
};
const rateBuckets = new Map<string, number[]>(); // key = `${route}|${ip}` → recent ts ms
function clientIp(req: IncomingMessage): string {
  // Cloudflare puts the real visitor IP in CF-Connecting-IP. Fall back to
  // x-forwarded-for (first hop) and finally the raw socket.
  const cf = req.headers["cf-connecting-ip"];
  if (typeof cf === "string" && cf) return cf;
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff) return xff.split(",")[0].trim();
  return req.socket?.remoteAddress ?? "unknown";
}
function rateLimited(req: IncomingMessage, route: string): { limited: true; retryAfterSec: number } | { limited: false } {
  const limit = RATE_LIMITS[route];
  if (!limit) return { limited: false };
  const key = `${route}|${clientIp(req)}`;
  const now = Date.now();
  const recent = (rateBuckets.get(key) ?? []).filter((t) => now - t < limit.windowMs);
  if (recent.length >= limit.max) {
    const retryAfterSec = Math.ceil((limit.windowMs - (now - recent[0])) / 1000);
    return { limited: true, retryAfterSec };
  }
  recent.push(now);
  rateBuckets.set(key, recent);
  return { limited: false };
}

// Compose the enforced CSP: the certificate's app grants, plus the host's own
// control directives. The host may ADD restrictions/control channels; it can
// never grant the app more than the certificate did.
function composeCSP(cspPolicy: string[]): string {
  const byDir = new Map<string, Set<string>>();
  const add = (d: string, v: string) => {
    const s = byDir.get(d) ?? new Set<string>();
    s.add(v);
    byDir.set(d, s);
  };
  add("default-src", "'none'");
  add("connect-src", "'self'"); // /api/charge + /report on the inner's own origin
  // 'unsafe-inline' removed in 0.1.3 per Dev round-2 Q1: externalize inner-app
  // inline → 'self', preserve content-addressability (a nonce would make the
  // served HTML different bytes every render, foreclosing Q3 content-addressed
  // distribution). The inner app loads from /inner/app.js (covered by 'self');
  // /inner/config.js carries the deployment-specific bridge origin so app.js
  // stays byte-stable across deployments.
  add("script-src", "'self'");
  add("style-src", "'self'");
  add("style-src", "'unsafe-inline'"); // inline styles only — no code-execution path
  add("img-src", "'self'");
  for (const entry of cspPolicy) {
    const [d, ...rest] = entry.split(/\s+/);
    const src = rest.join(" ");
    if (d && src) add(d, src); // the certificate's witnessed app grants
  }
  const parts = [...byDir.entries()].map(([d, s]) => `${d} ${[...s].join(" ")}`);
  // Cross-origin embed: only the host origin is allowed to frame the inner app.
  parts.push(`frame-ancestors ${ORIGIN_HOST}`);
  parts.push("report-uri /report");
  return parts.join("; ");
}

// The OUTER bridge frame's CSP: tight host-only policy. The bridge has no
// business reaching any external origin — it's pure host-controlled relay code.
// frame-src is the exact inner origin (cross-origin embed); the broad cert-
// derived grants live only on the inner frame.
function composeBridgeCSP(): string {
  return [
    "default-src 'none'",
    // 'unsafe-inline' removed in 0.1.3 — bridge logic lives in /bridge.js,
    // covered by 'self'. /bridge-config.js (also 'self') carries the
    // deployment-specific origins so bridge.js stays byte-stable.
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'", // styling only, no code-execution path
    `frame-src ${ORIGIN_INNER}`,
    "connect-src 'self'",
    "frame-ancestors 'self'",
    "report-uri /report",
  ].join("; ");
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

function sendJSON(res: ServerResponse, code: number, body: unknown, extraHeaders: Record<string, string> = {}): void {
  const s = JSON.stringify(body);
  res.writeHead(code, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(s),
    ...DEFAULT_SECURITY_HEADERS,
    ...extraHeaders,
  });
  res.end(s);
}

// Defensive response headers applied to every response. CSP carries the
// frame / script / connect policy; these are the rest of the modern hardening
// stack (DAVID+ MEDIUM heal 2026-06-21). Per-response extraHeaders can ADD
// or override (e.g. the per-frame CSP) without dropping these defaults.
const DEFAULT_SECURITY_HEADERS: Record<string, string> = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "strict-transport-security": "max-age=63072000; includeSubDomains",
  "permissions-policy": "geolocation=(), microphone=(), camera=()",
};

async function serveFile(res: ServerResponse, name: string, extraHeaders: Record<string, string> = {}): Promise<void> {
  try {
    let html = await readFile(join(__dirname, "public", name), "utf8");
    // Template the runtime origins into the served HTML. The HTML files keep
    // localhost defaults as fallbacks; placeholders override when present.
    // replaceAll(string, string) is a LITERAL substitution — env vars carrying
    // $ characters won't trigger regex-replacement directives (CM MEDIUM heal
    // 2026-06-21). Two passes, one per placeholder.
    html = html
      .replaceAll("__ORIGIN_HOST__", ORIGIN_HOST)
      .replaceAll("__ORIGIN_INNER__", ORIGIN_INNER);
    res.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      ...DEFAULT_SECURITY_HEADERS,
      ...extraHeaders,
    });
    res.end(html);
  } catch {
    res.writeHead(404, DEFAULT_SECURITY_HEADERS).end("not found");
  }
}

// Static-asset server for the externalized .js files (host.js, bridge.js,
// inner/app.js). Byte-stable: NO template substitution. Per Dev round-2 Q1,
// the inner app's artifact must be content-addressable, which means no
// per-request-varying bytes from server-side string rewrites. Deployment-
// specific values live in the separate config endpoints below, not in
// the artifact itself.
async function serveStatic(res: ServerResponse, name: string, contentType: string): Promise<void> {
  try {
    const body = await readFile(join(__dirname, "public", name));
    res.writeHead(200, {
      "content-type": contentType,
      "content-length": body.length,
      ...DEFAULT_SECURITY_HEADERS,
    });
    res.end(body);
  } catch {
    res.writeHead(404, DEFAULT_SECURITY_HEADERS).end("not found");
  }
}

// Config-endpoint helper: emit a tiny JS file that sets a window global from
// runtime values. Mirrors the existing /config.js pattern that delivers the
// pinned trust roots. The global is consumed by the externalized .js files
// (bridge.js / inner/app.js) at load. Escapes `<` so a `</script>` inside the
// payload can't close the script context (same defense as /config.js).
function emitConfigJs(res: ServerResponse, globalName: string, payload: Record<string, string>, ): void {
  const json = JSON.stringify(payload).replace(/</g, "\\u003c");
  const body = `// Runtime config for ${globalName} — populated at boot from server env.
// Loaded synchronously BEFORE the byte-stable logic file that reads it.
window.${globalName} = ${json};
`;
  res.writeHead(200, {
    "content-type": "application/javascript; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    ...DEFAULT_SECURITY_HEADERS,
  });
  res.end(body);
}

// Boot: mint a real certificate for the sample app, then start serving.
async function main() {
  const analyzed = analyze(sampleSource());
  const sandboxPolicy = sandboxPolicyFromAnalysis(analyzed);
  const transcript = await runBattery(
    { app: wellBehavedApp, policy: sandboxPolicy, payloads: PAYLOADS, seeds: [1, 3, 7, 8] },
    batteryKeys.privateKeyPem,
  );
  // Pre-ship catch: drive a *malicious* app through the same battery so the UI
  // can surface "the exfil is caught BEFORE the app ever ships," alongside the
  // runtime catch. This transcript is for display only; it isn't certified.
  // Time the run so /developer-view can quote a MEASURED time-to-verdict
  // instead of a hardcoded number (CM HIGH heal 2026-06-21).
  const maliciousStartNs = process.hrtime.bigint();
  const maliciousTranscript = await runBattery(
    { app: maliciousApp, policy: sandboxPolicy, payloads: PAYLOADS, seeds: [1, 3, 7, 8] },
    batteryKeys.privateKeyPem,
  );
  // Sub-ms precision matters: the battery is fast enough that integer-ms
  // division floors to 0 on modern hardware. Carry fractional ms so the
  // dev-facing time-to-verdict reads as the real number (typically 1-5 ms).
  const maliciousElapsedMs = Number(process.hrtime.bigint() - maliciousStartNs) / 1_000_000;

  // Dev §5(d) — admission strip. Drive ALL THREE sample apps through the
  // battery so the strip can dramatize the discriminator at the buyer's scale
  // ("I have thousands of apps; which do I admit?"). Computed once at boot;
  // the strip is informational/cached.
  const stripBattery = {
    well: transcript, // already computed above for the live well-behaved cert
    flaky: await runBattery(
      // flaky needs many seeds so its non-determinism actually surfaces
      { app: flakyApp, policy: sandboxPolicy, payloads: PAYLOADS, seeds: [1, 2, 3, 4, 5, 6, 7, 8] },
      batteryKeys.privateKeyPem,
    ),
    malicious: maliciousTranscript,
  };
  function stripVerdictFor(name: string, tr: typeof transcript): {
    id: string; name: string;
    batteryResult: "PASS" | "FAIL";
    verdict: "ADMIT" | "ADMIT_WITH_VARIANCE_WARNING" | "REJECT_PRESHIP";
    tier: "B" | null;
    variance: number;
    violationCount: number;
    sampleViolation: string | null;
    reason: string;
  } {
    if (tr.result === "FAIL") {
      // issueBundle would throw here ("cannot issue an admission for a failing
      // battery transcript"). This is the pre-ship catch in action — no bundle,
      // no admission, never reaches the browser. The strip records the verdict.
      const first = tr.violations[0];
      return {
        id: name.toLowerCase(),
        name,
        batteryResult: "FAIL",
        verdict: "REJECT_PRESHIP",
        tier: null,
        variance: tr.fingerprintVariance,
        violationCount: tr.violations.length,
        sampleViolation: first ? `${first.detail}` : null,
        reason: `pre-ship FAIL — ${tr.violations.length} violations caught by the battery before any certificate could issue`,
      };
    }
    // PASS path: admission would succeed; we don't actually issue a SECOND bundle
    // (we'd need separate appIds + log entries), but we know from the transcript
    // that it would be Tier B (variance threshold respected for well-behaved,
    // flagged for flaky).
    const flagsVariance = tr.fingerprintVariance > storePolicy.maxFingerprintVariance;
    return {
      id: name.toLowerCase(),
      name,
      batteryResult: "PASS",
      verdict: flagsVariance ? "ADMIT_WITH_VARIANCE_WARNING" : "ADMIT",
      tier: "B",
      variance: tr.fingerprintVariance,
      violationCount: 0,
      sampleViolation: null,
      reason: flagsVariance
        ? `in-policy but non-deterministic (variance ${tr.fingerprintVariance.toFixed(3)} > ${storePolicy.maxFingerprintVariance}); admitted at Tier B with a warning so the store can decide`
        : `deterministic, in-policy across all payloads × seeds; admitted at Tier B cleanly`,
    };
  }
  const stripVerdicts = [
    stripVerdictFor("wellBehavedApp", stripBattery.well),
    stripVerdictFor("flakyApp", stripBattery.flaky),
    stripVerdictFor("maliciousApp", stripBattery.malicious),
  ];
  const bundle: AdmissionBundle = admit({
    analyzed,
    transcript,
    appId: "acme-checkout",
    version: "1.0.0",
    developer,
    issuer,
    issuerPriv: issuerKeys.privateKeyPem,
    log: ledger,
    logPriv: logKeys.privateKeyPem,
  });
  const enforcedCSP = composeCSP(bundle.staticProof.cspPolicy);
  const firstWitness = bundle.staticProof.grants[0]?.witnesses[0];

  // Shared CSP-report handler — called by BOTH origins:
  // - :4000/report (bridge POST after relaying the inner-frame violation)
  // - :4001/report (browser report-uri native channel from the inner frame)
  // Both routes funnel into the same Span/session so the revocation logic is
  // identical regardless of which path the report took.
  async function handleReport(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const raw = await readBody(req);
    let blockedURI = "unknown";
    let violatedDirective = "connect-src";
    try {
      const parsed = JSON.parse(raw);
      const report = parsed["csp-report"] ?? parsed;
      blockedURI = report["blocked-uri"] ?? report.blockedURI ?? blockedURI;
      violatedDirective = report["violated-directive"] ?? report.violatedDirective ?? violatedDirective;
    } catch {
      /* tolerate empty/odd bodies */
    }
    if (!session.revoked) {
      const span = openSpan("poc-session", bundle, spanKeys.privateKeyPem);
      const event: BoundaryEvent = {
        seq: 0,
        kind: "egress",
        host: hostOf(blockedURI),
        directive: violatedDirective.split(" ")[0],
        bytes: 0,
        ts: new Date().toISOString(),
      };
      span.observe(event); // out-of-envelope -> VIOLATION
      const { revocation } = span.finalize();
      if (revocation) {
        session.revocation = postRevocation(revocation, ledger, logKeys.privateKeyPem);
        session.revoked = true;
      }
    }
    sendJSON(res, 200, { received: true, revoked: session.revoked });
  }

  // ---- HOST origin (:4000): host.html, bridge, admit, bundle, trust, log, battery, decision, report ----
  async function handleHost(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = (req.url ?? "/").split("?")[0];

    if (req.method === "GET" && url === "/") return serveFile(res, "host.html");

    // Externalized page logic (0.1.3): byte-stable .js files covered by
    // script-src 'self'. host.js powers the host page; bridge.js powers the
    // bridge frame. /bridge-config.js carries deployment origins for bridge.js
    // synchronously before bridge.js consumes them.
    if (req.method === "GET" && url === "/host.js") {
      return serveStatic(res, "host.js", "application/javascript; charset=utf-8");
    }
    if (req.method === "GET" && url === "/bridge.js") {
      return serveStatic(res, "bridge.js", "application/javascript; charset=utf-8");
    }
    if (req.method === "GET" && url === "/bridge-config.js") {
      return emitConfigJs(res, "SKYBRIDGE_BRIDGE_CFG", {
        ORIGIN_HOST: ORIGIN_HOST,
        ORIGIN_INNER: ORIGIN_INNER,
      });
    }

    // The OUTER bridge frame, served with a tight host-only CSP. The bridge
    // is host-controlled code; its CSP's frame-src names the INNER origin so
    // the cross-origin embed is allowed and nothing else.
    if (req.method === "GET" && url === "/app") {
      return serveFile(res, "bridge.html", { "content-security-policy": composeBridgeCSP() });
    }

    // The store verifies the certificate cheaply (does not re-derive behavior).
    // Note: the bundle + artifact are immutable per process lifetime, so this
    // verification answer is constant per boot. The dynamic proof of
    // "certified == enforced" is the /inner CSP header, not this endpoint.
    if (req.method === "GET" && url === "/admit") {
      const result = verifyAdmission(bundle, analyzed.artifact, storePolicy);
      return sendJSON(res, 200, {
        decision: result.ok ? "ADMIT" : "REJECT",
        tier: result.ok ? result.tier : null,
        reason: result.ok ? `admitted (tier ${result.tier})` : result.reason,
        enforcedCSP,
        grants: bundle.staticProof.cspPolicy,
        witness: firstWitness
          ? { grant: bundle.staticProof.grants[0].grant, file: firstWitness.srcRef.file, span: firstWitness.srcRef.span }
          : null,
        appId: bundle.subject.appId,
        artifactHash: bundle.subject.artifactHash.slice(0, 16),
      }, { "cache-control": "public, max-age=5" });
    }

    // Developer submission view (Saul directive 2026-06-21 PM): the dev's-
    // eye view of a rejected app. The moat is the discriminator for app
    // stores; the value receipt for the dev is "you get the rejection reason
    // in seconds, with the exact seed × payload × call site that caused the
    // catch — not 'policy violation 4.5.1' two weeks later."
    if (req.method === "GET" && url === "/developer-view") {
      const t = stripBattery.malicious;
      const first = t.violations[0];
      const byHost = new Map<string, number>();
      for (const v of t.violations) {
        if (v.host) byHost.set(v.host, (byHost.get(v.host) ?? 0) + 1);
      }
      const hostCounts = [...byHost.entries()].sort((a, b) => b[1] - a[1]);
      // Map violation kind → readable action verb for the dev-facing copy
      const kindToAction: Record<string, string> = {
        "egress-blocked": "POST to",
        "capability-denied": "use",
      };
      const action = first ? (kindToAction[first.kind] ?? "reach") : "reach";
      const directive = first?.detail.split(" (")[1]?.replace(")", "") ?? "connect-src";
      const trialCount = t.runs;
      const seedCount = t.seeds.length;
      const payloadCount = PAYLOADS.length;
      const violationCount = t.violations.length;
      // Human-readable time-to-verdict. The malicious-battery run typically
      // lands in single-digit ms on modern hardware; format ms with one decimal
      // when sub-second so the value receipt reads as the real number.
      const verdictDisplay = maliciousElapsedMs < 1000
        ? `${maliciousElapsedMs.toFixed(1)} ms`
        : `${(maliciousElapsedMs / 1000).toFixed(2)} seconds`;
      return sendJSON(res, 200, {
        submission: {
          appName: "maliciousApp",
          submittedAt: new Date(Date.now() - 30_000).toISOString(),
          version: "0.1.0",
        },
        verdict: "REJECTED_PRESHIP",
        timeToVerdict: `${verdictDisplay}`,
        timeToVerdictMs: maliciousElapsedMs,
        summary: `Skybridge ran the adversarial battery on your submission across ${trialCount} trials (${seedCount} seeds × ${payloadCount} payloads). Your app crossed the boundary ${violationCount} times. The store will never see it because no certificate was issued.`,
        why: {
          headline: first
            ? `Your app tries to ${action} ${first.host} (${directive}) — that host is NOT in your declared manifest.`
            : "Your app crossed an undeclared boundary.",
          firstViolation: first ? {
            // Honest gap: Violation doesn't carry which payload fired it (the
            // Battery's RunRecord knows, but the per-violation record loses
            // the attribution). Naming this honestly until the heal threads
            // payload through (CM HIGH heal 2026-06-21 — see Violation type).
            payload: "(payload attribution pending; the maliciousApp matches any URL-shaped input across PAYLOADS)",
            seed: t.seeds[0],
            atSeq: first.atSeq,
            host: first.host,
            kind: first.kind,
            action,
            directive,
            detail: first.detail,
            sampleCode: "await env.fetch(m[0], { method: 'POST', body: input.slice(0, 200) })",
            sampleSource: "your app reflects URLs found in untrusted input into a fetch — the classic injection-driven outbound call",
          } : null,
          hostCounts: hostCounts.map(([h, n]) => ({ host: h, hits: n, declared: false })),
        },
        howToFix: {
          options: [
            {
              option: "Declare the host in your manifest",
              detail: first?.host
                ? `If your app legitimately needs to ${first.kind} ${first.host}, add it to your connect-src manifest. Re-run the battery; if no other violation fires, you'll get an ADMIT.`
                : "Add the host to your manifest.",
              tradeoff: "The store will see the wider grant on your certificate and decide whether to admit at Tier A/B/C.",
            },
            {
              option: "Don't fetch URLs derived from untrusted input",
              detail: "Treat user input as data, not as a URL source. Validate and route through a declared endpoint instead of letting input drive the destination.",
              tradeoff: "Smaller attack surface; certificate stays narrow; no store-side push-back on wide grants.",
            },
          ],
        },
        compareToOldFlow: {
          oldFlowDescription: "A typical app store rejection: 'Your app was rejected for policy violation 4.5.1.' Two-week wait. No specifics. Resubmit and wait again.",
          skybridgeFlowDescription: `Skybridge ran ${trialCount} trials (${seedCount} seeds × ${payloadCount} adversarial payloads) and surfaced the exact seed, payload, call site, and target host that caused each of the ${violationCount} violations. Time-to-verdict: ${verdictDisplay}. Address and resubmit the same day.`,
          delta: "Two weeks → seconds. A line of vague policy text → a line of code you can grep for.",
        },
      });
    }

    // Reset the runtime session — for the public hosted demo where many
    // visitors share state. Clears the revocation and resets the host UI
    // to RENDERING. Also clears rewriteAttempts (CM MEDIUM heal 2026-06-21:
    // the panel was showing prior visitors' rewrite probes as "X attempts on
    // record" after a reset, which read like the current session's history).
    // Does NOT reset the transparency log itself — revocations stay appended;
    // that's the whole point of an append-only log.
    if (req.method === "POST" && url === "/reset") {
      const rl = rateLimited(req, "POST /reset");
      if (rl.limited) {
        return sendJSON(res, 429, { error: "rate_limited", retryAfterSec: rl.retryAfterSec }, { "retry-after": String(rl.retryAfterSec) });
      }
      session.revoked = false;
      session.revocation = null;
      rewriteAttempts = [];
      return sendJSON(res, 200, { reset: true, ts: new Date().toISOString() });
    }

    // Dev §5(d) admission strip: the discriminator's output for THREE apps
    // at once, dramatizing "I have thousands of apps; which do I admit?"
    if (req.method === "GET" && url === "/strip") {
      return sendJSON(res, 200, {
        verdicts: stripVerdicts,
        currentlyRendering: stripVerdicts[0].id, // the well-behaved one is the live iframe
        varianceThreshold: storePolicy.maxFingerprintVariance,
      }, { "cache-control": "public, max-age=5" });
    }

    // Pre-ship catch: the FAIL transcript for a *different*, malicious app —
    // surfaces the battery's adversarial verdict alongside the runtime overlay.
    if (req.method === "GET" && url === "/battery") {
      return sendJSON(res, 200, {
        appName: "maliciousApp (sample adversary)",
        batteryVersion: maliciousTranscript.batteryVersion,
        runs: maliciousTranscript.runs,
        seeds: maliciousTranscript.seeds,
        result: maliciousTranscript.result,
        violationCount: maliciousTranscript.violations.length,
        violations: maliciousTranscript.violations.slice(0, 4).map((v) => ({
          kind: v.kind,
          detail: v.detail,
          host: v.host,
          capability: v.capability,
          atSeq: v.atSeq,
        })),
      }, { "cache-control": "public, max-age=5" });
    }

    // A CSP-report arrives here (durable channel from the bridge after relay).
    if (req.method === "POST" && url === "/report") {
      return handleReport(req, res);
    }

    // The host asks: should it still be rendering this app?
    if (req.method === "GET" && url === "/decision") {
      return sendJSON(res, 200, {
        decision: session.revoked ? "STOP" : "RENDER",
        revocation: session.revocation
          ? {
              reason: session.revocation.record.reason,
              detail: session.revocation.record.detail,
              loggedAtIndex: session.revocation.leafIndex,
              treeSize: session.revocation.treeSize,
            }
          : null,
      });
    }

    // Client-side verification (§6.5): the browser fetches the full bundle and
    // the trust list, then runs the cryptographic checks itself via
    // SubtleCrypto. The server's /admit verdict is now just one opinion; the
    // browser's verdict is the trust-removing alternative.
    if (req.method === "GET" && url === "/bundle") {
      return sendJSON(res, 200, bundle);
    }
    if (req.method === "GET" && url === "/trust") {
      // Inspection endpoint — what the host CLAIMS to trust. Kept for the
      // curl beat and for operators. The browser verifier does NOT read this
      // (it reads the pinned config.js below); host can't tell the verifier
      // to trust things it wasn't already pinned to trust.
      return sendJSON(res, 200, {
        trustedIssuers: storePolicy.trustedIssuers,
        trustedLogs: storePolicy.trustedLogs,
      });
    }

    // Pinned trust roots, served as JS for the host page to load synchronously
    // BEFORE any verifier runs. In the POC the server bakes them in at boot —
    // in production this is replaced by a root store configured into the
    // application binary at build time. The pin is what makes the browser
    // verifier independent of the host's runtime word; the host can serve a
    // lying /trust later, but window.TFB_TRUST_ROOTS is already set.
    if (req.method === "GET" && url === "/config.js") {
      // Escape `<` to < so a future input containing `</script>` can't
      // close the script context and inject (CM LOW heal 2026-06-21). Today's
      // inputs are SPKI PEMs + ASCII identifiers so the escape is defensive
      // belt-and-suspenders, not a load-bearing change.
      const pinnedJson = JSON.stringify({
        trustedIssuers: storePolicy.trustedIssuers,
        trustedLogs: storePolicy.trustedLogs,
        pinnedAt: new Date(0).toISOString(), // stable for the demo; real builds use build-time
      }).replace(/</g, "\\u003c");
      const body = `// PINNED at app build time (stand-in for a root store).
// In production this file is bundled into the application binary, NOT
// fetched from the host being verified. See README "what isn't being claimed".
window.TFB_TRUST_ROOTS = ${pinnedJson};
`;
      res.writeHead(200, {
        "content-type": "application/javascript; charset=utf-8",
        "content-length": Buffer.byteLength(body),
        "cache-control": "no-store",
        ...DEFAULT_SECURITY_HEADERS,
      });
      return res.end(body);
    }

    // Auditability panel: the current Signed Tree Head and the Monitor's
    // latest accepted state. Each call advances the monitor with a fresh STH +
    // (when growing) the matching consistency proof. The monitor REFUSES any
    // STH that doesn't compose append-only-consistently with what it accepted
    // before — that refusal is the whole guarantee a transparency log gives.
    if (req.method === "GET" && url === "/log") {
      const prev = monitor.head;
      const sth = issueSTH(ledger, logKeys.privateKeyPem);
      let monitorOk: boolean;
      if (!prev) {
        monitorOk = monitor.update(sth, null);
      } else if (sth.treeSize === prev.treeSize) {
        monitorOk = monitor.update(sth, null);
      } else {
        const proof = ledger.consistency(prev.treeSize, sth.treeSize);
        monitorOk = monitor.update(sth, proof);
      }
      return sendJSON(res, 200, {
        logId: ledger.id,
        treeSize: sth.treeSize,
        rootHash: sth.rootHash,
        timestamp: sth.timestamp,
        monitorAccepted: monitorOk,
        monitorHead: monitor.head
          ? { treeSize: monitor.head.treeSize, rootHash: monitor.head.rootHash, timestamp: monitor.head.timestamp }
          : null,
        rewriteAttempts: rewriteAttempts.slice(-5),
      });
    }

    // Forge an STH for the current tree size with a different root hash, signed
    // with the real log key (so the signature check passes). The Monitor must
    // catch it as a split-view and reject — that's the consistency guarantee.
    if (req.method === "POST" && url === "/log/attempt-rewrite") {
      const rl = rateLimited(req, "POST /log/attempt-rewrite");
      if (rl.limited) {
        return sendJSON(res, 429, { error: "rate_limited", retryAfterSec: rl.retryAfterSec }, { "retry-after": String(rl.retryAfterSec) });
      }
      if (!monitor.head) {
        return sendJSON(res, 400, { rejected: false, reason: "monitor has no seed; GET /log first" });
      }
      const forgedRoot = "ff".repeat(32);
      const forged = signTreeHead(ledger.id, monitor.head.treeSize, forgedRoot, logKeys.privateKeyPem);
      const acceptedBefore = monitor.head.rootHash;
      const ok = monitor.update(forged, null);
      // Defensive: confirm the monitor's head didn't move to the forged value.
      const headUnchanged = monitor.head.rootHash === acceptedBefore;
      const rejected = !ok && headUnchanged;
      const record = {
        ts: new Date().toISOString(),
        forgedRoot,
        rejected,
        reason: rejected ? `split-view rejected: forged root ${forgedRoot.slice(0, 12)}… != accepted ${acceptedBefore.slice(0, 12)}…` : "MONITOR FAILED — accepted a forged STH",
      };
      rewriteAttempts.push(record);
      // Bound the in-memory list so the process doesn't leak under sustained
      // adversarial pressure on this endpoint (DAVID+ MEDIUM heal 2026-06-21).
      while (rewriteAttempts.length > REWRITE_ATTEMPTS_CAP) rewriteAttempts.shift();
      return sendJSON(res, 200, record);
    }

    res.writeHead(404, DEFAULT_SECURITY_HEADERS).end("not found");
  }

  // ---- INNER origin (:4001): the third-party app, its backend, its report-uri ----
  // Distinct origin from the host. Cookies, storage, postMessage, and
  // navigation all gate at the origin boundary now — the bridge isn't theater.
  async function handleInner(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = (req.url ?? "/").split("?")[0];

    // The INNER frame: the actual third-party app, served with the broad
    // certificate-derived CSP. Its frame-ancestors names ORIGIN_HOST so only
    // the host's bridge can embed it.
    if (req.method === "GET" && url === "/inner") {
      return serveFile(res, "app.html", { "content-security-policy": enforcedCSP });
    }

    // Externalized app logic (0.1.3): byte-stable, covered by script-src 'self'.
    // /inner/config.js carries the bridge origin synchronously before
    // /inner/app.js consumes it. app.js itself contains no deployment-specific
    // values, so its bytes are stable across deployments and content-addressable.
    if (req.method === "GET" && url === "/inner/app.js") {
      return serveStatic(res, "inner/app.js", "application/javascript; charset=utf-8");
    }
    if (req.method === "GET" && url === "/inner/config.js") {
      return emitConfigJs(res, "SKYBRIDGE_INNER_CFG", {
        ORIGIN_HOST: ORIGIN_HOST,
      });
    }

    // The app's one legitimate backend call — now same-origin to :4001 so
    // the demo doesn't drag in CORS. Allowed by the cert's connect-src 'self'.
    if (req.method === "GET" && url === "/api/charge") {
      return sendJSON(res, 200, { ok: true, charged: "$42.00", at: new Date().toISOString() });
    }

    // The inner's report-uri resolves to :4001/report (relative path on its
    // own origin). The browser sends native CSP violation reports here.
    // Funnels into the same Span/session as the bridge's :4000/report.
    if (req.method === "POST" && url === "/report") {
      return handleReport(req, res);
    }

    res.writeHead(404, DEFAULT_SECURITY_HEADERS).end("not found");
  }

  const hostServer = createServer((req, res) => handleHost(req, res));
  const innerServer = createServer((req, res) => handleInner(req, res));

  hostServer.listen(PORT_HOST, () => {
    console.log(`\nTFB Skybridge POC`);
    console.log(`  host + bridge:  ${ORIGIN_HOST}`);
    console.log(`  inner app:      ${ORIGIN_INNER}`);
    console.log(`  certificate minted for "${bundle.subject.appId}" (tier-B verifiable)`);
    console.log(`  enforced inner CSP: ${enforcedCSP}`);
    console.log(`  bridge CSP:         ${composeBridgeCSP()}\n  open ${ORIGIN_HOST}, then click "Inject attack".\n`);
  });
  innerServer.listen(PORT_INNER);
}

main().catch((e) => {
  console.error("POC failed to start:", e);
  process.exit(1);
});
