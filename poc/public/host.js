// TFB Skybridge — host page logic (externalized from host.html in 0.1.3).
//
// This file is byte-stable: no template substitution, no per-render value
// injection. The trust roots come from /config.js (window.TFB_TRUST_ROOTS).
// Bridge origin is derived from window.location.origin (the bridge shares
// :4000 with the host).
//
// Why externalized: round-3 closed the 'unsafe-inline' caveat by moving every
// script block to a same-origin file covered by script-src 'self'. Per Dev's
// round-2 ruling Q1: nonces would break content-addressability; externalize +
// 'self' preserves the cert-equals-byte-stream invariant for any future
// content-addressed artifact distribution layer.

  const $ = (id) => document.getElementById(id);

  async function loadAdmission() {
    const r = await fetch("/admit");
    const d = await r.json();
    $("policy").textContent = d.enforcedCSP.split("; ").join(";\n");
    $("policy").classList.remove("muted");
    const witness = d.witness
      ? `<div class="kv mono">witness: ${d.witness.file} bytes [${d.witness.span[0]}, ${d.witness.span[1]})</div>`
      : "";
    $("admit-body").innerHTML =
      `<div class="kv"><span class="pill ${d.decision === "ADMIT" ? "ok" : "stop"}">${d.decision}${d.tier ? " · TIER " + d.tier : ""}</span></div>` +
      `<div class="kv"><b>app</b> ${d.appId} <span class="mono muted">#${d.artifactHash}</span></div>` +
      `<div class="kv"><b>grants</b> ${d.grants.length} directives, each witnessed</div>` +
      witness +
      `<div class="kv muted">the store re-hashed the witness span; it did not re-analyze the app.</div>`;
    if (d.decision === "ADMIT") { $("s1").classList.add("done"); $("s2").classList.add("done"); }
  }

  function stop(detail) {
    $("overlay").classList.add("show");
    $("overlay-detail").textContent = detail;
    $("status-pill").className = "pill stop";
    $("status-pill").textContent = "STOPPED";
    $("s3").classList.add("done");
    $("s4").classList.add("done");
  }

  // Instant feedback: the bridge relays inner-frame postMessages up to here.
  // Dev §4: validate event.origin. The bridge is same-origin to the host
  // (both on :4000), so event.origin must be the host's own origin. Anything
  // from a different origin (e.g. a hypothetical injected iframe) is ignored.
  // Also gate on e.source so an additional same-origin frame can't spoof
  // the bridge — mirrors the bridge's own e.source check (DAVID+ MEDIUM heal
  // 2026-06-21: the bridge had origin AND source; the host had origin only).
  const ORIGIN_BRIDGE = window.location.origin; // bridge shares :4000 with host
  const BRIDGE_FRAME = document.getElementById("app");
  window.addEventListener("message", (e) => {
    if (e.origin !== ORIGIN_BRIDGE) return; // hard origin gate
    if (BRIDGE_FRAME && e.source !== BRIDGE_FRAME.contentWindow) return; // source gate
    if (!e.data) return;
    if (e.data.type === "violation") {
      $("revocation").textContent = "blocked: " + e.data.blockedURI;
      // Confirm + enrich from the server-side decision (the authoritative path).
      pollDecision();
      // The revocation appends to the transparency log — refresh the panel.
      loadLog();
    } else if (e.data.type === "declared-allowed") {
      $("s5").classList.add("done");
    }
  });

  async function pollDecision() {
    const r = await fetch("/decision");
    const d = await r.json();
    if (d.decision === "STOP") {
      const rv = d.revocation;
      stop(rv ? `${rv.reason}: ${rv.detail} — logged at index ${rv.loggedAtIndex} (tree size ${rv.treeSize})` : "revoked");
      $("revocation").innerHTML = rv ? `<b>${rv.reason}</b> — logged at index ${rv.loggedAtIndex}` : "revoked";
    }
  }

  async function loadLog() {
    const r = await fetch("/log");
    const d = await r.json();
    const pill = d.monitorAccepted
      ? `<span class="pill ok">MONITOR OK</span>`
      : `<span class="pill stop">MONITOR REJECTED</span>`;
    const attempts = (d.rewriteAttempts || []).length;
    $("log-body").innerHTML =
      `<div class="kv">${pill}</div>` +
      `<div class="kv"><b>log</b> ${d.logId}</div>` +
      `<div class="kv"><b>tree size</b> ${d.treeSize}</div>` +
      `<div class="kv mono">root ${d.rootHash.slice(0, 16)}…</div>` +
      `<div class="kv muted">latest STH @ ${new Date(d.timestamp).toLocaleTimeString()}</div>` +
      (attempts > 0
        ? `<div class="kv muted">${attempts} rewrite attempt${attempts === 1 ? "" : "s"} on record (all rejected)</div>`
        : "");
  }

  async function attemptRewrite() {
    const r = await fetch("/log/attempt-rewrite", { method: "POST" });
    const d = await r.json();
    $("rewrite-result").innerHTML = d.rejected
      ? `<span style="color:#137a3e;font-weight:600;">✓ rejected</span> · ${d.reason}`
      : `<span style="color:#b3261e;font-weight:600;">MONITOR FAILED</span> · ${d.reason}`;
    loadLog(); // refresh the rewrite-attempts counter
  }

  async function loadDevView() {
    const r = await fetch("/developer-view");
    const d = await r.json();
    const fv = d.why.firstViolation;
    const hostList = (d.why.hostCounts || [])
      .map((h) => `<div class="kv mono">${h.host} · ${h.hits} hit${h.hits === 1 ? "" : "s"} · <span class="muted">undeclared</span></div>`)
      .join("");
    const fixList = d.howToFix.options.map((o) =>
      `<div class="dev-fix">
        <div class="opt">${o.option}</div>
        <div class="det">${o.detail}</div>
        <div class="tradeoff">tradeoff: ${o.tradeoff}</div>
      </div>`
    ).join("");
    $("dev-view-body").innerHTML =
      `<div class="kv"><b>submission:</b> ${d.submission.appName} v${d.submission.version}</div>` +
      `<div class="kv"><b>verdict:</b> <span style="color:#b3261e;font-weight:700;">${d.verdict.replace("_", " ")}</span> · time-to-verdict ${d.timeToVerdict}</div>` +
      `<div class="dev-headline" style="margin-top:8px;">${d.summary}</div>` +
      `<div class="dev-section">
        <h4>Why your app was caught</h4>
        <div class="dev-grid">
          <div class="k">first violation:</div><div class="v"><b>${d.why.headline}</b></div>
          ${fv ? `
          <div class="k">payload:</div><div class="v mono">${fv.payload}</div>
          <div class="k">seed:</div><div class="v mono">${fv.seed}</div>
          <div class="k">at sequence:</div><div class="v mono">index ${fv.atSeq}</div>
          <div class="k">target host:</div><div class="v mono">${fv.host}</div>
          ` : ""}
        </div>
        ${fv ? `<div class="dev-code">${fv.sampleCode}</div><div class="kv muted" style="margin-top:4px;">${fv.sampleSource}</div>` : ""}
      </div>` +
      (hostList ? `<div class="dev-section"><h4>All undeclared hosts the battery saw</h4>${hostList}</div>` : "") +
      `<div class="dev-section">
        <h4>How to make this pass</h4>
        ${fixList}
      </div>` +
      `<div class="dev-compare">
        <div><span class="old">app store today:</span> ${d.compareToOldFlow.oldFlowDescription}</div>
        <div style="margin-top:4px;"><span class="new">Skybridge:</span> ${d.compareToOldFlow.skybridgeFlowDescription}</div>
        <div class="delta">${d.compareToOldFlow.delta}</div>
      </div>`;
  }

  async function loadStrip() {
    const r = await fetch("/strip");
    const d = await r.json();
    const rowFor = (v) => {
      const cls = v.verdict === "REJECT_PRESHIP" ? "reject"
        : v.verdict === "ADMIT_WITH_VARIANCE_WARNING" ? "warn"
        : "admit";
      const label = v.verdict === "REJECT_PRESHIP" ? "⛔ REJECT pre-ship"
        : v.verdict === "ADMIT_WITH_VARIANCE_WARNING" ? "⚠ ADMIT · variance warning"
        : `✓ ADMIT · Tier ${v.tier}`;
      const liveTag = v.id === d.currentlyRendering
        ? ` <span class="muted" style="font-weight:400;font-size:11px;">(currently rendering in the iframe →)</span>`
        : "";
      return `<div class="strip-row ${cls}">
        <span class="badge">${label}</span>
        <div class="name">${v.name}${liveTag}</div>
        <div class="why">${v.reason}</div>
      </div>`;
    };
    $("strip-body").innerHTML =
      `<div class="strip">${d.verdicts.map(rowFor).join("")}</div>` +
      `<div class="strip-footer">the buyer's question — "I have thousands of apps; which do I admit?" — answered by the same engine, three times.</div>`;
  }

  async function loadBattery() {
    const r = await fetch("/battery");
    const b = await r.json();
    const pill = b.result === "PASS"
      ? `<span class="pill ok">PASS</span>`
      : `<span class="pill stop">${b.result} · ${b.violationCount} violation${b.violationCount === 1 ? "" : "s"}</span>`;
    const vlist = b.violations.map((v) =>
      `<div class="kv mono">⛔ ${v.detail} <span class="muted">@seq ${v.atSeq}</span></div>`
    ).join("");
    $("battery-body").innerHTML =
      `<div class="kv">${pill}</div>` +
      `<div class="kv"><b>tested app</b> ${b.appName}</div>` +
      `<div class="kv"><b>battery</b> v${b.batteryVersion} · ${b.runs} runs (seeds ${b.seeds.join(", ")})</div>` +
      vlist +
      `<div class="kv muted" style="margin-top:6px;">${b.result === "FAIL" ? "this app would never have been admitted — caught before shipping." : "no adversarial finding."}</div>`;
  }

  // ============================================================
  // Client-side admission verification (§6.5) — SubtleCrypto port
  // ============================================================
  // The shape of the verifier mirrors src/proofbay/verify.ts (Tier A path),
  // ported to the browser. Trust here is: the SPKI PEMs the server told us
  // it trusts + the math. The server never sees our verdict.

  // ---- canonical JSON (RFC 8785-style; matches src/canonical.ts) ----
  function canonicalize(v) {
    if (v === null) return "null";
    const t = typeof v;
    if (t === "number") {
      if (!Number.isFinite(v)) throw new Error("non-finite number");
      return JSON.stringify(v);
    }
    if (t === "boolean" || t === "string") return JSON.stringify(v);
    if (Array.isArray(v)) return "[" + v.map(canonicalize).join(",") + "]";
    if (t === "object") {
      const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
      return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(v[k])).join(",") + "}";
    }
    throw new Error("unsupported type: " + t);
  }
  const enc = new TextEncoder();
  function canonicalBytes(v) { return enc.encode(canonicalize(v)); }

  // ---- hex helpers ----
  function bytesToHex(u8) {
    let s = "";
    for (const b of u8) s += b.toString(16).padStart(2, "0");
    return s;
  }
  function hexToBytes(s) {
    const u8 = new Uint8Array(s.length / 2);
    for (let i = 0; i < u8.length; i++) u8[i] = parseInt(s.substr(i * 2, 2), 16);
    return u8;
  }

  // ---- sha256 ----
  async function sha256Hex(bytes) {
    const h = await crypto.subtle.digest("SHA-256", bytes);
    return bytesToHex(new Uint8Array(h));
  }
  async function leafHashHex(bytes) {
    const buf = new Uint8Array(1 + bytes.length);
    buf[0] = 0x00;
    buf.set(bytes, 1);
    return sha256Hex(buf);
  }
  async function nodeHashHex(leftHex, rightHex) {
    const l = hexToBytes(leftHex), r = hexToBytes(rightHex);
    const buf = new Uint8Array(1 + l.length + r.length);
    buf[0] = 0x01;
    buf.set(l, 1);
    buf.set(r, 1 + l.length);
    return sha256Hex(buf);
  }

  // ---- Ed25519 SPKI PEM → CryptoKey ----
  function pemToSpki(pem) {
    const body = pem
      .replace(/-----BEGIN PUBLIC KEY-----/g, "")
      .replace(/-----END PUBLIC KEY-----/g, "")
      .replace(/\s+/g, "");
    const der = atob(body);
    const out = new Uint8Array(der.length);
    for (let i = 0; i < der.length; i++) out[i] = der.charCodeAt(i);
    return out;
  }
  async function importEd25519PublicKey(pem) {
    return crypto.subtle.importKey("spki", pemToSpki(pem), { name: "Ed25519" }, false, ["verify"]);
  }
  async function verifySig(pubKey, sigB64, data) {
    const sigBin = atob(sigB64);
    const sig = new Uint8Array(sigBin.length);
    for (let i = 0; i < sigBin.length; i++) sig[i] = sigBin.charCodeAt(i);
    return crypto.subtle.verify({ name: "Ed25519" }, pubKey, sig, data);
  }

  // ---- merkle: rebuild root from leaf + audit path (RFC 6962 inclusion) ----
  function pow2lt(c) { let k = 1; while (k * 2 < c) k *= 2; return k; }
  async function rebuildRoot(leafHex, m, n, proofHex) {
    let p = 0;
    async function rec(idx, lo, hi) {
      const count = hi - lo;
      if (count === 1) return leafHex;
      const k = pow2lt(count);
      if (idx - lo < k) {
        const left = await rec(idx, lo, lo + k);
        const right = proofHex[p++];
        if (right === undefined) throw new Error("malformed inclusion proof");
        return nodeHashHex(left, right);
      }
      const right = await rec(idx, lo + k, hi);
      const left = proofHex[p++];
      if (left === undefined) throw new Error("malformed inclusion proof");
      return nodeHashHex(left, right);
    }
    const root = await rec(m, 0, n);
    if (p !== proofHex.length) throw new Error("inclusion proof had extra nodes");
    return root;
  }

  // ---- the verifier (mirror of src/proofbay/verify.ts Tier A) ----
  function coreClone(b) {
    const c = JSON.parse(JSON.stringify(b));
    c.issuance.signature = "";
    c.issuance.transparencyReceipt = null;
    return c;
  }
  function leafClone(b) {
    const c = JSON.parse(JSON.stringify(b));
    c.issuance.transparencyReceipt = null;
    return c;
  }
  async function verifyAdmissionInBrowser(bundle, trust) {
    const checks = [];
    const issuerPem = bundle.issuance.proofBayIdentity.publicKeyPem;
    if (!trust.trustedIssuers.includes(issuerPem)) {
      return { ok: false, reason: "ISSUER_UNTRUSTED", checks };
    }
    checks.push({ name: "issuer in trust list", ok: true });

    const issuerKey = await importEd25519PublicKey(issuerPem);
    const issuerOk = await verifySig(issuerKey, bundle.issuance.signature, canonicalBytes(coreClone(bundle)));
    checks.push({ name: "issuer signature", ok: issuerOk });
    if (!issuerOk) return { ok: false, reason: "SIGNATURE_INVALID", checks };

    const receipt = bundle.issuance.transparencyReceipt;
    if (!receipt) return { ok: false, reason: "NOT_IN_TRANSPARENCY_LOG", checks };

    let logKeyOk = false;
    for (const pem of trust.trustedLogs) {
      try {
        const lk = await importEd25519PublicKey(pem);
        if (await verifySig(lk, receipt.rootSignature, hexToBytes(receipt.rootHash))) {
          logKeyOk = true;
          break;
        }
      } catch { /* try next */ }
    }
    checks.push({ name: "log STH signature", ok: logKeyOk });
    if (!logKeyOk) return { ok: false, reason: "LOG_UNTRUSTED", checks };

    const leafHex = await leafHashHex(canonicalBytes(leafClone(bundle)));
    let rebuilt;
    try {
      rebuilt = await rebuildRoot(leafHex, receipt.leafIndex, receipt.treeSize, receipt.auditPath);
    } catch (e) {
      checks.push({ name: "inclusion proof", ok: false });
      return { ok: false, reason: "NOT_IN_TRANSPARENCY_LOG", checks };
    }
    const inclOk = rebuilt === receipt.rootHash;
    checks.push({ name: "inclusion proof", ok: inclOk });
    if (!inclOk) return { ok: false, reason: "NOT_IN_TRANSPARENCY_LOG", checks };

    const now = Date.now();
    if (Date.parse(bundle.issuance.issuedAt) > now) return { ok: false, reason: "NOT_YET_VALID", checks };
    if (Date.parse(bundle.issuance.expiresAt) < now) return { ok: false, reason: "EXPIRED", checks };
    checks.push({ name: "freshness window", ok: true });

    return { ok: true, reason: "ADMIT (browser-verified, Tier A)", checks };
  }

  async function clientVerify() {
    $("client-body").innerHTML = `<span class="muted">running SubtleCrypto checks…</span>`;
    try {
      // Trust roots come from the PINNED config (loaded synchronously at page
      // top), NOT from /trust. The bundle still comes from the host being
      // verified — that's fine, the signatures protect it.
      const trust = window.TFB_TRUST_ROOTS;
      if (!trust || !Array.isArray(trust.trustedIssuers) || !trust.trustedIssuers.length) {
        throw new Error("pinned trust roots missing (config.js failed to load?)");
      }
      const bundleJson = await (await fetch("/bundle")).json();
      const v = await verifyAdmissionInBrowser(bundleJson, trust);
      const pill = v.ok
        ? `<span class="pill ok">${v.reason}</span>`
        : `<span class="pill stop">REJECT · ${v.reason}</span>`;
      const checkList = v.checks
        .map((c) => `<div class="kv mono">${c.ok ? "✓" : "✗"} ${c.name}</div>`)
        .join("");
      $("client-body").innerHTML =
        `<div class="kv">${pill}</div>` +
        checkList +
        `<div class="kv muted" style="margin-top:6px;">trust roots came from the pinned config (stand-in for a root store), not from the host. The server did not perform these checks — the browser did.</div>`;
    } catch (e) {
      $("client-body").innerHTML =
        `<div class="kv"><span class="pill stop">VERIFY ERROR</span></div>` +
        `<div class="kv mono">${e && e.message ? e.message : String(e)}</div>` +
        `<div class="kv muted" style="margin-top:6px;">SubtleCrypto Ed25519 requires Chrome 138+, Edge, or Safari 17+.</div>`;
    }
  }

  async function resetSession() {
    await fetch("/reset", { method: "POST" });
    // Restore the UI to RENDERING and clear the overlay/checkmarks.
    $("overlay").classList.remove("show");
    $("status-pill").className = "pill ok";
    $("status-pill").textContent = "RENDERING";
    $("revocation").innerHTML = "no revocation";
    $("s3").classList.remove("done");
    $("s4").classList.remove("done");
    $("s5").classList.remove("done");
    // Reload the iframe so the inner-app log clears and the violation handler resets.
    document.getElementById("app").src = document.getElementById("app").src;
    loadLog();
  }

  $("client-verify").addEventListener("click", clientVerify);
  $("log-refresh").addEventListener("click", loadLog);
  $("log-rewrite").addEventListener("click", attemptRewrite);
  $("reset-session").addEventListener("click", resetSession);

  loadAdmission();
  loadStrip();
  loadDevView();
  loadBattery();
  loadLog();
  setInterval(pollDecision, 1500); // backstop in case the postMessage is missed
