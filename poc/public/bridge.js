// TFB Skybridge — bridge frame logic (externalized from bridge.html in 0.1.3).
//
// The BRIDGE: the production isolation pattern, cross-origin (Dev §4).
//
// The host serves this outer frame at :4000 under a tight host-only CSP
// (default-src 'none'; script-src 'self'; frame-src http://localhost:4001;
// connect-src 'self'). The inner frame loads from :4001 under the BROAD
// certificate-derived CSP. Distinct ORIGINS — not just distinct frames —
// make the postMessage / cookie / storage boundary real. Properties bought:
//
//   - postMessage actually gates: this bridge accepts only event.origin ===
//     ORIGIN_INNER and posts to its parent with targetOrigin = ORIGIN_HOST.
//     No '*' anywhere. An attacker that injects a listener at the wrong
//     origin gets ignored.
//   - Compromising the inner app does NOT reach the bridge: distinct
//     origins, distinct CSPs, distinct documents, no shared script context.
//   - Browser CSP-report delivery: the inner's report-uri resolves to
//     :4001/report (its own origin) — the browser sends native reports
//     there directly. The bridge ALSO POSTs to /report on :4000 as the
//     redundant fast path. Both funnel into the same Span.
//
// Per Dev's round-2 Q1 ruling: the origins come from a config endpoint
// (window.SKYBRIDGE_BRIDGE_CFG, populated by /bridge-config.js loaded
// synchronously before this script). Externalizing makes this file
// byte-stable — no template substitution at serve time. The deployment-
// specific origins live in the config endpoint, not in the artifact.

  if (!window.SKYBRIDGE_BRIDGE_CFG ||
      typeof window.SKYBRIDGE_BRIDGE_CFG.ORIGIN_HOST !== "string" ||
      typeof window.SKYBRIDGE_BRIDGE_CFG.ORIGIN_INNER !== "string") {
    // Fail loud: the bridge has no business running without origin pins.
    // Silent fallback to '*' or empty string would re-introduce the very
    // postMessage-confusion class the cross-origin split exists to close.
    throw new Error("bridge-config.js failed to load — SKYBRIDGE_BRIDGE_CFG missing");
  }
  const ORIGIN_HOST = window.SKYBRIDGE_BRIDGE_CFG.ORIGIN_HOST;
  const ORIGIN_INNER = window.SKYBRIDGE_BRIDGE_CFG.ORIGIN_INNER;

  const inner = document.getElementById("inner");

  window.addEventListener("message", (e) => {
    // Hard origin check FIRST — this is the actual security property the
    // cross-origin split buys. Reject anything not from the inner's origin.
    if (e.origin !== ORIGIN_INNER) return;
    if (e.source !== inner.contentWindow) return; // belt + suspenders
    if (!e.data || typeof e.data !== "object") return;

    if (e.data.type === "violation") {
      // (a) durable: POST to /report on the bridge's own origin (:4000).
      // Same-origin fetch — no CORS, allowed by bridge CSP connect-src 'self'.
      // The browser ALSO sends a native CSP report to :4001/report via the
      // inner's report-uri. Both funnel to the same Span; redundancy is intentional.
      try {
        fetch("/report", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ blockedURI: e.data.blockedURI, violatedDirective: e.data.directive }),
        });
      } catch (_) {}
      // (b) instant: relay up to the host using the host's exact origin.
      parent.postMessage(e.data, ORIGIN_HOST);
    } else if (e.data.type === "declared-allowed") {
      // pure UX signal — relay as-is, exact targetOrigin.
      parent.postMessage(e.data, ORIGIN_HOST);
    }
  });
