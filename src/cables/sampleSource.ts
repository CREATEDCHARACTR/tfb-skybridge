// A realistic multi-file app the analyzer scans. Egress constructs span JS, HTML
// (including an inline script), and CSS, with two origins referenced twice and
// one relative fetch that must NOT produce a grant.
import type { Artifact } from "../proofbay/artifact";

const APP_JS = `// checkout widget
const stripe = Stripe('pk_live_demo');

async function charge(cart) {
  await fetch('https://api.stripe.com/v1/charges', { method: 'POST' });
  await fetch('/api/ping');                 // relative -> same origin, no grant
}

import('https://js.stripe.com/v3/');
import confetti from 'https://esm.sh/canvas-confetti';

const ws = new WebSocket('wss://realtime.acme.io/ws');
navigator.sendBeacon('https://metrics.acme.io/collect', '{}');

localStorage.setItem('cart', JSON.stringify({}));
`;

const INDEX_HTML = `<!doctype html>
<html>
  <head>
    <script src="https://js.stripe.com/v3/"></script>
  </head>
  <body>
    <img src="https://cdn.acme.io/logo.png" alt="logo" />
    <script>
      fetch('https://api.stripe.com/v1/config');
    </script>
  </body>
</html>
`;

const STYLES_CSS = `@import 'https://fonts.acme.io/inter.css';

body {
  background: url('https://cdn.acme.io/bg.png') no-repeat;
  font-family: Inter, system-ui;
}
`;

export function sampleSource(): Artifact {
  return new Map<string, Buffer>([
    ["app.js", Buffer.from(APP_JS, "utf8")],
    ["index.html", Buffer.from(INDEX_HTML, "utf8")],
    ["styles.css", Buffer.from(STYLES_CSS, "utf8")],
  ]);
}

// The grants the analyzer is expected to derive (used by the harness).
export const EXPECTED_GRANTS = [
  "connect-src https://api.stripe.com",
  "connect-src https://metrics.acme.io",
  "connect-src wss://realtime.acme.io",
  "img-src https://cdn.acme.io",
  "script-src https://esm.sh",
  "script-src https://js.stripe.com",
  "style-src https://cdn.acme.io",
  "style-src https://fonts.acme.io",
];
