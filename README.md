# tfb-skybridge

**Proof-carrying admission for third-party agent apps.** The developer CLI: run the Skybridge discriminator on your own code; verdict in milliseconds with the exact seed × payload × call site that caused any catch.

```bash
npx tfb-skybridge check ./my-app
# or globally:
npm install -g tfb-skybridge
skybridge check ./my-app
```

[Live demo · projecttfb.com/skybridge/](https://www.projecttfb.com/skybridge/)

---

## What it does

You point it at your app directory. It runs three subsystems against your code:

1. **Cables** — static analysis derives the minimal CSP from your source.
2. **Battery** — your app runs under an instrumented sandbox against five adversarial payloads × N seeds. Anything that crosses the boundary into an undeclared target is a violation.
3. **Verdict** — `ADMIT`, `ADMIT_WITH_VARIANCE_WARNING`, or `REJECT_PRESHIP`. CI-friendly exit codes.

The output names exactly which payload, which seed, which call site, and which undeclared host caused any catch. **Two weeks of "policy violation 4.5.1" becomes 0.6 ms of "your app POSTs to evil.example.com at app.ts:17."**

---

## Quick start

```bash
mkdir my-app && cd my-app

cat > index.mjs <<'EOF'
/** @param {import("tfb-skybridge/src/battery/types").BoundaryEnv} env */
export default async function myApp(env) {
  await env.fetch("https://api.stripe.com/v1/charges", { method: "POST" });
}
EOF

cat > skybridge.json <<'EOF'
{
  "hosts": ["api.stripe.com"],
  "directives": ["connect-src"],
  "capabilities": []
}
EOF

npx tfb-skybridge check .
# → ✓ ADMIT · Tier B
```

---

## What your app needs to provide

| file | required | purpose |
|---|---|---|
| `index.mjs` (or `.js`, `.ts`) | yes | default-exports an `AppEntry` function: `(env, input) => void \| Promise<void>`. The CLI tries `.mjs` first (works everywhere), then `.js`, then `.ts` (only loads outside `node_modules/` on Node 23.6+ where Node strips TS types natively). |
| `skybridge.json` | recommended | declares your manifest (`hosts`, `directives`, `capabilities`). Without it, Cables tries to derive from source — that works for browser-native patterns (`fetch`, `<script src>`, `new WebSocket`) but misses the `env.*` BoundaryEnv shape |

The `BoundaryEnv` your app uses is capability-injected — your app gets `env.fetch`, `env.loadScript`, `env.connect`, `env.beacon`, `env.storage`, `env.hostMessage`, `env.random` instead of ambient `fetch`/`localStorage`/etc. The sandbox sees and gates every boundary crossing.

---

## Verdict tiers + exit codes

| exit | verdict | what it means |
|---:|---|---|
| `0` | ✓ ADMIT · Tier B | deterministic, in-policy across every trial |
| `1` | ⚠ ADMIT · variance warning | in-policy but non-deterministic (passes Tier A/B, would fail Tier C sampled replay) |
| `2` | ⛔ REJECT pre-ship | any boundary violation; surfaces host + payload + seed + sequence + call-site context |
| `3` | (CLI error) | missing entry file, bad manifest, dynamic import failure |

CI integration:
```bash
npx tfb-skybridge check . && ./deploy.sh
```

---

## Three reference apps (in `examples/`)

```bash
npx tfb-skybridge check ./examples/well-behaved-app    # → exit 0
npx tfb-skybridge check ./examples/flaky-app           # → exit 1
npx tfb-skybridge check ./examples/malicious-app       # → exit 2
```

Each exercises a different verdict path. Read them as the canonical contract examples.

---

## `--json` for CI / dashboards

```bash
npx tfb-skybridge check --json ./my-app
```

Returns structured output: `verdict`, `timeToVerdictMs`, `manifest`, `cables.grants`, `battery.violations[]`, `manifestSource`. Wire into your existing pre-merge or pre-deploy gate.

---

## What this CLI is, what it isn't

**Is:** the dev-side surface of [TFB Skybridge](https://www.projecttfb.com/skybridge/) — the same engine that powers the live demo at `skybridge.projecttfb.com`. The discriminator's verdict on your local machine is the same verdict an app store running Skybridge would give your submission.

**Isn't:**
- A complete app-store admission pipeline. The CLI runs Cables + Battery; the full pipeline also issues a signed certificate, appends to a transparency log, and renders the app under the certificate's CSP at runtime. See the live demo for the end-to-end.
- Production-grade for adversarial code that escapes the sandbox. The Battery's sandbox is robust against the BoundaryEnv contract but not a kernel-level isolate. Don't run truly hostile code locally — the live hosted demo runs in its own process for a reason.
- A replacement for code review. The Battery catches what your app *does*, not what it *means*. Logic bugs that don't cross the boundary won't be caught.

For the full bounded-claim set and what's intentionally deferred (AST-backed Cables, content-addressed artifact distribution, build-time root store), see [projecttfb.com/skybridge/](https://www.projecttfb.com/skybridge/) "What this surface does NOT promise." Note that `'unsafe-inline'` is gone as of 0.1.3 — the inner-app `script-src` is `'self' + cert-derived external script hosts`. Externalize-first, no nonces: nonces would make the served HTML different bytes every render, foreclosing the content-addressed distribution that browser Tier B trustlessness depends on. Any future irreducible inline gets a Cables-emitted `'sha256-...'` source + witness; the path is documented and the artifact stays content-addressable.

---

## License

MIT. See `LICENSE`.

## Author

Saul Lowery · saul@projecttfb.com · [projecttfb.com/skybridge/](https://www.projecttfb.com/skybridge/)
