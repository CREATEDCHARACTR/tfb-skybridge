# Example apps for the Skybridge CLI

Three apps that exercise the three CLI verdict paths. Run any of them with:

```bash
npm run check -- ./examples/well-behaved-app
npm run check -- ./examples/flaky-app
npm run check -- ./examples/malicious-app
```

| app | expected verdict | expected exit code | what it shows |
|---|---|---|---|
| `well-behaved-app/` | ✓ ADMIT · Tier B | 0 | deterministic, in-policy across every trial |
| `flaky-app/` | ⚠ ADMIT · variance warning | 1 | in-policy but non-deterministic; passes Tier A/B, would fail Tier C |
| `malicious-app/` | ⛔ REJECTED · pre-ship catch | 2 | injection-driven exfil to an undeclared host; Battery catches it |

Each app is a single `index.ts` that default-exports an `AppEntry` function. That's the contract a developer's app needs to satisfy for `skybridge check` to drive it.

If you want to see the full structured verdict as JSON (for CI), add `--json`:

```bash
npm run check -- --json ./examples/malicious-app
```
