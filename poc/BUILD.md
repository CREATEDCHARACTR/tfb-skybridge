# TFB Skybridge — Proof-of-Concept: BUILD INSTRUCTIONS

**Audience:** an AI coding agent (e.g. Claude Code) building/running/extending this on a Mac.
**Status of the provided files:** the server path is implemented and verified end-to-end with curl. The only thing that requires a real browser is CSP *enforcement* firing the violation event. Your job is to run it, verify the browser beats, and (optionally) extend it.

---

## 0. The one thing this POC must prove

A skeptic can already accept that our engine's logic works (it has ~99 passing gates in `src/`). The POC exists to prove the one claim they can't grant from a Node test: **the policy we certified is the policy the browser actually enforces — and when the app misbehaves, admission is revoked live.**

Demonstrated as four beats on one screen:

1. **Cheap admission** — the host verifies the certificate (re-hash one witness byte-span, no re-analysis) → "ADMIT · Tier B".
2. **Certified = enforced** — the app renders in a nested iframe under exactly the certificate's CSP, served as a real `Content-Security-Policy` header. Its one legitimate call works.
3. **Runtime block** — the app assembles an exfil URL *at runtime* and fetches an undeclared host; the **browser** blocks it on `connect-src`.
4. **Live revocation** — the violation reaches the Span, which signs a revocation and appends it to the transparency log; the host overlays **STOPPED**.

**Acceptance = all four visibly happen in Chrome.**

---

## 1. Architecture (and why)

```
Browser
  host.html  (the "platform")  ──embeds──▶  iframe src="/app"
     │  GET /admit  → shows admission + policy        │  served WITH the
     │  on message/poll → flips to STOP               │  Content-Security-Policy header
     ▼                                                ▼
  ───────────────────────  Node server (poc/server.ts)  ───────────────────────
   reuses the REAL engine in ../src:  Cables · Proof Bay · Span · Ledger
   GET /admit     verifyAdmission(...) → decision + enforced CSP + witness
   GET /app       serves app.html WITH the certificate-derived CSP header
   GET /api/charge the app's one legitimate backend call (allowed via 'self')
   POST /report   browser CSP violation → openSpan → finalize → postRevocation → log
   GET /decision  RENDER | STOP (+ the logged revocation)
```

Key decisions, each deliberate — **do not "simplify" these away:**

- **Crypto stays server-side.** The Node server does all signing/verification using the existing engine. The browser never touches crypto, so there is no Web Crypto port for the POC. (A later iteration can move verification to the client with SubtleCrypto.)
- **The CSP is a real response header on `/app`,** composed from the certificate's grants plus the host's own control directives (`default-src 'none'`, `connect-src 'self'` for the report channel, `report-uri /report`, `frame-ancestors 'self'`). The host may add restrictions; it can never grant the app more than the certificate did. This composition is the point — keep it.
- **Single nested iframe + CSP header** is enough to prove "certified = enforced". The production double-iframe (isolating the host bridge from the app) is an extension, not needed for this proof.
- **The attack URL is assembled at runtime** (string concatenation) so no literal evil URL exists in source — the class of attack a static scan misses but the enforced CSP blocks anyway. Keep it runtime-derived.
- **Two report paths, on purpose:** the frame's host-controlled shim `postMessage`s the parent for *instant* UI, and also `POST`s `/report` for the *durable* server-side revocation. `report-uri /report` is set as a browser-native backstop. Redundancy is intentional — browser report delivery can be batched/delayed.

---

## 2. Files (provided)

```
tfb-skybridge-suite/
  src/ ...                      the verified engine (unchanged)
  poc/
    server.ts                   the host platform server (node:http, zero-dep)
    public/
      host.html                 the platform UI (admission panel + frame + STOP overlay)
      app.html                  the third-party app (legit call + runtime attack + Span shim)
  package.json                  has script:  "poc": "tsx poc/server.ts"
```

If you are rebuilding from scratch rather than using the provided files, reproduce exactly the endpoints and behaviors in §1, importing from `../src` (see the import block at the top of `poc/server.ts`).

---

## 3. Run it

```bash
# from the suite root
npm install
npm run poc
# server prints the minted certificate + the enforced CSP, then listens on :4000
```

Open **http://localhost:4000** in Chrome.

Expected:
- Left rail shows **ADMIT · TIER B**, the app id + artifact hash, "8 directives, each witnessed", and the witness span (`app.js bytes [104,137)`).
- The enforced CSP is printed (browser-enforced).
- The app frame renders; click **Pay $42.00** → "✓ charge ok".
- Click **Inject attack (exfiltrate)** → the frame logs "⛔ blocked by CSP: https://evil.example.com/… (connect-src)", and the host overlays **STOPPED — admission revoked**, showing `VIOLATION: undeclared host evil.example.com — logged at index N`.

---

## 4. Acceptance tests

### 4a. Server path (automated — already verified, re-run to confirm)

```bash
npm run poc &  sleep 4
curl -s localhost:4000/admit | grep -q '"decision":"ADMIT"' && echo "PASS admit"
curl -s -D - -o /dev/null localhost:4000/app | grep -qi 'content-security-policy' && echo "PASS csp-header"
curl -s localhost:4000/decision | grep -q '"decision":"RENDER"' && echo "PASS render-before"
curl -s -X POST localhost:4000/report -H 'content-type: application/json' \
  -d '{"blockedURI":"https://evil.example.com/steal","violatedDirective":"connect-src"}' >/dev/null
curl -s localhost:4000/decision | grep -q '"decision":"STOP"' && echo "PASS stop-after"
pkill -f poc/server.ts
```
All five must print PASS.

### 4b. Browser beats (manual — the actual proof)

1. Admission panel shows ADMIT · Tier B on load. ✔
2. "Pay" succeeds (allowed `/api/charge`). ✔
3. "Inject attack" produces a **CSP violation in the DevTools console** and the frame's log line. ✔ (This confirms the *browser* blocked it, not us.)
4. The host flips to the STOP overlay with the logged revocation. ✔

If beat 3 does not fire a violation: confirm `/app` is being served with the `Content-Security-Policy` header (DevTools ▸ Network ▸ /app ▸ Headers), and that `evil.example.com` is absent from `connect-src`. If beat 4 lags: the `postMessage` may have been missed — the 1.5s `/decision` poll is the backstop and should flip it within ~2s.

---

## 5. Known caveats (expected, not bugs)

- **`'unsafe-inline'` is gone as of 0.1.3** (Dev round-2 Q1 ruling). The inner-app `script-src` is now `'self' + cert-derived external script hosts`; the page logic lives in same-origin .js files. Externalize-first, NOT nonces: nonces would make the served HTML different bytes every render, breaking content-addressability and foreclosing browser Tier B trustlessness (§6.5.1 gate-(a)). For any future irreducible inline, Cables emits a `'sha256-...'` source + witness (see §6.5.2 below).
- **`report-uri` is deprecated** in favor of `report-to` + a `Reporting-Endpoints` header, but `report-uri` is reliable in Chrome and simplest here. The app shim's `POST /report` is the primary durable path regardless.
- **The legitimate call targets `'self'`** (`/api/charge`) for an offline-clean demo; the certificate still *names* the real external origins (api.stripe.com, etc.) in the displayed policy. To make the legit call hit a declared external host, see §6.
- **`sandbox`** is intentionally not set on the iframe so the shim can `postMessage` + `fetch('/report')` freely; the security being demonstrated is the **CSP**, not the sandbox attribute. Production layers both.

---

## 6. Extension hooks (next iterations — do these only after the four beats pass)

In rough priority:

1. **Declared external allowed-host:** add a second app action that fetches a real external origin that *is* in the certificate (e.g. a public test API you add to the app source so Cables witnesses it), proving allowed-external succeeds while undeclared-external is blocked.
2. **Pre-ship catch (the battery as a second panel):** add `GET /battery` that runs `runBattery` against a *malicious* app entry and returns the FAIL transcript, so the UI can show "this exfil is also caught before the app ever ships," next to the runtime catch.
3. **Auditability panel:** add `GET /log` exposing the Ledger's signed tree head + a `Monitor` check, and a button that attempts a rewrite and shows it rejected — surfacing the consistency-proof guarantee in the UI.
4. **Double-iframe:** nest the app one frame deeper, with the host bridge in the outer frame and the app in the inner, to mirror the production isolation model.
5. **Client-side verification:** port `verifyAdmission`'s signature checks to SubtleCrypto so the *browser* verifies the certificate, removing the server from the trust path for admission.

### 6.5.1 Deferral — browser Tier B verification (post-§6.5)

**Status:** deferred. Do not implement until both gates below exist.

§6.5 ships **Tier A** in the browser (identity + signature + transparency + freshness). **Tier B** would also re-hash the witness spans against the served artifact bytes — and re-hashing bytes the same server just handed you is not trustless. Browser Tier B is only meaningful when both of these are true:

- **Gate (a) — content-addressed artifact distribution.** The bundle's `subject.artifactRef` resolves over a distribution layer the issuer does not control (IPFS `cid://` or equivalent), so the hash *is* the address and the source cannot substitute different bytes for the verifier than for the user. Without this, a `GET /artifact` on the host serves bytes the host could lie about.
- **Gate (b) — client-pinned trust roots.** The browser's trust roots must come from a configured root store bundled into the application binary, not from a `GET /trust` endpoint on the host being verified. §6.5's `config.js` is the POC stand-in; production replaces it with the real root store. (See README "what isn't being claimed.")

When (a) and (b) both exist, browser Tier B is ~30 more lines: fetch the artifact by CID, hash it, re-hash each witness span via `sliceHash`, and run the minimality / completeness / observed-egress / fingerprint-variance checks the server-side Tier B already performs in `src/proofbay/verify.ts`.

Until then: keep `/admit` (server-side) as the Tier B story and `/bundle` + pinned `config.js` (client-side) as the Tier A story. Don't ship a `GET /artifact` from the host and call browser Tier B "trustless" — that's gate-(a) theater.

### 6.5.2 Deferred capability — Cables hash-witness for irreducible inline

**Status:** capability documented, not implemented. The current POC has no irreducible inline (every inline `<script>` was externalized in 0.1.3 to a same-origin `.js` file covered by `script-src 'self'`). If a future surface needs inline JavaScript that genuinely cannot be externalized, the path is:

1. Cables emits a Grant with source `'sha256-<base64-of-digest>'` and a Witness whose `srcRef.span` points at the inline script's byte range inside the served HTML artifact.
2. The Proof Bay issuer signs the bundle as usual; the certificate's `script-src` carries the `'sha256-...'` source alongside `'self'`.
3. The store / verifier re-hashes the byte span (same machinery as every other witnessed Grant) and rejects on mismatch.

A hash IS a property of the artifact — identical bytes anywhere in the world produce the same hash. A nonce is NOT (it's stamped per-render by the host). Choosing hashes preserves content-addressability and the cert-equals-byte-stream invariant; choosing nonces would foreclose §6.5.1 gate-(a). Per Dev round-2 Q1, externalize first; reach for hashes only when externalization is impossible. Do not reach for nonces at all.

Each extension is additive and must not regress the four core beats or the §4a server tests.

---

## 7. Definition of done (for this POC)

- `npm run poc` boots, mints a real certificate, and serves.
- §4a prints five PASS lines.
- In Chrome: admission shows Tier B; the legit call works; **the attack fires a real CSP violation**; the host flips to STOP with a logged revocation.

That is the smallest end-to-end proof that the certified policy is the enforced policy and that admission is revocable live. Everything else is an extension.
