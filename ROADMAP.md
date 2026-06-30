# Skybridge Roadmap

> Living document. Last updated 2026-06-30. The status of every item below is HONEST — shipped means tested + on npm; near-term means designed + spec'd but not built; later means accepted as direction but no work scheduled; non-goal means explicitly out of scope.

## Shipped (v0.1.4 on npm)

- **CLI admission gate** (`skybridge check <app-dir>`) for JS/TS apps using the `BoundaryEnv` capability-injection contract
- **Cables** — static analysis derives minimal CSP from source
- **Battery** — instrumented sandbox runs the app against five adversarial payloads × N seeds; surfaces exact seed × payload × call site for any catch
- **Proofbay** — signed admission certificates with tier A/B/C verification
- **Span / chain** — append-only signed event chains with Merkle transparency log
- **Loop** — host-decision protocol with revocation
- **3 reference apps** (well-behaved / flaky / malicious) demonstrating each verdict path
- **CI-friendly exit codes** (0 ADMIT / 1 variance / 2 REJECT / 3 error)
- **`--json` output** for dashboards + pipeline gates
- **47/47 test suite green** including adversarial coverage (tampered roots, forged sigs, split-views, expired bundles)

## Near-term (designed, not built)

### AI orchestration audit chain
End-to-end signed receipts for AI-built code pipelines. The AI generation step signs the spec hash. The test step signs the results. The build step signs the artifact. Customer ends up with a verifiable chain of custody from spec → ship. Already proven in the substrate composition (cron evidence chains use the same span primitive); needs a developer-facing CLI surface.

### AI-to-AI handoff signing
Cross-session sender attribution for chip prompts, Slack posts, file handoffs, workflow inputs. Per-agent identity keys + signed handoff envelopes + trust registry rooted at the deployment's signing key. The receiving agent cryptographically verifies the sender before acting. First real cross-session signed handoff fired 2026-06-28; primitive is shipped in TFB substrate as `handoff_span.py`; needs the developer-facing port.

### Cables AST-backed analyzer
Today Cables uses pattern-based source analysis (works for `fetch`, `<script src>`, `new WebSocket`). Upgrading to a full AST walk (TypeScript Compiler API) catches more shapes — dynamic property access, computed import paths, deferred capability use. Spec'd in the README's "What this surface does NOT promise" section.

### Content-addressed artifact distribution
Tier C trustless verification requires the served HTML bytes be content-addressable. Today the inner-app `script-src` is `'self' + cert-derived external script hosts`; no `'unsafe-inline'` since v0.1.3. The next step: replace any irreducible inline with a Cables-emitted `'sha256-...'` source + witness path so the artifact stays content-addressable across re-renders.

## Medium-term (accepted direction, build queue)

### Apple iOS native app screening — `skybridge check --ios <project-dir>`

Bring the Skybridge admission discipline to native iOS apps. Today the CLI admits JS/TS shapes; this extends the discriminator to Swift / Objective-C apps.

What this needs:
- **Swift parser in Cables** — analyze Swift source for declared vs actual network egress, storage access, sensor capabilities, background mode usage
- **Info.plist + entitlements analysis** — the iOS equivalent of CSP directives (`NSAppTransportSecurity`, `NSLocationWhenInUseUsageDescription`, `com.apple.security.app-sandbox`, etc.)
- **NSPrivacyAccessedAPI category mapping** — Apple's required reasons API; Skybridge surfaces undeclared usage pre-Apple-review
- **iOS Simulator-based Battery** — runtime sandbox using `simctl` + adversarial payloads; identifies which Swift call site crosses an undeclared boundary
- **xcodebuild integration hook** — admission cert as a build phase, not a sidecar; verdict gates the archive step

Why this matters: Apple's review catches some violations but is slow (days to weeks) and opaque ("policy violation 4.5.1"). Skybridge gives the developer the same verdict locally in seconds with the exact seed × payload × call site. Apple's review still happens — Skybridge runs UPSTREAM, not in place of it.

Honest engineering bound: iOS sandboxing isn't Node-shaped. The Battery's iOS port needs real platform work, not a Cables-style file-walk. This is a multi-month build, not a weekend.

### Apple macOS native app screening — `skybridge check --macos <project-dir>`

Same shape as iOS but a richer capability surface:
- App Sandbox + Hardened Runtime entitlements analysis
- Endpoint Security Framework runtime hooks (where licensed)
- Notarization-compatibility check — surface violations Apple's notary service would catch, locally
- Compatibility with developer-id signing flows

Why this matters: macOS apps ship through more channels than iOS (App Store, direct distribution, MDM, enterprise). Skybridge admission cert travels with the artifact across channels. Especially valuable for enterprise IT admitting third-party Mac apps before deploying via MDM.

### Cross-platform binary verification
Once iOS + macOS native ship, generalize: a single admission cert format that works across browsers + Node + iOS + macOS + (eventually) Android + Windows. The pattern that's already shipped for JS/TS becomes the universal admission shape.

## Later (accepted direction, no work scheduled)

- Android native (Kotlin/Java) — same shape as iOS but Android platform; deferred until iOS proves the model
- Windows native (.NET / Win32) — deferred for same reason
- Smart contract / Solidity admission — different threat model; needs separate design
- Compiled binary (Go, Rust, C++) source analysis — needs language-specific Cables ports
- Multi-tenant SaaS admission orchestration — Skybridge per-app today; multi-tenant gateway is a separate primitive

## Non-goals (explicit)

- Replacing Apple's review. Skybridge runs UPSTREAM of App Store Connect; Apple still reviews; we don't push, sign for, or modify Apple's process.
- Replacing OS-level sandboxes. The Battery is robust against the BoundaryEnv contract but is not a kernel-level isolate. Don't run truly hostile code locally.
- Replacing code review. The Battery catches what an app DOES, not what it MEANS. Logic bugs that don't cross the boundary won't be caught.
- Becoming an app store. Skybridge is the discriminator at the admission boundary; the store layer (distribution, billing, takedown) is somebody else's primitive.
- Issuing signing identities for Apple's developer program. That's Apple's; Skybridge's signing is for the admission cert, separate from Apple's code signing.

## How items move from "later" to "near-term"

- Customer demand surfacing the gap repeatedly (3+ independent asks)
- A specific deployment that needs the capability
- A maintainer with bandwidth to scope the work

File an issue at https://github.com/CREATEDCHARACTR/tfb-skybridge/issues if you have a use case that should pull an item forward.

