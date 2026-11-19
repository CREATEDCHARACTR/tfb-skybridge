# TFB Drawbridge runtime demo

This is a local, `OBSERVE_ONLY` Drawbridge demonstration. The browser, HTTP API,
and CLI all traverse one `DrawbridgeRuntimeController`. The controller composes
the existing TypeScript inference producer and shadow observer; this layer does
not reimplement their scoring semantics.

The temporary model is a real ChatGPT/Codex agent acting through a bounded file
exchange. Drawbridge makes no model-provider request and does not call a local
model. The synthetic region scenarios demonstrate accountable plumbing only;
they do not establish production behavior or authorize enforcement.

## Build and start from source

```sh
npm run build && npm run drawbridge:serve -- --token-file /absolute/path/to/owner-only-agent-token
```

Open `http://127.0.0.1:4317`. The owner-held token file must be a single-link
regular file with mode `0600`; its value is never printed. That token gates the
only endpoints that can reveal a raw request or accept a raw response. A
`DRAWBRIDGE_AGENT_TOKEN` environment value is also accepted for supervised
runtimes, but its value is likewise never emitted.

After installing the packed module as a dependency, the native compiled entry
is also available as `tfb-drawbridge serve`; it does not require the source-only
`tsx` development dependency.

## ChatGPT-agent response workflow

1. Submit a prompt in the browser and copy the displayed request id.
2. Read the content-addressed request locally:

   ```sh
   npm run drawbridge:agent -- agent-request REQUEST_ID --token-file /absolute/path/to/agent-token
   ```

3. Have the ChatGPT/Codex agent answer that exact request and save only its
   answer in a mode-restricted UTF-8 file.
4. Supply the response bytes and their computed digest:

   ```sh
   npm run drawbridge:agent -- agent-respond REQUEST_ID \
     --response-file /absolute/path/to/response.txt \
     --token-file /absolute/path/to/agent-token
   ```

The browser polls the shared controller and then shows the response, assessment
and reason, `OBSERVE_ONLY` authority, receipt reference, and synthetic-evidence
disclosure. Conflicting response retries, unknown providers, digest mismatch,
expired requests, expired or replayed region evidence, and substituted session
or sequence bindings hold closed.

Browser session status and mutations require a generation-bound capability held
in memory only. `sessionStorage` retains a separately scoped resume token, not
the mutation capability; reload exchanges that token for the current in-memory
capability and rotates the prior capability out of service. Explicit erasure
rotates the session generation, so old capability and resume bytes cannot
authorize a recreated session.

## Custody and retention

- Raw prompt/response files are `0600` beneath a `0700` exchange root, reject
  symlink custody paths, and are erased after completion. While the runtime is
  active, a timer enforces their TTL; after downtime, construction and health
  sweep overdue exchange files before serving work. This is not a wall-clock
  erasure guarantee while every supervising process is stopped, so production
  privacy remains held until independent supervision is deployed and witnessed.
- `npm run drawbridge:janitor -- --state-dir /absolute/state/root` is the
  independent one-shot retention owner intended for a separate supervisor. Its
  presence does not prove deployment: the release gate still requires evidence
  that the HTTP runtime and janitor have distinct live supervision.
- Durable v2 session JSON contains domain-separated keyed prompt/response
  commitments, a keyed output fingerprint, opaque observations, the assessment,
  provider identity, evidence hash, and an optional fixed-domain SHA-256 content
  address of bounded attestor output. It contains neither raw prompt/response
  text nor public dictionary-linkable prompt/response hashes. An attestor
  receives one canonical 32-byte request-binding digest, never the raw prompt or
  response.
- Runtime metrics scope zero network calls to the model-provider transport. An
  operator-supplied attestation callback can use an external transport, which
  this runtime does not measure and therefore does not claim as zero.
- Receipts have both count and time ceilings. To erase one session explicitly:

  ```sh
  npm run drawbridge:agent -- erase SESSION_REF --session-token-file /absolute/path/to/session-capability
  ```

- Demo state defaults to `.state/drawbridge-demo`. A stable mode-restricted
  producer key preserves opaque identity and monotonic sequence across restart.
- The state root and both custody leaves must remain owner-held `0700`
  directories with their startup device/inode identities unchanged. Symlinked
  ancestors, group/world-writable roots, and post-start path replacement hold
  the runtime before any status or mutation access.
- CLI custody values are read from owner-held, single-link `0600` files (or
  inherited environment variables). Raw `--token` and `--session-token`
  arguments are rejected so live secrets do not land in shell history or the
  process argument list.

## Verification

```sh
npm run typecheck
npm run test:drawbridge-e2e
```

The e2e suite includes a planted external-network target and proves the CLI
rejects it before I/O. A real socket smoke can be run in an environment that
permits loopback `listen`; restricted sandboxes may return `listen EPERM` even
though the same HTTP dispatcher is exercised directly by the suite.
