import { strict as nodeAssert } from "node:assert";
import vm from "node:vm";
import { renderDrawbridgeBrowserScript, renderDrawbridgeConsole } from "../src/drawbridge-runtime/ui";

type TestCase = { name: string; run: () => void | Promise<void> };
const tests: TestCase[] = [];
const test = (name: string, run: TestCase["run"]) => tests.push({ name, run });

class FakeElement {
  value = "";
  textContent = "";
  disabled = false;
  hidden = false;
  readonly children: FakeElement[] = [];
  readonly listeners = new Map<string, (...args: unknown[]) => unknown>();

  addEventListener(name: string, listener: (...args: unknown[]) => unknown): void {
    this.listeners.set(name, listener);
  }

  replaceChildren(...children: FakeElement[]): void {
    this.children.splice(0, this.children.length, ...children);
  }

  append(child: FakeElement): void {
    this.children.push(child);
  }
}

interface FakeReply {
  path: string;
  status?: number;
  body?: unknown;
  error?: Error;
  hang?: boolean;
}

interface BrowserHarness {
  elements: Record<string, FakeElement>;
  calls: Array<{ path: string; options: Record<string, unknown> }>;
  storage: Map<string, string>;
  timers: Array<() => unknown>;
  deadlineTimers: Array<() => unknown>;
  consoleWrites: string[];
  windowListeners: Map<string, () => unknown>;
}

async function flushPromises(): Promise<void> {
  for (let index = 0; index < 8; index++) await new Promise<void>((resolve) => setImmediate(resolve));
}

async function bootBrowser(replies: FakeReply[], seed: Record<string, string> = {}): Promise<BrowserHarness> {
  const ids = [
    "prompt", "scenario", "submit", "retry-pending", "new-session", "erase-session", "state", "request", "response",
    "assessment", "reason", "receipt", "attestation", "status-region",
  ];
  const elements = Object.fromEntries(ids.map((id) => [id, new FakeElement()])) as Record<string, FakeElement>;
  const storage = new Map(Object.entries(seed));
  const calls: BrowserHarness["calls"] = [];
  const timers: BrowserHarness["timers"] = [];
  const deadlineTimers: BrowserHarness["deadlineTimers"] = [];
  const consoleWrites: string[] = [];
  const windowListeners = new Map<string, () => unknown>();
  let timerId = 0;
  const activeDeadlineTimers = new Set<number>();
  const queue = [...replies];
  const context = vm.createContext({
    document: {
      getElementById: (id: string) => elements[id],
      createElement: () => new FakeElement(),
    },
    window: {
      addEventListener: (name: string, listener: () => unknown) => windowListeners.set(name, listener),
    },
    sessionStorage: {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem: (key: string, value: string) => storage.set(key, String(value)),
      removeItem: (key: string) => storage.delete(key),
    },
    crypto: { randomUUID: () => "11111111-2222-4333-8444-555555555555" },
    fetch: async (path: string, options: Record<string, unknown> = {}) => {
      calls.push({ path, options });
      const next = queue.shift();
      nodeAssert(next, `unexpected fetch ${path}`);
      nodeAssert.equal(path, next.path);
      if (next.error) throw next.error;
      if (next.hang) {
        const signal = options.signal as AbortSignal | undefined;
        nodeAssert(signal, "hung fetch requires an AbortSignal");
        return await new Promise<never>((_resolve, reject) => {
          signal.addEventListener("abort", () => reject(signal.reason ?? new Error("aborted")), { once: true });
        });
      }
      return { status: next.status ?? 200, json: async () => next.body };
    },
    AbortController,
    setTimeout: (callback: () => unknown, delay = 0) => {
      const id = ++timerId;
      if (delay === 10_000) {
        activeDeadlineTimers.add(id);
        deadlineTimers.push(() => {
          if (!activeDeadlineTimers.delete(id)) return;
          return callback();
        });
      } else timers.push(callback);
      return id;
    },
    clearTimeout: (id: number) => { activeDeadlineTimers.delete(id); },
    console: {
      log: (...values: unknown[]) => consoleWrites.push(values.join(" ")),
      error: (...values: unknown[]) => consoleWrites.push(values.join(" ")),
    },
  });
  vm.runInContext(renderDrawbridgeBrowserScript(), context);
  await flushPromises();
  return { elements, calls, storage, timers, deadlineTimers, consoleWrites, windowListeners };
}

test("control room exposes complete semantic and accessible receipt state", () => {
  const html = renderDrawbridgeConsole();
  for (const required of [
    "Attestation", "id=\"attestation\"", "id=\"agent-response-heading\"",
    "aria-labelledby=\"agent-response-heading\"", "role=\"status\"",
    "id=\"retry-pending\"", "id=\"new-session\"", ":focus-visible", "#d65d43", "#8f9a8f",
  ]) nodeAssert(html.includes(required), `missing ${required}`);
  nodeAssert(!html.includes("<label class=\"label\">Agent response</label>"));
});

test("new crossing retains bounded session custody and renders explicit unattested state", async () => {
  const cap = "c".repeat(64);
  const resumeToken = "f".repeat(64);
  const ref = "a".repeat(64);
  const request = "b".repeat(64);
  const browser = await bootBrowser([
    { path: "/api/regions", body: { ok: true, regions: [{ scenarioId: "bridge.north" }] } },
    { path: "/api/sessions", body: {
      ok: true, sessionRef: ref, sessionCapability: cap, sessionResumeToken: resumeToken,
    } },
    { path: "/api/prompts", status: 202, body: { ok: true, requestId: request } },
    { path: `/api/turns/${request}/complete`, body: {
      ok: true,
      response: "Exact stand-in response",
      assessment: { status: "INSUFFICIENT_EVIDENCE", reason: "grid_size_below_floor" },
      receiptReference: "d".repeat(64),
      attestationReference: null,
    } },
    { path: `/api/sessions/${ref}`, body: {
      ok: true,
      actionablePendingRequestId: null,
      nextSequence: 2,
      pending: [],
      receipts: [{
        requestId: request,
        sequence: 1,
        receiptReference: "d".repeat(64),
        assessment: { status: "INSUFFICIENT_EVIDENCE", reason: "grid_size_below_floor" },
        attestationReference: null,
      }],
    } },
  ]);
  browser.elements.prompt.value = "Inspect the bridge";
  browser.elements.scenario.value = "bridge.north";
  await browser.elements.submit.listeners.get("click")?.();
  await flushPromises();

  const promptCall = browser.calls.find((item) => item.path === "/api/prompts");
  const completeCall = browser.calls.find((item) => item.path.includes("/complete"));
  nodeAssert.equal((promptCall?.options.headers as Record<string, string>)["x-drawbridge-session-capability"], cap);
  nodeAssert.equal((completeCall?.options.headers as Record<string, string>)["x-drawbridge-session-capability"], cap);
  nodeAssert.equal(browser.elements.state.textContent, "OBSERVED");
  nodeAssert.equal(browser.elements.attestation.textContent, "NOT_CONFIGURED");
  nodeAssert.equal(browser.elements.submit.disabled, false);
  nodeAssert.equal(browser.storage.get("tfb.drawbridge.browser_session_identity.v1"), "11111111-2222-4333-8444-555555555555");
  nodeAssert.equal(browser.storage.get("tfb.drawbridge.browser_session_ref.v1"), ref);
  nodeAssert.equal(browser.storage.get("tfb.drawbridge.browser_session_resume_token.v1"), resumeToken);
  nodeAssert.equal(browser.storage.has("tfb.drawbridge.browser_session_capability.v1"), false);
  nodeAssert.equal([...browser.storage.values()].includes(cap), false);
  nodeAssert.deepEqual(browser.consoleWrites, []);
  for (const clearedDeadline of browser.deadlineTimers) await clearedDeadline();
  await flushPromises();
  nodeAssert.equal(browser.elements.state.textContent, "OBSERVED");
});

test("reload resumes the same journey and projects the latest redacted receipt", async () => {
  const cap = "c".repeat(64);
  const resumeToken = "f".repeat(64);
  const ref = "a".repeat(64);
  const identity = "11111111-2222-4333-8444-555555555555";
  const request = "b".repeat(64);
  const browser = await bootBrowser([
    { path: "/api/regions", body: { ok: true, regions: [{ scenarioId: "bridge.south" }] } },
    { path: "/api/sessions", body: {
      ok: true, sessionRef: ref, sessionCapability: cap, sessionResumeToken: resumeToken,
    } },
    { path: `/api/sessions/${ref}`, body: {
      ok: true,
      nextSequence: 2,
      pending: [],
      receipts: [{
        requestId: request,
        receiptReference: "d".repeat(64),
        assessment: { status: "CANDIDATE_EVIDENCE", reason: "region_spread_candidate_observed" },
        attestationReference: "attestation://local/exact-reference",
      }],
    } },
    { path: `/api/sessions/${ref}`, body: { ok: true } },
  ], {
    "tfb.drawbridge.browser_session_identity.v1": identity,
    "tfb.drawbridge.browser_session_ref.v1": ref,
    "tfb.drawbridge.browser_session_resume_token.v1": resumeToken,
  });

  const resume = browser.calls.find((item) => item.path === "/api/sessions");
  nodeAssert.deepEqual(JSON.parse(String(resume?.options.body)), {
    tenantId: "drawbridge-demo-browser",
    sessionId: identity,
    resumeToken,
  });
  const status = browser.calls.find((item) => item.path === `/api/sessions/${ref}`);
  nodeAssert.equal((status?.options.headers as Record<string, string>)["x-drawbridge-session-capability"], cap);
  nodeAssert.equal(browser.elements.state.textContent, "RESUMED · NEXT 2");
  nodeAssert.equal(browser.elements.request.textContent, request);
  nodeAssert.equal(browser.elements.receipt.textContent, "d".repeat(64));
  nodeAssert.equal(browser.elements.attestation.textContent, "attestation://local/exact-reference");
  nodeAssert.equal(browser.elements.response.textContent, "Raw response was not retained; showing the durable redacted receipt.");
  nodeAssert.equal(browser.elements.submit.disabled, false);
  await browser.elements["erase-session"].listeners.get("click")?.();
  await flushPromises();
  const deletion = browser.calls.find((item) => item.path === `/api/sessions/${ref}` && item.options.method === "DELETE");
  nodeAssert.equal((deletion?.options.headers as Record<string, string>)["x-drawbridge-session-capability"], cap);
  nodeAssert.equal(browser.storage.size, 0);
  nodeAssert.equal(browser.elements.state.textContent, "ERASED");
});

test("reload recovers the oldest committed pending turn before any newer turn", async () => {
  const cap = "c".repeat(64);
  const resumeToken = "f".repeat(64);
  const ref = "a".repeat(64);
  const oldestRequest = "b".repeat(64);
  const newerRequest = "e".repeat(64);
  const browser = await bootBrowser([
    { path: "/api/regions", body: { ok: true, regions: [{ scenarioId: "bridge.south" }] } },
    { path: "/api/sessions", body: {
      ok: true, sessionRef: ref, sessionCapability: cap, sessionResumeToken: resumeToken,
    } },
    { path: `/api/sessions/${ref}`, body: {
      ok: true,
      nextSequence: 3,
      actionablePendingRequestId: oldestRequest,
      pending: [
        { requestId: oldestRequest, sequence: 1 },
        { requestId: newerRequest, sequence: 2 },
      ],
      receipts: [],
    } },
    { path: `/api/turns/${oldestRequest}/complete`, body: {
      ok: true,
      response: "Oldest exact response",
      assessment: { status: "INSUFFICIENT_EVIDENCE", reason: "oldest_completed" },
      receiptReference: "d".repeat(64),
      attestationReference: null,
    } },
    { path: `/api/sessions/${ref}`, body: {
      ok: true,
      nextSequence: 3,
      actionablePendingRequestId: newerRequest,
      pending: [{ requestId: newerRequest, sequence: 2 }],
      receipts: [{
        requestId: oldestRequest,
        sequence: 1,
        receiptReference: "d".repeat(64),
        assessment: { status: "INSUFFICIENT_EVIDENCE", reason: "oldest_completed" },
        attestationReference: null,
      }],
    } },
  ], {
    "tfb.drawbridge.browser_session_identity.v1": "11111111-2222-4333-8444-555555555555",
    "tfb.drawbridge.browser_session_ref.v1": ref,
    "tfb.drawbridge.browser_session_resume_token.v1": resumeToken,
  });

  nodeAssert.equal(browser.elements.state.textContent, "RESUMED · PENDING_AGENT_RESPONSE");
  nodeAssert.equal(browser.elements.request.textContent, oldestRequest);
  nodeAssert.equal(browser.elements.assessment.textContent, "Not observed");
  nodeAssert.equal(browser.elements.receipt.textContent, "None");
  nodeAssert.equal(browser.elements.attestation.textContent, "NOT_CONFIGURED");
  nodeAssert.equal(browser.elements.submit.disabled, true);
  nodeAssert.equal(browser.timers.length, 1);
  browser.elements.prompt.value = "Must not cross ahead of durable pending work";
  browser.elements.scenario.value = "bridge.south";
  await browser.elements.submit.listeners.get("click")?.();
  await flushPromises();
  nodeAssert.equal(browser.calls.filter((item) => item.path === "/api/prompts").length, 0);
  await browser.timers[0]();
  await flushPromises();
  const complete = browser.calls.find((item) => item.path === `/api/turns/${oldestRequest}/complete`);
  nodeAssert.equal((complete?.options.headers as Record<string, string>)["x-drawbridge-session-capability"], cap);
  nodeAssert.equal(browser.elements.state.textContent, "RESUMED · PENDING_AGENT_RESPONSE");
  nodeAssert.equal(browser.elements.request.textContent, newerRequest);
  nodeAssert.equal(browser.elements.submit.disabled, true);
  nodeAssert.equal(browser.timers.length, 2);
  nodeAssert.equal(browser.calls.some((item) => item.path === `/api/turns/${newerRequest}/complete`), false);
});

test("a stored journey survives region bootstrap failure without silent replacement", async () => {
  const ref = "a".repeat(64);
  const resumeToken = "f".repeat(64);
  const browser = await bootBrowser([
    { path: "/api/regions", error: new Error("region registry unavailable") },
  ], {
    "tfb.drawbridge.browser_session_identity.v1": "11111111-2222-4333-8444-555555555555",
    "tfb.drawbridge.browser_session_ref.v1": ref,
    "tfb.drawbridge.browser_session_resume_token.v1": resumeToken,
  });

  nodeAssert.equal(browser.elements.state.textContent, "HELD");
  nodeAssert.equal(browser.elements.submit.disabled, true);
  nodeAssert.equal(browser.elements["new-session"].hidden, false);
  nodeAssert.equal(browser.storage.size, 3);
  await browser.elements.submit.listeners.get("click")?.();
  await flushPromises();
  nodeAssert.equal(browser.calls.filter((item) => item.path === "/api/sessions").length, 0);
});

test("hung bootstrap fetch is aborted at the browser request deadline", async () => {
  const browser = await bootBrowser([
    { path: "/api/regions", hang: true },
  ]);
  const deadline = browser.deadlineTimers.at(-1);
  nodeAssert(deadline, "bootstrap deadline timer missing");
  await deadline();
  await flushPromises();
  nodeAssert.equal(browser.elements.state.textContent, "HELD");
  nodeAssert.equal(browser.elements.reason.textContent, "browser_request_deadline_exceeded");
  nodeAssert.equal(browser.calls.length, 1);
});

test("hung completion fetch preserves the exact pending turn for bounded retry", async () => {
  const cap = "c".repeat(64);
  const resumeToken = "f".repeat(64);
  const ref = "a".repeat(64);
  const request = "b".repeat(64);
  const browser = await bootBrowser([
    { path: "/api/regions", body: { ok: true, regions: [{ scenarioId: "bridge.north" }] } },
    { path: "/api/sessions", body: {
      ok: true, sessionRef: ref, sessionCapability: cap, sessionResumeToken: resumeToken,
    } },
    { path: "/api/prompts", status: 202, body: { ok: true, requestId: request } },
    { path: `/api/turns/${request}/complete`, hang: true },
    { path: `/api/turns/${request}/complete`, body: {
      ok: true,
      response: "Recovered after browser deadline",
      assessment: { status: "INSUFFICIENT_EVIDENCE", reason: "bounded_deadline_retry" },
      receiptReference: "d".repeat(64),
      attestationReference: null,
    } },
    { path: `/api/sessions/${ref}`, body: {
      ok: true,
      actionablePendingRequestId: null,
      nextSequence: 2,
      pending: [],
      receipts: [{
        requestId: request,
        sequence: 1,
        receiptReference: "d".repeat(64),
        assessment: { status: "INSUFFICIENT_EVIDENCE", reason: "bounded_deadline_retry" },
        attestationReference: null,
      }],
    } },
  ]);
  browser.elements.prompt.value = "Inspect the bridge";
  browser.elements.scenario.value = "bridge.north";
  const crossing = browser.elements.submit.listeners.get("click")?.() as Promise<void>;
  await flushPromises();
  const deadline = browser.deadlineTimers.at(-1);
  nodeAssert(deadline, "completion deadline timer missing");
  await deadline();
  await crossing;
  await flushPromises();
  nodeAssert.equal(browser.elements.state.textContent, "HELD · PENDING_RETRY");
  nodeAssert.equal(browser.elements.reason.textContent, "browser_request_deadline_exceeded");
  nodeAssert.equal(browser.elements.request.textContent, request);
  nodeAssert.equal(browser.elements.submit.disabled, true);
  nodeAssert.equal(browser.elements["retry-pending"].hidden, false);
  await browser.elements["retry-pending"].listeners.get("click")?.();
  await flushPromises();
  nodeAssert.equal(browser.calls.filter((item) => item.path === `/api/turns/${request}/complete`).length, 2);
  nodeAssert.equal(browser.elements.state.textContent, "OBSERVED");
  nodeAssert.equal(browser.elements.request.textContent, request);
});

test("hung erasure fetch aborts without discarding local session custody", async () => {
  const cap = "c".repeat(64);
  const resumeToken = "f".repeat(64);
  const ref = "a".repeat(64);
  const identity = "11111111-2222-4333-8444-555555555555";
  const browser = await bootBrowser([
    { path: "/api/regions", body: { ok: true, regions: [{ scenarioId: "bridge.south" }] } },
    { path: "/api/sessions", body: {
      ok: true, sessionRef: ref, sessionCapability: cap, sessionResumeToken: resumeToken,
    } },
    { path: `/api/sessions/${ref}`, body: { ok: true, nextSequence: 1, pending: [], receipts: [] } },
    { path: `/api/sessions/${ref}`, hang: true },
  ], {
    "tfb.drawbridge.browser_session_identity.v1": identity,
    "tfb.drawbridge.browser_session_ref.v1": ref,
    "tfb.drawbridge.browser_session_resume_token.v1": resumeToken,
  });
  const erasure = browser.elements["erase-session"].listeners.get("click")?.() as Promise<void>;
  await flushPromises();
  const deadline = browser.deadlineTimers.at(-1);
  nodeAssert(deadline, "erasure deadline timer missing");
  await deadline();
  await erasure;
  await flushPromises();
  nodeAssert.equal(browser.elements.state.textContent, "HELD");
  nodeAssert.equal(browser.elements.reason.textContent, "browser_request_deadline_exceeded");
  nodeAssert.equal(browser.storage.get("tfb.drawbridge.browser_session_identity.v1"), identity);
  nodeAssert.equal(browser.storage.get("tfb.drawbridge.browser_session_ref.v1"), ref);
  nodeAssert.equal(browser.storage.get("tfb.drawbridge.browser_session_resume_token.v1"), resumeToken);
});

test("pagehide cancels the bounded poll before another network iteration", async () => {
  const cap = "c".repeat(64);
  const resumeToken = "f".repeat(64);
  const ref = "a".repeat(64);
  const request = "b".repeat(64);
  const browser = await bootBrowser([
    { path: "/api/regions", body: { ok: true, regions: [{ scenarioId: "bridge.north" }] } },
    { path: "/api/sessions", body: {
      ok: true, sessionRef: ref, sessionCapability: cap, sessionResumeToken: resumeToken,
    } },
    { path: "/api/prompts", status: 202, body: { ok: true, requestId: request } },
    { path: `/api/turns/${request}/complete`, status: 202, body: {
      ok: false, holds: ["agent_response_pending"],
    } },
  ]);
  browser.elements.prompt.value = "Inspect the bridge";
  browser.elements.scenario.value = "bridge.north";
  await browser.elements.submit.listeners.get("click")?.();
  await flushPromises();
  nodeAssert.equal(browser.timers.length, 1);
  const callsBeforePagehide = browser.calls.length;
  browser.windowListeners.get("pagehide")?.();
  await browser.timers[0]();
  await flushPromises();
  nodeAssert.equal(browser.calls.length, callsBeforePagehide);
});

test("poll failure retains the exact pending turn and retries only that turn", async () => {
  const cap = "c".repeat(64);
  const resumeToken = "f".repeat(64);
  const ref = "a".repeat(64);
  const request = "b".repeat(64);
  const browser = await bootBrowser([
    { path: "/api/regions", body: { ok: true, regions: [{ scenarioId: "bridge.north" }] } },
    { path: "/api/sessions", body: {
      ok: true, sessionRef: ref, sessionCapability: cap, sessionResumeToken: resumeToken,
    } },
    { path: "/api/prompts", status: 202, body: { ok: true, requestId: request } },
    { path: `/api/turns/${request}/complete`, status: 202, body: { ok: false, holds: ["agent_response_pending"] } },
    { path: `/api/turns/${request}/complete`, error: new Error("server disappeared") },
    { path: `/api/turns/${request}/complete`, body: {
      ok: true,
      response: "Recovered exact response",
      assessment: { status: "INSUFFICIENT_EVIDENCE", reason: "recovered_same_request" },
      receiptReference: "d".repeat(64),
      attestationReference: null,
    } },
    { path: `/api/sessions/${ref}`, body: {
      ok: true,
      actionablePendingRequestId: null,
      nextSequence: 2,
      pending: [],
      receipts: [{
        requestId: request,
        sequence: 1,
        receiptReference: "d".repeat(64),
        assessment: { status: "INSUFFICIENT_EVIDENCE", reason: "recovered_same_request" },
        attestationReference: null,
      }],
    } },
  ]);
  browser.elements.prompt.value = "Inspect the bridge";
  browser.elements.scenario.value = "bridge.north";
  await browser.elements.submit.listeners.get("click")?.();
  await flushPromises();
  nodeAssert.equal(browser.timers.length, 1);
  await browser.timers[0]();
  await flushPromises();
  nodeAssert.equal(browser.elements.state.textContent, "HELD · PENDING_RETRY");
  nodeAssert.equal(browser.elements.reason.textContent, "server disappeared");
  nodeAssert.equal(browser.elements.request.textContent, request);
  nodeAssert.equal(browser.elements.submit.disabled, true);
  nodeAssert.equal(browser.elements["retry-pending"].hidden, false);
  const promptsBeforeBlockedSubmit = browser.calls.filter((item) => item.path === "/api/prompts").length;
  await browser.elements.submit.listeners.get("click")?.();
  await flushPromises();
  nodeAssert.equal(browser.calls.filter((item) => item.path === "/api/prompts").length, promptsBeforeBlockedSubmit);
  await browser.elements["retry-pending"].listeners.get("click")?.();
  await flushPromises();
  const completeCalls = browser.calls.filter((item) => item.path === `/api/turns/${request}/complete`);
  nodeAssert.equal(completeCalls.length, 3);
  nodeAssert.equal(browser.elements.state.textContent, "OBSERVED");
  nodeAssert.equal(browser.elements.submit.disabled, false);
  nodeAssert.equal(browser.elements["retry-pending"].hidden, true);
});

test("poll ceiling holds the exact pending turn until bounded same-turn retry", async () => {
  const cap = "c".repeat(64);
  const resumeToken = "f".repeat(64);
  const ref = "a".repeat(64);
  const request = "b".repeat(64);
  const pendingReplies: FakeReply[] = Array.from({ length: 330 }, () => ({
    path: `/api/turns/${request}/complete`,
    status: 202,
    body: { ok: false, holds: ["agent_response_pending"] },
  }));
  const browser = await bootBrowser([
    { path: "/api/regions", body: { ok: true, regions: [{ scenarioId: "bridge.north" }] } },
    { path: "/api/sessions", body: {
      ok: true, sessionRef: ref, sessionCapability: cap, sessionResumeToken: resumeToken,
    } },
    { path: "/api/prompts", status: 202, body: { ok: true, requestId: request } },
    ...pendingReplies,
    { path: `/api/turns/${request}/complete`, body: {
      ok: true,
      response: "Response after operator retry",
      assessment: { status: "INSUFFICIENT_EVIDENCE", reason: "bounded_retry" },
      receiptReference: "d".repeat(64),
      attestationReference: null,
    } },
    { path: `/api/sessions/${ref}`, body: {
      ok: true,
      actionablePendingRequestId: null,
      nextSequence: 2,
      pending: [],
      receipts: [{
        requestId: request,
        sequence: 1,
        receiptReference: "d".repeat(64),
        assessment: { status: "INSUFFICIENT_EVIDENCE", reason: "bounded_retry" },
        attestationReference: null,
      }],
    } },
  ]);
  browser.elements.prompt.value = "Inspect the bridge";
  browser.elements.scenario.value = "bridge.north";
  await browser.elements.submit.listeners.get("click")?.();
  await flushPromises();
  let timerIndex = 0;
  while (browser.elements.state.textContent !== "HELD · PENDING_RETRY" && timerIndex < 340) {
    const timer = browser.timers[timerIndex++];
    nodeAssert(timer, `missing bounded timer ${timerIndex}`);
    await timer();
    await flushPromises();
  }
  nodeAssert.equal(browser.elements.state.textContent, "HELD · PENDING_RETRY");
  nodeAssert.equal(browser.elements.reason.textContent, "agent_response_poll_ceiling_reached");
  nodeAssert.equal(browser.elements.request.textContent, request);
  nodeAssert.equal(browser.elements.submit.disabled, true);
  nodeAssert.equal(browser.elements["retry-pending"].hidden, false);
  nodeAssert.equal(browser.calls.filter((item) => item.path === `/api/turns/${request}/complete`).length, 330);
  await browser.elements["retry-pending"].listeners.get("click")?.();
  await flushPromises();
  nodeAssert.equal(browser.calls.filter((item) => item.path === `/api/turns/${request}/complete`).length, 331);
  nodeAssert.equal(browser.elements.state.textContent, "OBSERVED");
  nodeAssert.equal(browser.elements.submit.disabled, false);
});

test("a rejected capability never creates a replacement journey", async () => {
  const ref = "a".repeat(64);
  const rejected = await bootBrowser([
    { path: "/api/regions", body: { ok: true, regions: [{ scenarioId: "bridge.north" }] } },
    { path: "/api/sessions", status: 409, body: { ok: false, holds: ["session_resume_token_invalid"] } },
  ], {
    "tfb.drawbridge.browser_session_identity.v1": "11111111-2222-4333-8444-555555555555",
    "tfb.drawbridge.browser_session_ref.v1": ref,
    "tfb.drawbridge.browser_session_resume_token.v1": "e".repeat(64),
  });
  nodeAssert.equal(rejected.calls.filter((item) => item.path === "/api/sessions").length, 1);
  nodeAssert.equal(rejected.storage.size, 0);
  nodeAssert.equal(rejected.elements.state.textContent, "HELD");
  nodeAssert.equal(rejected.elements.submit.disabled, true);
  nodeAssert.equal(rejected.elements["new-session"].hidden, false);
});

let failed = 0;
for (const item of tests) {
  try {
    await item.run();
    process.stdout.write(`ok   ${item.name}\n`);
  } catch (error) {
    failed++;
    process.stderr.write(`not ok - ${item.name}\n${String(error)}\n`);
  }
}
process.stdout.write(`${tests.length - failed}/${tests.length} drawbridge UI tests passed\n`);
process.exitCode = failed ? 1 : 0;
