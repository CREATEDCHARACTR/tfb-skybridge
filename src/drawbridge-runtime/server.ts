import { timingSafeEqual } from "node:crypto";
import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { DrawbridgeRuntimeController } from "./controller";
import { isWellFormedUnicode, OBSERVE_ONLY_AUTHORITY, type RuntimeResult } from "./types";
import { renderDrawbridgeBrowserScript, renderDrawbridgeConsole } from "./ui";

const MAX_REQUEST_BYTES = 300_000;
const MAX_RESPONSE_BYTES = 1_000_000;
const SERVER_REQUEST_TIMEOUT_MS = 10_000;
const SERVER_HEADERS_TIMEOUT_MS = 5_000;
const SERVER_KEEP_ALIVE_TIMEOUT_MS = 2_000;
const SERVER_MAX_CONNECTIONS = 32;
const SERVER_MAX_REQUESTS_PER_SOCKET = 32;
const LOOPBACK_CLIENT_TIMEOUT_MS = 5_000;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);

function narration(op: string, ok: boolean, holds: string[], errors: string[] = []): RuntimeResult {
  return {
    op, ok, actions: [],
    skips: ["model_provider_network_not_called", "local_model_not_called", "policy_action_not_evaluated"],
    errors, holds,
    metrics: { model_provider_network_calls: 0, http_error_echoes_raw_payload: false },
    next: ok ? "Continue the local OBSERVE_ONLY demo." : "Heal the named HTTP contract hold before retrying.",
    authority: OBSERVE_ONLY_AUTHORITY,
  };
}

function exactBody(value: unknown, keys: string[]): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value)
    && JSON.stringify(Object.keys(value as Record<string, unknown>).sort()) === JSON.stringify([...keys].sort());
}

function bearerMatches(authorization: string | undefined, expected: string): boolean {
  if (!authorization?.startsWith("Bearer ")) return false;
  const supplied = Buffer.from(authorization.slice("Bearer ".length));
  const wanted = Buffer.from(expected);
  return supplied.length === wanted.length && timingSafeEqual(supplied, wanted);
}

export interface DrawbridgeHttpInput {
  method: string;
  path: string;
  body?: unknown;
  authorization?: string;
  sessionCapability?: string;
  secFetchSite?: string;
}

export interface DrawbridgeHttpOutput {
  status: number;
  contentType: "application/json; charset=utf-8" | "text/html; charset=utf-8" | "text/javascript; charset=utf-8" | "image/x-icon";
  body: unknown;
}

function json(status: number, body: unknown): DrawbridgeHttpOutput {
  return { status, contentType: "application/json; charset=utf-8", body };
}

class StrictJsonScanner {
  private index = 0;

  constructor(private readonly source: string) {}

  scan(): void {
    this.whitespace();
    this.value();
    this.whitespace();
    if (this.index !== this.source.length) this.invalid();
  }

  private invalid(): never { throw new Error("request_body_json_invalid"); }

  private whitespace(): void {
    while (this.index < this.source.length && /[\t\n\r ]/u.test(this.source[this.index])) this.index++;
  }

  private value(): void {
    this.whitespace();
    const character = this.source[this.index];
    if (character === "{") { this.object(); return; }
    if (character === "[") { this.array(); return; }
    if (character === '"') { this.string(); return; }
    if (character === "t") { this.literal("true"); return; }
    if (character === "f") { this.literal("false"); return; }
    if (character === "n") { this.literal("null"); return; }
    if (character === "-" || (character >= "0" && character <= "9")) { this.number(); return; }
    this.invalid();
  }

  private object(): void {
    this.index++;
    this.whitespace();
    if (this.source[this.index] === "}") { this.index++; return; }
    const keys = new Set<string>();
    while (this.index < this.source.length) {
      if (this.source[this.index] !== '"') this.invalid();
      const key = this.string();
      if (keys.has(key)) throw new Error(`request_body_duplicate_key:${key}`);
      keys.add(key);
      this.whitespace();
      if (this.source[this.index] !== ":") this.invalid();
      this.index++;
      this.value();
      this.whitespace();
      if (this.source[this.index] === "}") { this.index++; return; }
      if (this.source[this.index] !== ",") this.invalid();
      this.index++;
      this.whitespace();
    }
    this.invalid();
  }

  private array(): void {
    this.index++;
    this.whitespace();
    if (this.source[this.index] === "]") { this.index++; return; }
    while (this.index < this.source.length) {
      this.value();
      this.whitespace();
      if (this.source[this.index] === "]") { this.index++; return; }
      if (this.source[this.index] !== ",") this.invalid();
      this.index++;
      this.whitespace();
    }
    this.invalid();
  }

  private string(): string {
    const start = this.index;
    this.index++;
    while (this.index < this.source.length) {
      const code = this.source.charCodeAt(this.index);
      if (code === 0x22) {
        this.index++;
        try { return JSON.parse(this.source.slice(start, this.index)) as string; }
        catch { return this.invalid(); }
      }
      if (code < 0x20) this.invalid();
      if (code === 0x5c) {
        this.index++;
        const escaped = this.source[this.index];
        if (escaped === "u") {
          if (!/^[0-9a-fA-F]{4}$/u.test(this.source.slice(this.index + 1, this.index + 5))) this.invalid();
          this.index += 5;
          continue;
        }
        if (!escaped || !'"\\/bfnrt'.includes(escaped)) this.invalid();
      }
      this.index++;
    }
    return this.invalid();
  }

  private literal(expected: string): void {
    if (this.source.slice(this.index, this.index + expected.length) !== expected) this.invalid();
    this.index += expected.length;
  }

  private number(): void {
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(this.source.slice(this.index));
    if (!match) this.invalid();
    this.index += match[0].length;
  }
}

export function parseStrictJson(source: string): unknown {
  try {
    new StrictJsonScanner(source).scan();
    const parsed = JSON.parse(source) as unknown;
    const assertText = (value: unknown): void => {
      if (typeof value === "string") {
        if (!isWellFormedUnicode(value)) throw new Error("json_string_not_well_formed");
        return;
      }
      if (Array.isArray(value)) { value.forEach(assertText); return; }
      if (value && typeof value === "object") {
        for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
          if (!isWellFormedUnicode(key)) throw new Error("json_string_not_well_formed");
          assertText(nested);
        }
      }
    };
    assertText(parsed);
    return parsed;
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("request_body_duplicate_key:")) throw error;
    if (error instanceof Error && error.message === "json_string_not_well_formed") throw error;
    throw new Error("request_body_json_invalid");
  }
}

function sessionCapabilityGate(
  controller: DrawbridgeRuntimeController,
  sessionRef: string,
  supplied: string | undefined,
  op: string,
): DrawbridgeHttpOutput | undefined {
  if (!supplied) return json(401, narration(op, false, ["session_capability_required"]));
  if (!controller.verifySessionCapability(sessionRef, supplied)) {
    return json(403, narration(op, false, ["session_capability_invalid"]));
  }
  return undefined;
}

export function dispatchDrawbridgeHttp(
  controller: DrawbridgeRuntimeController,
  agentToken: string,
  input: DrawbridgeHttpInput,
): DrawbridgeHttpOutput {
  if (Buffer.byteLength(agentToken) < 32) throw new Error("agent_custody_token_minimum_32_bytes_required");
  const method = input.method.toUpperCase();
  const url = new URL(input.path, "http://127.0.0.1");
  if (url.pathname.startsWith("/api/") && input.secFetchSite?.toLowerCase() === "cross-site") {
    return json(403, narration("drawbridge.http.request", false, ["cross_site_request_forbidden"]));
  }

  if (method === "GET" && url.pathname === "/") {
    return { status: 200, contentType: "text/html; charset=utf-8", body: renderDrawbridgeConsole() };
  }
  if (method === "GET" && url.pathname === "/drawbridge.js") {
    return { status: 200, contentType: "text/javascript; charset=utf-8", body: renderDrawbridgeBrowserScript() };
  }
  if (method === "GET" && url.pathname === "/favicon.ico") {
    return { status: 204, contentType: "image/x-icon", body: "" };
  }
  if (method === "GET" && url.pathname === "/api/health") {
    const health = controller.health();
    return json(health.ok ? 200 : 503, health);
  }
  if (method === "GET" && url.pathname === "/api/regions") return json(200, controller.listRegions());

  if (method === "POST" && url.pathname === "/api/sessions") {
    const body = input.body as Record<string, unknown> | undefined;
    const initial = exactBody(body, ["tenantId", "sessionId"]);
    const resume = exactBody(body, ["tenantId", "sessionId", "resumeToken"]);
    if ((!initial && !resume)
      || typeof body?.tenantId !== "string" || typeof body.sessionId !== "string"
      || (resume && typeof body.resumeToken !== "string")) {
      return json(400, narration("drawbridge.http.start_session", false, ["request_body_contract_invalid"]));
    }
    const started = controller.startSession(body.tenantId, body.sessionId, resume ? body.resumeToken as string : undefined);
    return json(started.ok ? 200 : 409, started);
  }
  if (method === "POST" && url.pathname === "/api/prompts") {
    if (!exactBody(input.body, ["sessionRef", "prompt", "scenarioId"])
      || typeof input.body.sessionRef !== "string" || typeof input.body.prompt !== "string" || typeof input.body.scenarioId !== "string") {
      return json(400, narration("drawbridge.http.submit_prompt", false, ["request_body_contract_invalid"]));
    }
    const denied = sessionCapabilityGate(controller, input.body.sessionRef, input.sessionCapability, "drawbridge.http.submit_prompt");
    if (denied) return denied;
    const result = controller.submitPrompt(
      input.body.sessionRef,
      input.body.prompt,
      input.body.scenarioId,
      input.sessionCapability ?? "",
      { requireEmptyPending: true },
    );
    return json(result.ok ? 202 : result.holds.includes("session_capability_invalid") ? 403 : 409, result);
  }
  const sessionMatch = /^\/api\/sessions\/([0-9a-f]{64})$/.exec(url.pathname);
  if (method === "GET" && sessionMatch) {
    const denied = sessionCapabilityGate(controller, sessionMatch[1], input.sessionCapability, "drawbridge.http.session_status");
    if (denied) return denied;
    const result = controller.sessionStatus(sessionMatch[1], input.sessionCapability ?? "");
    return json(result.ok ? 200 : result.holds.includes("session_capability_invalid") ? 403 : 404, result);
  }
  if (method === "DELETE" && sessionMatch) {
    const denied = sessionCapabilityGate(controller, sessionMatch[1], input.sessionCapability, "drawbridge.http.erase_session");
    if (denied) return denied;
    const result = controller.eraseSession(sessionMatch[1], input.sessionCapability ?? "");
    return json(result.ok ? 200 : result.holds.includes("session_capability_invalid") ? 403 : 404, result);
  }
  const agentRequestMatch = /^\/api\/agent\/requests\/([0-9a-f]{64})$/.exec(url.pathname);
  if (method === "GET" && agentRequestMatch) {
    if (!bearerMatches(input.authorization, agentToken)) {
      return json(401, narration("drawbridge.http.get_agent_request", false, ["agent_custody_token_required"]));
    }
    const result = controller.getAgentRequest(agentRequestMatch[1]);
    return json(result.ok ? 200 : 404, result);
  }
  if (method === "POST" && url.pathname === "/api/agent/responses") {
    if (!bearerMatches(input.authorization, agentToken)) {
      return json(401, narration("drawbridge.http.submit_agent_response", false, ["agent_custody_token_required"]));
    }
    if (!exactBody(input.body, ["requestId", "provider", "response", "responseSha256"])
      || typeof input.body.requestId !== "string" || typeof input.body.provider !== "string"
      || typeof input.body.response !== "string" || typeof input.body.responseSha256 !== "string") {
      return json(400, narration("drawbridge.http.submit_agent_response", false, ["request_body_contract_invalid"]));
    }
    const result = controller.submitAgentResponse({
      requestId: input.body.requestId,
      provider: input.body.provider,
      response: input.body.response,
      responseSha256: input.body.responseSha256,
    });
    return json(result.ok ? 200 : 409, result);
  }
  const completeMatch = /^\/api\/turns\/([0-9a-f]{64})\/complete$/.exec(url.pathname);
  if (method === "POST" && completeMatch) {
    if (!exactBody(input.body, [])) return json(400, narration("drawbridge.http.complete_turn", false, ["request_body_contract_invalid"]));
    if (!input.sessionCapability) return json(401, narration("drawbridge.http.complete_turn", false, ["session_capability_required"]));
    const sessionRef = controller.requestSessionRef(completeMatch[1]);
    if (!sessionRef) return json(404, narration("drawbridge.http.complete_turn", false, ["request_not_registered"]));
    const denied = sessionCapabilityGate(controller, sessionRef, input.sessionCapability, "drawbridge.http.complete_turn");
    if (denied) return denied;
    const result = controller.completeTurn(completeMatch[1], input.sessionCapability ?? "");
    return json(result.ok ? 200
      : result.holds.includes("session_capability_invalid") ? 403
        : result.holds.includes("agent_response_pending") ? 202 : 409, result);
  }
  return json(404, narration("drawbridge.http.request", false, ["route_not_found"]));
}

function setSecurityHeaders(response: ServerResponse, contentType: string): void {
  response.setHeader("content-type", contentType);
  response.setHeader("cache-control", "no-store, max-age=0");
  response.setHeader("x-content-type-options", "nosniff");
  response.setHeader("referrer-policy", "no-referrer");
  response.setHeader("x-frame-options", "DENY");
  response.setHeader("cross-origin-resource-policy", "same-origin");
  response.setHeader("content-security-policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
}

function hostAllowed(request: IncomingMessage): boolean {
  const host = request.headers.host;
  if (!host) return false;
  try { return LOOPBACK_HOSTS.has(new URL(`http://${host}`).hostname); } catch { return false; }
}

function originAllowed(request: IncomingMessage): boolean {
  const origin = request.headers.origin;
  if (!origin) return true;
  try { return LOOPBACK_HOSTS.has(new URL(origin).hostname); } catch { return false; }
}

export function isExactJsonMediaType(value: unknown): boolean {
  return typeof value === "string" && /^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(value);
}

async function readBody(request: IncomingMessage): Promise<unknown> {
  if (!isExactJsonMediaType(request.headers["content-type"])) {
    throw new Error("content_type_application_json_required");
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += bytes.length;
    if (size > MAX_REQUEST_BYTES) throw new Error("request_body_too_large");
    chunks.push(bytes);
  }
  let source: string;
  try { source = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)); }
  catch { throw new Error("request_body_utf8_required"); }
  return parseStrictJson(source);
}

function emit(response: ServerResponse, output: DrawbridgeHttpOutput): void {
  setSecurityHeaders(response, output.contentType);
  response.statusCode = output.status;
  response.end(typeof output.body === "string" ? output.body : `${JSON.stringify(output.body)}\n`);
}

async function serve(
  request: IncomingMessage,
  response: ServerResponse,
  controller: DrawbridgeRuntimeController,
  agentToken: string,
): Promise<void> {
  if (!hostAllowed(request) || !originAllowed(request)) {
    emit(response, json(403, narration("drawbridge.http.request", false, ["loopback_origin_required"])));
    return;
  }
  if (typeof request.headers["sec-fetch-site"] === "string" && request.headers["sec-fetch-site"].toLowerCase() === "cross-site") {
    emit(response, json(403, narration("drawbridge.http.request", false, ["cross_site_request_forbidden"])));
    return;
  }
  const method = request.method ?? "GET";
  const body = ["POST", "DELETE"].includes(method) && method !== "DELETE" ? await readBody(request) : undefined;
  emit(response, dispatchDrawbridgeHttp(controller, agentToken, {
    method,
    path: request.url ?? "/",
    body,
    authorization: request.headers.authorization,
    secFetchSite: typeof request.headers["sec-fetch-site"] === "string" ? request.headers["sec-fetch-site"] : undefined,
    sessionCapability: typeof request.headers["x-drawbridge-session-capability"] === "string"
      ? request.headers["x-drawbridge-session-capability"]
      : undefined,
  }));
}

export function createDrawbridgeHttpServer(options: { controller: DrawbridgeRuntimeController; agentToken: string }): Server {
  if (Buffer.byteLength(options.agentToken) < 32) throw new Error("agent_custody_token_minimum_32_bytes_required");
  const server = createServer((request, response) => {
    void serve(request, response, options.controller, options.agentToken).catch((error) => {
      if (response.headersSent) { response.destroy(); return; }
      const message = error instanceof Error ? error.message : String(error);
      emit(response, json(message === "request_body_too_large" ? 413 : 400, narration("drawbridge.http.request", false, [message])));
    });
  });
  server.requestTimeout = SERVER_REQUEST_TIMEOUT_MS;
  server.headersTimeout = SERVER_HEADERS_TIMEOUT_MS;
  server.keepAliveTimeout = SERVER_KEEP_ALIVE_TIMEOUT_MS;
  server.maxConnections = SERVER_MAX_CONNECTIONS;
  server.maxRequestsPerSocket = SERVER_MAX_REQUESTS_PER_SOCKET;
  return server;
}

export interface LoopbackRequestOptions {
  method?: "GET" | "POST" | "DELETE";
  body?: unknown;
  headers?: Record<string, string>;
  timeoutMs?: number;
}

export function requestLoopbackJson(endpoint: string, options: LoopbackRequestOptions = {}): Promise<unknown> {
  const url = new URL(endpoint);
  if (url.protocol !== "http:" || !LOOPBACK_HOSTS.has(url.hostname) || url.username || url.password) {
    return Promise.reject(new Error("loopback_endpoint_required"));
  }
  const body = options.body === undefined ? undefined : Buffer.from(JSON.stringify(options.body));
  const timeoutMs = options.timeoutMs ?? LOOPBACK_CLIENT_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000) {
    return Promise.reject(new Error("loopback_timeout_out_of_range"));
  }
  return new Promise((resolve, reject) => {
    const request = httpRequest(url, {
      method: options.method ?? "GET",
      headers: {
        accept: "application/json",
        ...(body ? { "content-type": "application/json", "content-length": String(body.length) } : {}),
        ...options.headers,
      },
    }, (response) => {
      const chunks: Buffer[] = [];
      let size = 0;
      response.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_RESPONSE_BYTES) { response.destroy(new Error("loopback_response_too_large")); return; }
        chunks.push(chunk);
      });
      response.on("error", reject);
      response.on("end", () => {
        let parsed: unknown;
        try { parsed = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
        catch { reject(new Error("loopback_response_json_invalid")); return; }
        const status = response.statusCode ?? 0;
        if (status < 200 || status >= 300) { reject(new Error(`loopback_http_${status}:${JSON.stringify(parsed)}`)); return; }
        resolve(parsed);
      });
    });
    request.on("error", reject);
    request.setTimeout(timeoutMs, () => request.destroy(new Error("loopback_request_timeout")));
    request.end(body);
  });
}
