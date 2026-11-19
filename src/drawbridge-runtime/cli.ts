#!/usr/bin/env node
import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  ftruncateSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  unlinkSync,
} from "node:fs";
import { dirname, join, parse, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createDrawbridgeRuntime } from "./bootstrap";
import { createDrawbridgeHttpServer, requestLoopbackJson, type LoopbackRequestOptions } from "./server";
import { CHATGPT_AGENT_PROVIDER, MAX_AGENT_RESPONSE_BYTES, OBSERVE_ONLY_AUTHORITY } from "./types";

type RequestJson = (endpoint: string, options?: LoopbackRequestOptions) => Promise<unknown>;

export interface DrawbridgeCliDependencies {
  requestJson?: RequestJson;
  writeOut?: (line: string) => void;
  writeError?: (line: string) => void;
  beforeResponseFileOpen?: () => void;
}

export interface ParsedArguments {
  command: string;
  positional: string[];
  flags: Map<string, string>;
}

function parseArguments(args: string[]): ParsedArguments {
  const [command = "help", ...rest] = args;
  const positional: string[] = [];
  const flags = new Map<string, string>();
  for (let index = 0; index < rest.length; index++) {
    const value = rest[index];
    if (!value.startsWith("--")) { positional.push(value); continue; }
    const next = rest[index + 1];
    if (!next || next.startsWith("--")) throw new Error(`value_required_for_${value.slice(2)}`);
    const flag = value.slice(2);
    if (flags.has(flag)) throw new Error("duplicate_cli_flag_forbidden");
    flags.set(flag, next);
    index++;
  }
  return { command, positional, flags };
}

const CLI_ARGUMENT_CONTRACTS: ReadonlyMap<string, { positionalCount: number; flags: ReadonlySet<string> }> = new Map([
  ["help", { positionalCount: 0, flags: new Set() }],
  ["--help", { positionalCount: 0, flags: new Set() }],
  ["-h", { positionalCount: 0, flags: new Set() }],
  ["serve", { positionalCount: 0, flags: new Set(["port", "state-dir", "token-file"]) }],
  ["retention-sweep", { positionalCount: 0, flags: new Set(["state-dir"]) }],
  ["agent-request", { positionalCount: 1, flags: new Set(["url", "token-file"]) }],
  ["agent-respond", { positionalCount: 1, flags: new Set(["url", "token-file", "response-file"]) }],
  ["complete", { positionalCount: 1, flags: new Set(["url", "session-token-file"]) }],
  ["status", { positionalCount: 1, flags: new Set(["url", "session-token-file"]) }],
  ["erase", { positionalCount: 1, flags: new Set(["url", "session-token-file"]) }],
]);

export function parseAndValidateDrawbridgeArguments(args: string[]): ParsedArguments {
  const parsed = parseArguments(args);
  const contract = CLI_ARGUMENT_CONTRACTS.get(parsed.command);
  if (!contract) throw new Error("drawbridge_cli_command_unknown");
  if (parsed.flags.has("token") || parsed.flags.has("session-token")) throw new Error("secret_argv_forbidden");
  if (parsed.positional.length !== contract.positionalCount
    || [...parsed.flags.keys()].some((flag) => !contract.flags.has(flag))) {
    throw new Error(`${parsed.command.replace(/-/gu, "_")}_argv_invalid`);
  }
  return parsed;
}

function help(): string {
  return [
    "TFB Drawbridge · OBSERVE_ONLY demo",
    "",
    "  serve [--port 4317] [--state-dir .state/drawbridge-demo] (--token-file MODE_0600_FILE | DRAWBRIDGE_AGENT_TOKEN)",
    "  retention-sweep [--state-dir .state/drawbridge-demo]",
    "  agent-request REQUEST_ID --token-file MODE_0600_FILE [--url http://127.0.0.1:4317]",
    "  agent-respond REQUEST_ID --response-file FILE --token-file MODE_0600_FILE [--url ...]",
    "  complete REQUEST_ID --session-token-file MODE_0600_FILE [--url ...]",
    "  status SESSION_REF --session-token-file MODE_0600_FILE [--url ...]",
    "  erase SESSION_REF --session-token-file MODE_0600_FILE [--url ...]",
    "",
    "No command calls a model provider. agent-request/agent-respond are a local custody exchange for the ChatGPT agent stand-in.",
  ].join("\n");
}

function assertAgentResponseReceipt(value: unknown, requestId: string, responseSha256: string): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("agent_response_receipt_binding_invalid");
  const receipt = value as Record<string, unknown>;
  const authority = receipt.authority;
  const authorityKeys = authority && typeof authority === "object" && !Array.isArray(authority)
    ? Object.keys(authority as Record<string, unknown>).sort()
    : [];
  const expectedAuthorityKeys = Object.keys(OBSERVE_ONLY_AUTHORITY).sort();
  const authorityValuesMatch = authority && typeof authority === "object" && !Array.isArray(authority)
    && Object.entries(OBSERVE_ONLY_AUTHORITY).every(([key, expected]) => (authority as Record<string, unknown>)[key] === expected);
  const actionNames = Array.isArray(receipt.actions) ? receipt.actions : [];
  if (receipt.ok !== true
    || receipt.op !== "drawbridge.runtime.submit_agent_response"
    || receipt.requestId !== requestId
    || receipt.responseSha256 !== responseSha256
    || receipt.provider !== CHATGPT_AGENT_PROVIDER
    || !Array.isArray(receipt.errors) || receipt.errors.length !== 0
    || !Array.isArray(receipt.holds) || receipt.holds.length !== 0
    || JSON.stringify(authorityKeys) !== JSON.stringify(expectedAuthorityKeys)
    || !authorityValuesMatch
    || !actionNames.some((action) => action === "validated_content_addressed_agent_exchange"
      || action === "duplicate_response_noop"
      || action === "duplicate_completed_response_noop")) {
    throw new Error("agent_response_receipt_binding_invalid");
  }
}

function requireId(value: string | undefined, name: string): string {
  if (!value || !/^[0-9a-f]{64}$/.test(value)) throw new Error(`${name}_sha256_required`);
  return value;
}

function baseUrl(flags: Map<string, string>): string {
  return (flags.get("url") ?? "http://127.0.0.1:4317").replace(/\/$/u, "");
}

function custodyToken(flags: Map<string, string>): string {
  if (flags.has("token")) throw new Error("secret_argv_forbidden");
  const value = flags.get("token-file")
    ? readCustodiedTokenFile(flags.get("token-file") as string, "agent_custody_token")
    : process.env.DRAWBRIDGE_AGENT_TOKEN;
  if (!value || Buffer.byteLength(value) < 32) throw new Error("agent_custody_token_minimum_32_bytes_required");
  return value;
}

function sessionCapability(flags: Map<string, string>): string {
  if (flags.has("session-token")) throw new Error("secret_argv_forbidden");
  const value = flags.get("session-token-file")
    ? readCustodiedTokenFile(flags.get("session-token-file") as string, "session_capability")
    : process.env.DRAWBRIDGE_SESSION_CAPABILITY;
  if (!value || !/^[0-9a-f]{64}$/.test(value)) throw new Error("session_capability_sha256_required");
  return value;
}

function decodeUtf8(bytes: Buffer): string {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { throw new Error("response_file_utf8_required"); }
}

interface CustodiedResponseFile {
  descriptor: number;
  path: string;
  bytes: Buffer;
  device: number;
  inode: number;
}

function validateResponseAncestors(path: string): void {
  const parent = dirname(path);
  const root = parse(parent).root;
  let current = root;
  for (const segment of parent.slice(root.length).split("/").filter(Boolean)) {
    current = join(current, segment);
    const status = lstatSync(current);
    if (status.isSymbolicLink()) throw new Error("response_file_ancestor_symlink_forbidden");
    if (!status.isDirectory()) throw new Error("response_file_ancestor_directory_required");
  }
}

function readCustodiedTokenFile(inputPath: string, label: string): string {
  const path = resolve(inputPath);
  validateResponseAncestors(path);
  const pathStatus = lstatSync(path);
  if (pathStatus.isSymbolicLink() || !pathStatus.isFile()) throw new Error(`${label}_file_regular_required`);
  let descriptor: number;
  try { descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW); }
  catch { throw new Error(`${label}_file_unsafe`); }
  try {
    const status = fstatSync(descriptor);
    const uid = process.getuid?.();
    if (!status.isFile() || status.dev !== pathStatus.dev || status.ino !== pathStatus.ino) throw new Error(`${label}_file_identity_changed`);
    if (uid !== undefined && status.uid !== uid) throw new Error(`${label}_file_owner_required`);
    if ((status.mode & 0o777) !== 0o600) throw new Error(`${label}_file_mode_0600_required`);
    if (status.nlink !== 1) throw new Error(`${label}_file_single_inode_required`);
    if (status.size < 1 || status.size > 4_096) throw new Error(`${label}_file_size_invalid`);
    const value = decodeUtf8(readFileSync(descriptor)).trim();
    validateResponseAncestors(path);
    const current = lstatSync(path);
    if (current.dev !== status.dev || current.ino !== status.ino) throw new Error(`${label}_file_identity_changed`);
    return value;
  } finally { closeSync(descriptor); }
}

function openCustodiedResponseFile(inputPath: string, beforeOpen?: () => void): CustodiedResponseFile {
  const path = resolve(inputPath);
  validateResponseAncestors(path);
  const pathStatus = lstatSync(path);
  if (pathStatus.isSymbolicLink()) throw new Error("response_file_symlink_forbidden");
  if (!pathStatus.isFile()) throw new Error("response_file_regular_required");
  beforeOpen?.();
  let descriptor: number;
  try { descriptor = openSync(path, constants.O_RDWR | constants.O_NOFOLLOW); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ELOOP") throw new Error("response_file_symlink_forbidden");
    throw error;
  }
  try {
    const status = fstatSync(descriptor);
    if (!status.isFile()) throw new Error("response_file_regular_required");
    if (status.dev !== pathStatus.dev || status.ino !== pathStatus.ino) throw new Error("response_file_identity_changed_before_handoff");
    validateResponseAncestors(path);
    const current = lstatSync(path);
    if (current.dev !== status.dev || current.ino !== status.ino) throw new Error("response_file_identity_changed_before_handoff");
    const uid = process.getuid?.();
    if (uid !== undefined && status.uid !== uid) throw new Error("response_file_owner_required");
    if ((status.mode & 0o777) !== 0o600) throw new Error("response_file_mode_0600_required");
    if (status.nlink !== 1) throw new Error("response_file_single_inode_required");
    if (status.size > MAX_AGENT_RESPONSE_BYTES) throw new Error("response_file_too_large");
    return { descriptor, path, bytes: readFileSync(descriptor), device: status.dev, inode: status.ino };
  } catch (error) {
    closeSync(descriptor);
    throw error;
  }
}

function eraseCustodiedResponseFile(file: CustodiedResponseFile): void {
  ftruncateSync(file.descriptor, 0);
  fsyncSync(file.descriptor);
  validateResponseAncestors(file.path);
  const current = lstatSync(file.path);
  if (current.dev !== file.device || current.ino !== file.inode) throw new Error("response_file_identity_changed_after_handoff");
  validateResponseAncestors(file.path);
  unlinkSync(file.path);
  const directory = openSync(dirname(file.path), constants.O_RDONLY);
  try { fsyncSync(directory); } finally { closeSync(directory); }
}

export async function runDrawbridgeCli(args: string[], dependencies: DrawbridgeCliDependencies = {}): Promise<number> {
  const requestJson = dependencies.requestJson ?? requestLoopbackJson;
  const writeOut = dependencies.writeOut ?? ((line: string) => process.stdout.write(`${line}\n`));
  const writeError = dependencies.writeError ?? ((line: string) => process.stderr.write(`${line}\n`));
  try {
    const parsed = parseAndValidateDrawbridgeArguments(args);
    if (parsed.command === "help" || parsed.command === "--help" || parsed.command === "-h") {
      writeOut(help());
      return 0;
    }
    if (parsed.command === "retention-sweep") {
      const stateRoot = resolve(parsed.flags.get("state-dir") ?? ".state/drawbridge-demo");
      const runtime = createDrawbridgeRuntime(stateRoot);
      try {
        const health = runtime.controller.health();
        writeOut(JSON.stringify({
          ...health,
          op: "drawbridge.cli.retention_sweep",
          actions: [...new Set([...(health.actions ?? []), "ran_independent_retention_sweep"])],
          next: health.ok
            ? "Run this command under a supervisor independent from the HTTP runtime; deployment evidence is still required for any wall-clock retention claim."
            : "Heal every named custody or integrity hold before the next supervised sweep.",
        }));
        return health.ok ? 0 : 1;
      } finally {
        runtime.close();
      }
    }
    if (parsed.command === "serve") {
      const port = Number(parsed.flags.get("port") ?? "4317");
      if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error("listen_port_out_of_range");
      const stateRoot = resolve(parsed.flags.get("state-dir") ?? ".state/drawbridge-demo");
      if (parsed.flags.has("token")) throw new Error("secret_argv_forbidden");
      const tokenFile = parsed.flags.get("token-file");
      const environmentToken = process.env.DRAWBRIDGE_AGENT_TOKEN;
      if (!tokenFile && !environmentToken) throw new Error("agent_custody_token_file_or_environment_required");
      const token = tokenFile
        ? readCustodiedTokenFile(tokenFile, "agent_custody_token")
        : environmentToken as string;
      const tokenSource = tokenFile ? "custodied_file" : "environment";
      if (Buffer.byteLength(token) < 32) throw new Error("agent_custody_token_minimum_32_bytes_required");
      const runtime = createDrawbridgeRuntime(stateRoot);
      const server = createDrawbridgeHttpServer({ controller: runtime.controller, agentToken: token });
      await new Promise<void>((resolveListen, rejectListen) => {
        server.once("error", rejectListen);
        server.listen(port, "127.0.0.1", resolveListen);
      });
      writeOut(JSON.stringify({
        op: "drawbridge.cli.serve", ok: true,
        actions: ["started_loopback_http_and_browser_surface"],
        skips: ["model_provider_network_not_called", "local_model_not_called"], errors: [], holds: [],
        metrics: { port, model_provider_network_calls: 0, agent_token_source: tokenSource, agent_token_disclosed: false },
        next: "Open the local control room, submit a prompt, then give the displayed request id to the ChatGPT agent stand-in workflow.",
        authority: OBSERVE_ONLY_AUTHORITY,
        url: `http://127.0.0.1:${port}`,
      }));
      await new Promise<void>((resolveClose) => {
        const close = () => server.close(() => resolveClose());
        process.once("SIGINT", close);
        process.once("SIGTERM", close);
        server.once("close", resolveClose);
      });
      runtime.close();
      return 0;
    }

    const id = requireId(parsed.positional[0], parsed.command.includes("agent") || parsed.command === "complete" ? "request_id" : "session_ref");
    const url = baseUrl(parsed.flags);
    if (parsed.command === "agent-request") {
      const response = await requestJson(`${url}/api/agent/requests/${id}`, {
        headers: { authorization: `Bearer ${custodyToken(parsed.flags)}` },
      });
      writeOut(JSON.stringify(response, null, 2));
      return 0;
    }
    if (parsed.command === "agent-respond") {
      const responseFile = parsed.flags.get("response-file");
      if (!responseFile) throw new Error("response_file_required");
      const file = openCustodiedResponseFile(responseFile, dependencies.beforeResponseFileOpen);
      try {
        const response = decodeUtf8(file.bytes);
        const responseSha256 = createHash("sha256").update(file.bytes).digest("hex");
        const receipt = await requestJson(`${url}/api/agent/responses`, {
          method: "POST",
          headers: { authorization: `Bearer ${custodyToken(parsed.flags)}` },
          body: { requestId: id, provider: CHATGPT_AGENT_PROVIDER, response, responseSha256 },
        });
        assertAgentResponseReceipt(receipt, id, responseSha256);
        eraseCustodiedResponseFile(file);
        writeOut(JSON.stringify(receipt, null, 2));
        return 0;
      } finally {
        closeSync(file.descriptor);
      }
    }
    if (parsed.command === "complete") {
      writeOut(JSON.stringify(await requestJson(`${url}/api/turns/${id}/complete`, {
        method: "POST", body: {}, headers: { "x-drawbridge-session-capability": sessionCapability(parsed.flags) },
      }), null, 2));
      return 0;
    }
    if (parsed.command === "status") {
      writeOut(JSON.stringify(await requestJson(`${url}/api/sessions/${id}`, {
        headers: { "x-drawbridge-session-capability": sessionCapability(parsed.flags) },
      }), null, 2));
      return 0;
    }
    if (parsed.command === "erase") {
      writeOut(JSON.stringify(await requestJson(`${url}/api/sessions/${id}`, {
        method: "DELETE", headers: { "x-drawbridge-session-capability": sessionCapability(parsed.flags) },
      }), null, 2));
      return 0;
    }
    throw new Error("drawbridge_cli_command_unknown");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    writeError(JSON.stringify({
      op: "drawbridge.cli", ok: false, actions: [],
      skips: ["model_provider_network_not_called", "local_model_not_called"],
      errors: [message], holds: ["cli_request_not_completed"],
      metrics: { model_provider_network_calls: 0 },
      next: "Correct the named CLI contract error and retry.", authority: OBSERVE_ONLY_AUTHORITY,
    }));
    return 1;
  }
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  process.exitCode = await runDrawbridgeCli(process.argv.slice(2));
}
