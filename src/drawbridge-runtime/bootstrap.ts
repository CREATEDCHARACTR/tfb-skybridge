import { randomBytes } from "node:crypto";
import {
  closeSync,
  chmodSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeFileSync,
  type Stats,
} from "node:fs";
import { join, parse, resolve } from "node:path";
import type { ShadowExtractionConfig } from "../behavior/extraction/shadow";
import { DrawbridgeRuntimeController } from "./controller";
import { ExternalAgentExchange } from "./exchange";
import { DEFAULT_DEMO_REGIONS, type FrozenRegionEvidenceRegistry } from "./region";
import { RedactedSessionStore } from "./store";

const SECRET = /^[0-9a-f]{64}$/;

interface CustodyAnchor {
  path: string;
  status: Stats;
  kind: "directory" | "file";
  mode: number;
}

export interface DrawbridgeBootstrapOptions {
  now?: () => number;
  exchangeTtlMs?: number;
  regionEvidenceTtlMs?: number;
  receiptTtlMs?: number;
  maxReceipts?: number;
  staleLockMs?: number;
  maxSessions?: number;
  maxPending?: number;
  observerConfig?: Partial<ShadowExtractionConfig>;
  regions?: FrozenRegionEvidenceRegistry;
  attestor?: (payloadDigest: Buffer) => string;
}

function fsyncDirectory(path: string): void {
  const descriptor = openSync(path, constants.O_RDONLY);
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
}

function ensureStateRoot(root: string): Stats {
  const absolute = resolve(root);
  const rootPath = parse(absolute).root;
  let current = rootPath;
  let createdFinal = false;
  for (const segment of absolute.slice(rootPath.length).split("/").filter(Boolean)) {
    current = join(current, segment);
    if (existsSync(current)) {
      const status = lstatSync(current);
      if (status.isSymbolicLink()) {
        throw new Error(current === absolute ? "drawbridge_state_root_symlink_forbidden" : "drawbridge_state_ancestor_symlink_forbidden");
      }
      if (!status.isDirectory()) {
        throw new Error(current === absolute ? "drawbridge_state_root_not_directory" : "drawbridge_state_ancestor_not_directory");
      }
    } else {
      mkdirSync(current, { mode: 0o700 });
      if (current === absolute) createdFinal = true;
    }
  }
  if (createdFinal) chmodSync(absolute, 0o700);
  const status = lstatSync(absolute);
  const uid = process.getuid?.();
  if (uid !== undefined && status.uid !== uid) throw new Error("drawbridge_state_root_owner_required");
  if ((status.mode & 0o777) !== 0o700) throw new Error("drawbridge_state_root_mode_0700_required");
  return status;
}

function directoryAnchor(path: string, status = lstatSync(path)): CustodyAnchor {
  const uid = process.getuid?.();
  if (status.isSymbolicLink() || !status.isDirectory()) throw new Error("drawbridge_custody_directory_invalid");
  if (uid !== undefined && status.uid !== uid) throw new Error("drawbridge_custody_owner_changed");
  if ((status.mode & 0o777) !== 0o700) throw new Error("drawbridge_custody_mode_changed");
  return { path, status, kind: "directory", mode: 0o700 };
}

function fileAnchor(path: string): CustodyAnchor {
  const status = lstatSync(path);
  const uid = process.getuid?.();
  if (status.isSymbolicLink() || !status.isFile() || status.nlink !== 1) throw new Error("drawbridge_custody_file_invalid");
  if (uid !== undefined && status.uid !== uid) throw new Error("drawbridge_custody_owner_changed");
  if ((status.mode & 0o777) !== 0o600) throw new Error("drawbridge_custody_mode_changed");
  return { path, status, kind: "file", mode: 0o600 };
}

function assertAnchor(anchor: CustodyAnchor): void {
  const current = lstatSync(anchor.path);
  const uid = process.getuid?.();
  const kindMatches = anchor.kind === "directory" ? current.isDirectory() : current.isFile() && current.nlink === 1;
  if (current.isSymbolicLink() || !kindMatches || current.dev !== anchor.status.dev || current.ino !== anchor.status.ino) {
    throw new Error("drawbridge_custody_identity_changed");
  }
  if (uid !== undefined && current.uid !== uid) throw new Error("drawbridge_custody_owner_changed");
  if ((current.mode & 0o777) !== anchor.mode) throw new Error("drawbridge_custody_mode_changed");
}

function readSecret(path: string): Buffer {
  const status = lstatSync(path);
  if (status.isSymbolicLink() || !status.isFile()) throw new Error("producer_secret_file_unsafe");
  const uid = process.getuid?.();
  if (uid !== undefined && status.uid !== uid) throw new Error("producer_secret_owner_required");
  if ((status.mode & 0o777) !== 0o600) throw new Error("producer_secret_mode_0600_required");
  if (status.nlink !== 1) throw new Error("producer_secret_single_inode_required");
  let descriptor: number;
  try { descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW); }
  catch { throw new Error("producer_secret_file_unsafe"); }
  try {
    const opened = fstatSync(descriptor);
    if (!opened.isFile() || opened.dev !== status.dev || opened.ino !== status.ino) throw new Error("producer_secret_file_unsafe");
    if (uid !== undefined && opened.uid !== uid) throw new Error("producer_secret_owner_required");
    if ((opened.mode & 0o777) !== 0o600) throw new Error("producer_secret_mode_0600_required");
    if (opened.nlink !== 1) throw new Error("producer_secret_single_inode_required");
    const encoded = readFileSync(descriptor, "utf8").trim();
    if (!SECRET.test(encoded)) throw new Error("producer_secret_contract_invalid");
    return Buffer.from(encoded, "hex");
  } finally { closeSync(descriptor); }
}

function loadOrCreateProducerSecret(root: string): Buffer {
  const path = join(root, ".producer-key");
  if (!existsSync(path)) {
    let descriptor: number | undefined;
    try {
      descriptor = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      writeFileSync(descriptor, `${randomBytes(32).toString("hex")}\n`, "utf8");
      fsyncSync(descriptor);
      closeSync(descriptor);
      descriptor = undefined;
      fsyncDirectory(root);
    } catch (error) {
      if (descriptor !== undefined) closeSync(descriptor);
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
  }
  return readSecret(path);
}

export function createDrawbridgeRuntime(stateRoot: string, options: DrawbridgeBootstrapOptions = {}) {
  const root = resolve(stateRoot);
  const rootAnchor = directoryAnchor(root, ensureStateRoot(root));
  const exchange = new ExternalAgentExchange(join(root, "exchange"), {
    now: options.now,
    ttlMs: options.exchangeTtlMs,
  });
  const producerSecret = loadOrCreateProducerSecret(root);
  const store = new RedactedSessionStore(join(root, "sessions"), {
    now: options.now,
    receiptTtlMs: options.receiptTtlMs,
    maxReceipts: options.maxReceipts,
    staleLockMs: options.staleLockMs,
    maxSessions: options.maxSessions,
    maxPending: options.maxPending,
  });
  const exchangeAnchor = directoryAnchor(exchange.root);
  const storeAnchor = directoryAnchor(store.root);
  const producerKeyAnchor = fileAnchor(join(root, ".producer-key"));
  const custodyCheck = () => {
    assertAnchor(rootAnchor);
    assertAnchor(exchangeAnchor);
    assertAnchor(storeAnchor);
    assertAnchor(producerKeyAnchor);
  };
  custodyCheck();
  const regions = options.regions ?? DEFAULT_DEMO_REGIONS;
  const controller = new DrawbridgeRuntimeController({
    exchange,
    store,
    regions,
    producerSecret,
    now: options.now,
    regionEvidenceTtlMs: options.regionEvidenceTtlMs,
    observerConfig: options.observerConfig,
    attestor: options.attestor,
    custodyCheck,
  });
  return {
    root,
    exchange,
    store,
    regions,
    controller,
    close: () => {
      exchange.close();
      store.close();
    },
  };
}
