import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  unlinkSync,
  writeFileSync,
  type Stats,
} from "node:fs";
import { basename, join, parse, resolve } from "node:path";
import { isInferenceObservation } from "../behavior/extraction/producer";
import type { DurableTurnReceipt, PendingTurn, RuntimeAuthority, SessionState } from "./types";
import { assertWellFormedUnicode, CHATGPT_AGENT_PROVIDER } from "./types";

const SHA256 = /^[0-9a-f]{64}$/;
const SESSION_KEYS = [
  "capabilityNonce", "generation", "nextSequence", "pending", "receipts", "retiredThroughSequence", "schema",
  "sessionRef", "tenantRef", "writerFenceToken",
].sort();
const PENDING_KEYS = ["createdAtMs", "observation", "promptCommitment", "regionEvidenceExpiresAtMs", "regionEvidenceSha256", "requestExpiresAtMs", "requestId", "sequence"].sort();
const RECEIPT_KEYS = [
  "assessment", "attestationReference", "authority", "completedAtMs", "observation", "outputFingerprint", "promptCommitment",
  "provider", "receiptReference", "regionEvidenceSha256", "requestId", "responseCommitment", "schema", "sequence",
].sort();
const AUTHORITY_KEYS = ["actionCeiling", "activationAuthorized", "authorityGranted", "integrationAuthorized", "productionClaimAuthorized"].sort();
const ASSESSMENT_KEYS = ["authority", "gridSize", "reason", "regionCount", "signalId", "status"].sort();
const RECOVERY_OWNER_KEYS = ["claimId", "createdAtMs", "pid", "schema", "token"].sort();
const STATE_TRANSACTION_KEYS = [
  "candidateDev", "candidateIno", "candidateName", "lockToken", "originalDev", "originalIno", "pid", "priorName",
  "schema", "sessionRef", "stateExisted",
].sort();
const MAX_TIMER_DELAY_MS = 2_147_000_000;
const HARD_SESSION_CEILING = 256;
const HARD_PENDING_CEILING = 128;
const CAPACITY_LOCK_REF = "0".repeat(64);
const INTERNAL_RETIRE = Symbol("drawbridge.session-store.internal-retire");

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function record(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  return JSON.stringify(Object.keys(value).sort()) === JSON.stringify(expected);
}

function safeInt(value: unknown, minimum = 0): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= minimum;
}

function assertAuthority(value: unknown): asserts value is RuntimeAuthority {
  if (!record(value) || !exactKeys(value, AUTHORITY_KEYS)
    || value.authorityGranted !== false || value.actionCeiling !== "OBSERVE_ONLY"
    || value.integrationAuthorized !== false || value.activationAuthorized !== false
    || value.productionClaimAuthorized !== false) {
    throw new Error("session_store_contract_invalid");
  }
}

function assertAssessment(value: unknown): void {
  if (!record(value) || !exactKeys(value, ASSESSMENT_KEYS)
    || !["CANDIDATE_EVIDENCE", "INSUFFICIENT_EVIDENCE"].includes(value.status as string)
    || typeof value.reason !== "string" || !/^[a-z0-9_]{1,128}$/.test(value.reason)
    || value.signalId !== "drawbridge.extraction.region_spread.v1-research"
    || value.authority !== "none" || !safeInt(value.gridSize) || !safeInt(value.regionCount)) {
    throw new Error("session_store_contract_invalid");
  }
}

function assertPending(value: unknown): asserts value is PendingTurn {
  if (!record(value) || !exactKeys(value, PENDING_KEYS)
    || typeof value.requestId !== "string" || !SHA256.test(value.requestId)
    || !safeInt(value.sequence, 1)
    || typeof value.promptCommitment !== "string" || !SHA256.test(value.promptCommitment)
    || !safeInt(value.createdAtMs)
    || !safeInt(value.requestExpiresAtMs) || value.requestExpiresAtMs <= value.createdAtMs
    || typeof value.regionEvidenceSha256 !== "string" || !SHA256.test(value.regionEvidenceSha256)
    || !isInferenceObservation(value.observation)
    || !safeInt(value.regionEvidenceExpiresAtMs) || value.regionEvidenceExpiresAtMs <= value.createdAtMs) {
    throw new Error("session_store_contract_invalid");
  }
  if (BigInt(`0x${value.observation.sequence}`) !== BigInt(value.sequence)) throw new Error("session_store_contract_invalid");
}

function assertReceipt(value: unknown): asserts value is DurableTurnReceipt {
  if (!record(value) || !exactKeys(value, RECEIPT_KEYS)
    || value.schema !== "tfb.drawbridge.runtime_turn_receipt.v2"
    || typeof value.receiptReference !== "string" || !SHA256.test(value.receiptReference)
    || typeof value.requestId !== "string" || !SHA256.test(value.requestId)
    || !safeInt(value.sequence, 1)
    || typeof value.promptCommitment !== "string" || !SHA256.test(value.promptCommitment)
    || typeof value.responseCommitment !== "string" || !SHA256.test(value.responseCommitment)
    || typeof value.outputFingerprint !== "string" || !SHA256.test(value.outputFingerprint)
    || value.provider !== CHATGPT_AGENT_PROVIDER
    || typeof value.regionEvidenceSha256 !== "string" || !SHA256.test(value.regionEvidenceSha256)
    || !isInferenceObservation(value.observation)
    || (value.attestationReference !== null
      && (typeof value.attestationReference !== "string" || !/^attestation-sha256:[0-9a-f]{64}$/.test(value.attestationReference)))
    || !safeInt(value.completedAtMs)) {
    throw new Error("session_store_contract_invalid");
  }
  if (BigInt(`0x${value.observation.sequence}`) !== BigInt(value.sequence)) throw new Error("session_store_contract_invalid");
  assertAssessment(value.assessment);
  assertAuthority(value.authority);
}

function assertSession(value: unknown, expectedRef: string): asserts value is SessionState {
  if (!record(value) || !exactKeys(value, SESSION_KEYS)
    || value.schema !== "tfb.drawbridge.runtime_session.v2"
    || value.sessionRef !== expectedRef || !SHA256.test(expectedRef)
    || typeof value.tenantRef !== "string" || !SHA256.test(value.tenantRef)
    || typeof value.generation !== "string" || !SHA256.test(value.generation)
    || typeof value.capabilityNonce !== "string" || !SHA256.test(value.capabilityNonce)
    || typeof value.writerFenceToken !== "string" || !/^[0-9a-f]{32}$/.test(value.writerFenceToken)
    || !safeInt(value.nextSequence, 1) || !safeInt(value.retiredThroughSequence)
    || value.retiredThroughSequence >= value.nextSequence
    || !Array.isArray(value.pending) || !Array.isArray(value.receipts)) {
    throw new Error("session_store_contract_invalid");
  }
  value.pending.forEach(assertPending);
  value.receipts.forEach(assertReceipt);
  const turns = [...value.pending, ...value.receipts];
  const sequences = new Set(turns.map((turn) => turn.sequence));
  const requestIds = new Set(turns.map((turn) => turn.requestId));
  if (sequences.size !== turns.length || requestIds.size !== turns.length
    || sequences.size !== value.nextSequence - 1 - value.retiredThroughSequence) {
    throw new Error("session_store_contract_invalid");
  }
  for (let sequence = value.retiredThroughSequence + 1; sequence < value.nextSequence; sequence++) {
    if (!sequences.has(sequence)) throw new Error("session_store_contract_invalid");
  }
  const observations = turns.map((turn) => turn.observation);
  if (observations.some((observation) => observation.tenantToken !== observations[0]?.tenantToken
    || observation.sessionToken !== observations[0]?.sessionToken)) {
    throw new Error("session_store_contract_invalid");
  }
}

function hmac(secret: Buffer, domain: string, ...values: string[]): string {
  const digest = createHmac("sha256", secret).update(domain, "utf8");
  for (const value of values) digest.update("\0").update(value.normalize("NFKC"), "utf8");
  return digest.digest("hex");
}

interface LockMetadata {
  pid: number;
  createdAtMs: number;
  token: string;
}

interface RecoveryOwner {
  schema: "tfb.drawbridge.session_lock_recovery_owner.v1";
  claimId: string;
  pid: number;
  createdAtMs: number;
  token: string;
}

interface RecoveryClaim {
  path: string;
  status: Stats;
  ownerPath: string;
  ownerStatus: Stats;
  owner: RecoveryOwner;
  takeoverPath?: string;
  takeoverStatus?: Stats;
}

interface StateTransaction {
  schema: "tfb.drawbridge.session_state_transaction.v1";
  sessionRef: string;
  pid: number;
  lockToken: string;
  candidateName: string;
  candidateDev: string;
  candidateIno: string;
  priorName: string;
  stateExisted: boolean;
  originalDev: string;
  originalIno: string;
}

function lockMetadata(value: unknown): LockMetadata | undefined {
  if (!record(value) || !exactKeys(value, ["createdAtMs", "pid", "token"])
    || !safeInt(value.pid, 1) || !safeInt(value.createdAtMs)
    || typeof value.token !== "string" || !/^[0-9a-f]{32}$/.test(value.token)) return undefined;
  return { pid: value.pid, createdAtMs: value.createdAtMs, token: value.token };
}

function recoveryOwner(value: unknown): RecoveryOwner | undefined {
  if (!record(value) || !exactKeys(value, RECOVERY_OWNER_KEYS)
    || value.schema !== "tfb.drawbridge.session_lock_recovery_owner.v1"
    || typeof value.claimId !== "string" || !SHA256.test(value.claimId)
    || !safeInt(value.pid, 1) || !safeInt(value.createdAtMs)
    || typeof value.token !== "string" || !/^[0-9a-f]{32}$/.test(value.token)) return undefined;
  return value as unknown as RecoveryOwner;
}

function stateTransaction(value: unknown): StateTransaction | undefined {
  if (!record(value) || !exactKeys(value, STATE_TRANSACTION_KEYS)
    || value.schema !== "tfb.drawbridge.session_state_transaction.v1"
    || typeof value.sessionRef !== "string" || !SHA256.test(value.sessionRef)
    || !safeInt(value.pid, 1)
    || typeof value.lockToken !== "string" || !/^[0-9a-f]{32}$/.test(value.lockToken)
    || typeof value.candidateName !== "string"
    || typeof value.priorName !== "string"
    || typeof value.stateExisted !== "boolean"
    || typeof value.candidateDev !== "string" || !/^[0-9]+$/.test(value.candidateDev)
    || typeof value.candidateIno !== "string" || !/^[0-9]+$/.test(value.candidateIno)
    || typeof value.originalDev !== "string" || !/^[0-9]+$/.test(value.originalDev)
    || typeof value.originalIno !== "string" || !/^[0-9]+$/.test(value.originalIno)) return undefined;
  const prefix = `${value.sessionRef}.json.${value.pid}.`;
  if (!value.candidateName.startsWith(prefix) || !/\.tmp$/.test(value.candidateName)
    || !value.priorName.startsWith(prefix) || !/\.prior$/.test(value.priorName)) return undefined;
  return value as unknown as StateTransaction;
}

export interface StoreOptions {
  referenceSecret?: Buffer;
  now?: () => number;
  staleLockMs?: number;
  maxReceipts?: number;
  receiptTtlMs?: number;
  maxSessions?: number;
  maxPending?: number;
  beforeStateCommit?: (lockPath: string) => void;
  beforeRecoveryRetire?: (lockPath: string) => void;
  afterRecoveryFenceCheck?: (lockPath: string) => void;
  afterRecoveryOwnerTakeover?: (ownerPath: string) => void;
  afterStateFenceCheck?: (lockPath: string) => void;
  afterStatePublish?: (lockPath: string) => void;
  beforeCommitMarkerRename?: (markerPath: string) => void;
  afterCommitMarkerRestoreLink?: (markerPath: string, committingPath: string) => void;
}

export interface StartedSessionState {
  state: SessionState;
  sessionCapability: string;
  sessionResumeToken: string;
}

export interface StorePendingBinding {
  requestId: string;
  tenantRef: string;
  sessionRef: string;
  sequence: number;
  promptCommitment: string;
  requestExpiresAtMs: number;
  regionEvidenceSha256: string;
  regionEvidenceExpiresAtMs: number;
}

export interface StoreAudit {
  sessionCount: number;
  pendingCount: number;
  receiptCount: number;
  pendingBindings: StorePendingBinding[];
  receiptRequestIds: string[];
}

export interface AgentRequestRegistration {
  session: { tenantRef: string; sessionRef: string };
  pending?: Pick<PendingTurn, "requestId" | "sequence" | "promptCommitment" | "requestExpiresAtMs" | "regionEvidenceSha256" | "regionEvidenceExpiresAtMs">;
  receipt?: Pick<DurableTurnReceipt, "requestId" | "responseCommitment" | "receiptReference" | "assessment">;
}

function ensureCustodyRoot(root: string, createMissing: boolean): void {
  const absolute = resolve(root);
  const rootPath = parse(absolute).root;
  let current = rootPath;
  let createdFinal = false;
  for (const segment of absolute.slice(rootPath.length).split("/").filter(Boolean)) {
    current = join(current, segment);
    if (existsSync(current)) {
      const status = lstatSync(current);
      if (status.isSymbolicLink()) {
        throw new Error(current === absolute ? "session_store_root_symlink_forbidden" : "session_store_ancestor_symlink_forbidden");
      }
      if (!status.isDirectory()) throw new Error(current === absolute ? "session_store_root_not_directory" : "session_store_ancestor_not_directory");
      if (current === absolute) {
        const uid = process.getuid?.();
        if (uid !== undefined && status.uid !== uid) throw new Error("session_store_root_owner_required");
        if ((status.mode & 0o777) !== 0o700) throw new Error("session_store_root_mode_0700_required");
      }
    } else {
      if (!createMissing) throw new Error("session_store_root_missing");
      mkdirSync(current, { mode: 0o700 });
      if (current === absolute) createdFinal = true;
    }
  }
  if (createdFinal) chmodSync(root, 0o700);
}

export class RedactedSessionStore {
  private readonly referenceSecret: Buffer;
  private readonly now: () => number;
  private readonly staleLockMs: number;
  private readonly maxReceipts: number;
  private readonly receiptTtlMs: number;
  private readonly maxSessions: number;
  private readonly maxPending: number;
  private readonly beforeStateCommit?: (lockPath: string) => void;
  private readonly beforeRecoveryRetire?: (lockPath: string) => void;
  private readonly afterRecoveryFenceCheck?: (lockPath: string) => void;
  private readonly afterRecoveryOwnerTakeover?: (ownerPath: string) => void;
  private readonly afterStateFenceCheck?: (lockPath: string) => void;
  private readonly afterStatePublish?: (lockPath: string) => void;
  private readonly beforeCommitMarkerRename?: (markerPath: string) => void;
  private readonly afterCommitMarkerRestoreLink?: (markerPath: string, committingPath: string) => void;
  private readonly rootIdentity: Pick<Stats, "dev" | "ino">;
  private readonly receiptTimers = new Map<string, ReturnType<typeof setTimeout>>();
  private readonly requestIndex = new Map<string, string>();
  private crashRecoveries = { locks: 0, temporaries: 0 };

  constructor(readonly root: string, options: StoreOptions = {}) {
    this.now = options.now ?? Date.now;
    this.staleLockMs = options.staleLockMs ?? 30_000;
    this.maxReceipts = options.maxReceipts ?? 128;
    this.receiptTtlMs = options.receiptTtlMs ?? 86_400_000;
    this.maxSessions = options.maxSessions ?? HARD_SESSION_CEILING;
    this.maxPending = options.maxPending ?? HARD_PENDING_CEILING;
    this.beforeStateCommit = options.beforeStateCommit;
    this.beforeRecoveryRetire = options.beforeRecoveryRetire;
    this.afterRecoveryFenceCheck = options.afterRecoveryFenceCheck;
    this.afterRecoveryOwnerTakeover = options.afterRecoveryOwnerTakeover;
    this.afterStateFenceCheck = options.afterStateFenceCheck;
    this.afterStatePublish = options.afterStatePublish;
    this.beforeCommitMarkerRename = options.beforeCommitMarkerRename;
    this.afterCommitMarkerRestoreLink = options.afterCommitMarkerRestoreLink;
    if (!Number.isInteger(this.staleLockMs) || this.staleLockMs < 1 || this.staleLockMs > 300_000) {
      throw new Error("session_store_stale_lock_out_of_range");
    }
    if (!Number.isInteger(this.maxReceipts) || this.maxReceipts < 1 || this.maxReceipts > 128) throw new Error("session_store_receipt_ceiling_out_of_range");
    if (!Number.isInteger(this.receiptTtlMs) || this.receiptTtlMs < 1 || this.receiptTtlMs > 2_592_000_000) {
      throw new Error("session_store_receipt_ttl_out_of_range");
    }
    if (!Number.isInteger(this.maxSessions) || this.maxSessions < 1 || this.maxSessions > HARD_SESSION_CEILING) {
      throw new Error("session_store_session_ceiling_out_of_range");
    }
    if (!Number.isInteger(this.maxPending) || this.maxPending < 1 || this.maxPending > HARD_PENDING_CEILING) {
      throw new Error("session_store_pending_ceiling_out_of_range");
    }
    ensureCustodyRoot(root, true);
    const rootStatus = lstatSync(root);
    this.rootIdentity = { dev: rootStatus.dev, ino: rootStatus.ino };
    this.cleanupStateTransactions();
    this.cleanupRecoveryClaims();
    if (this.recoveryFenceNames().length) throw new Error("session_store_recovery_busy");
    this.cleanupDeadOwnerTemporaries();
    if (options.referenceSecret && options.referenceSecret.length < 32) throw new Error("reference_secret_minimum_32_bytes_required");
    this.referenceSecret = options.referenceSecret ? Buffer.from(options.referenceSecret) : this.loadOrCreateReferenceSecret();
    this.sweepExpiredReceipts();
  }

  private assertRootIdentity(): void {
    ensureCustodyRoot(this.root, false);
    const current = lstatSync(this.root);
    if (current.dev !== this.rootIdentity.dev || current.ino !== this.rootIdentity.ino) {
      throw new Error("session_store_root_identity_changed");
    }
  }

  private statePath(sessionRef: string): string { this.assertRootIdentity(); return join(this.root, `${sessionRef}.json`); }
  private lockPath(sessionRef: string): string { this.assertRootIdentity(); return join(this.root, `${sessionRef}.lock`); }

  private identity(tenantId: string, sessionId: string): { tenantRef: string; sessionRef: string } {
    assertWellFormedUnicode(tenantId);
    assertWellFormedUnicode(sessionId);
    if (!tenantId.trim() || !sessionId.trim()) throw new Error("session_identity_required");
    const tenantRef = hmac(this.referenceSecret, "drawbridge:tenant-ref:v2", tenantId);
    const sessionRef = hmac(this.referenceSecret, "drawbridge:session-ref:v2", tenantId, sessionId);
    return { tenantRef, sessionRef };
  }

  sessionIdentity(tenantId: string, sessionId: string): { sessionRef: string; exists: boolean } {
    const { sessionRef } = this.identity(tenantId, sessionId);
    return { sessionRef, exists: existsSync(this.statePath(sessionRef)) };
  }

  private capabilityForState(state: SessionState): string {
    return hmac(this.referenceSecret, "drawbridge:session-capability:v3", state.tenantRef, state.sessionRef, state.generation, state.capabilityNonce);
  }

  private resumeTokenForState(state: SessionState): string {
    return hmac(this.referenceSecret, "drawbridge:session-resume-token:v2", state.tenantRef, state.sessionRef, state.generation);
  }

  private tokenMatches(supplied: string | undefined, expected: string): boolean {
    if (!supplied || !SHA256.test(supplied)) return false;
    const left = Buffer.from(supplied, "utf8");
    const right = Buffer.from(expected, "utf8");
    return left.length === right.length && timingSafeEqual(left, right);
  }

  private sessionCapabilityForState(state: SessionState): string {
    assertSession(state, state.sessionRef);
    return this.capabilityForState(state);
  }

  private sessionResumeTokenForState(state: SessionState): string {
    assertSession(state, state.sessionRef);
    return this.resumeTokenForState(state);
  }

  private sessionCapability(sessionRef: string): string {
    if (!SHA256.test(sessionRef) || !existsSync(this.statePath(sessionRef))) throw new Error("session_not_found");
    return this.capabilityForState(this.loadSessionUnchecked(sessionRef));
  }

  private sessionResumeToken(sessionRef: string): string {
    if (!SHA256.test(sessionRef) || !existsSync(this.statePath(sessionRef))) throw new Error("session_not_found");
    return this.resumeTokenForState(this.loadSessionUnchecked(sessionRef));
  }

  verifySessionCapability(sessionRef: string, supplied: string | undefined): boolean {
    if (!supplied || !SHA256.test(supplied) || !SHA256.test(sessionRef) || !existsSync(this.statePath(sessionRef))) return false;
    try { return this.tokenMatches(supplied, this.sessionCapability(sessionRef)); } catch { return false; }
  }

  verifySessionResumeToken(sessionRef: string, supplied: string | undefined): boolean {
    if (!supplied || !SHA256.test(supplied) || !SHA256.test(sessionRef) || !existsSync(this.statePath(sessionRef))) return false;
    try { return this.tokenMatches(supplied, this.sessionResumeToken(sessionRef)); } catch { return false; }
  }

  private assertSessionResume(state: SessionState, resumeToken: string | undefined): void {
    if (!resumeToken) throw new Error("session_resume_token_required");
    if (!this.tokenMatches(resumeToken, this.resumeTokenForState(state))) throw new Error("session_resume_token_invalid");
  }

  private assertSessionCapability(state: SessionState, sessionCapability: string | undefined): void {
    if (!sessionCapability) throw new Error("session_capability_required");
    if (!this.tokenMatches(sessionCapability, this.capabilityForState(state))) throw new Error("session_capability_invalid");
  }

  private fsyncRoot(): void {
    this.assertRootIdentity();
    const descriptor = openSync(this.root, constants.O_RDONLY);
    try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
  }

  private readCustodied(path: string): string {
    const status = lstatSync(path);
    if (status.isSymbolicLink() || !status.isFile()) throw new Error("session_store_contract_invalid");
    let descriptor: number;
    try { descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW); }
    catch { throw new Error("session_store_contract_invalid"); }
    try {
      if (!fstatSync(descriptor).isFile()) throw new Error("session_store_contract_invalid");
      return readFileSync(descriptor, "utf8");
    } finally { closeSync(descriptor); }
  }

  private writeExclusive(path: string, bytes: string): void {
    const descriptor = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try {
      writeFileSync(descriptor, bytes, "utf8");
      fsyncSync(descriptor);
    } finally { closeSync(descriptor); }
    this.fsyncRoot();
  }

  private writeLockExclusive(path: string, bytes: string): void {
    const temporary = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.locktmp`;
    try {
      this.writeExclusive(temporary, bytes);
      linkSync(temporary, path);
      this.fsyncRoot();
    } finally {
      if (existsSync(temporary)) {
        unlinkSync(temporary);
        this.fsyncRoot();
      }
    }
  }

  private stateTransactionNames(sessionRef?: string): string[] {
    const prefix = sessionRef ?? "[0-9a-f]{64}";
    const pattern = new RegExp(`^${prefix}\\.json\\.[1-9][0-9]*\\.[0-9a-f]{12}\\.txn(?:\\.committing)?(?:\\.takeover)?$`);
    return readdirSync(this.root).filter((name) => pattern.test(name)).sort();
  }

  private readStateTransaction(path: string, expectedLinks = 1): { transaction: StateTransaction; status: Stats } {
    const status = lstatSync(path);
    const uid = process.getuid?.();
    if (status.isSymbolicLink() || !status.isFile() || status.nlink !== expectedLinks
      || (uid !== undefined && status.uid !== uid) || (status.mode & 0o777) !== 0o600) {
      throw new Error("session_store_state_transaction_contract_invalid");
    }
    let parsed: unknown;
    try { parsed = JSON.parse(this.readCustodied(path)) as unknown; }
    catch { throw new Error("session_store_state_transaction_contract_invalid"); }
    const transaction = stateTransaction(parsed);
    const match = /^([0-9a-f]{64})\.json\.([1-9][0-9]*)\.([0-9a-f]{12})\.txn/.exec(basename(path));
    if (!transaction || !match || transaction.sessionRef !== match[1] || transaction.pid !== Number(match[2])
      || transaction.candidateName !== `${match[1]}.json.${match[2]}.${match[3]}.tmp`
      || transaction.priorName !== `${match[1]}.json.${match[2]}.${match[3]}.prior`) {
      throw new Error("session_store_state_transaction_contract_invalid");
    }
    return { transaction, status };
  }

  private statusMatches(status: Stats, dev: string, ino: string): boolean {
    return String(status.dev) === dev && String(status.ino) === ino;
  }

  private rollbackStateTransaction(markerPath: string, markerStatus: Stats, siblingMarkerPaths: string[] = []): void {
    const { transaction, status } = this.readStateTransaction(markerPath, 1 + siblingMarkerPaths.length);
    if (status.dev !== markerStatus.dev || status.ino !== markerStatus.ino) {
      throw new Error("session_store_state_recovery_fence_lost");
    }
    const finalPath = this.statePath(transaction.sessionRef);
    const candidatePath = join(this.root, transaction.candidateName);
    const priorPath = join(this.root, transaction.priorName);
    const finalStatus = existsSync(finalPath) ? lstatSync(finalPath) : undefined;
    const candidateAtFinal = !!finalStatus && this.statusMatches(finalStatus, transaction.candidateDev, transaction.candidateIno);
    const originalAtFinal = !!finalStatus && this.statusMatches(finalStatus, transaction.originalDev, transaction.originalIno);

    if (transaction.stateExisted) {
      if (existsSync(priorPath)) {
        const prior = lstatSync(priorPath);
        if (!this.statusMatches(prior, transaction.originalDev, transaction.originalIno)) {
          throw new Error("session_store_state_recovery_fence_lost");
        }
        if (candidateAtFinal || !finalStatus) renameSync(priorPath, finalPath);
        else if (originalAtFinal) unlinkSync(priorPath);
        else throw new Error("session_store_state_recovery_fence_lost");
      } else if (!originalAtFinal) {
        throw new Error("session_store_state_recovery_prior_missing");
      }
    } else {
      if (existsSync(priorPath)) throw new Error("session_store_state_recovery_fence_lost");
      if (candidateAtFinal) unlinkSync(finalPath);
      else if (finalStatus) throw new Error("session_store_state_recovery_fence_lost");
    }

    if (existsSync(candidatePath)) {
      const candidate = lstatSync(candidatePath);
      if (!this.statusMatches(candidate, transaction.candidateDev, transaction.candidateIno)) {
        throw new Error("session_store_state_recovery_fence_lost");
      }
      unlinkSync(candidatePath);
    }
    const currentMarker = lstatSync(markerPath);
    if (currentMarker.dev !== markerStatus.dev || currentMarker.ino !== markerStatus.ino) {
      throw new Error("session_store_state_recovery_fence_lost");
    }
    for (const siblingMarkerPath of siblingMarkerPaths) {
      const sibling = lstatSync(siblingMarkerPath);
      if (sibling.dev !== markerStatus.dev || sibling.ino !== markerStatus.ino) {
        throw new Error("session_store_state_recovery_fence_lost");
      }
      unlinkSync(siblingMarkerPath);
    }
    unlinkSync(markerPath);
    this.fsyncRoot();
  }

  private cleanupStateTransactions(sessionRef?: string): number {
    let recovered = 0;
    const transactionNames = this.stateTransactionNames(sessionRef);
    const existingTakeovers = transactionNames.filter((name) => name.endsWith(".takeover"));
    if (existingTakeovers.length) throw new Error("session_store_state_recovery_busy");
    const roots = new Set(transactionNames
      .filter((name) => !name.endsWith(".takeover"))
      .map((name) => name.endsWith(".txn.committing") ? name.slice(0, -".committing".length) : name));
    for (const rootName of [...roots].sort()) {
      const basePath = join(this.root, rootName);
      const committingPath = `${basePath}.committing`;
      if (existsSync(basePath) && existsSync(committingPath)) {
        const base = lstatSync(basePath);
        const committing = lstatSync(committingPath);
        if (base.dev !== committing.dev || base.ino !== committing.ino || base.nlink !== 2 || committing.nlink !== 2) {
          throw new Error("session_store_state_transaction_alias_contract_invalid");
        }
        const baseTransaction = this.readStateTransaction(basePath, 2);
        const committingTransaction = this.readStateTransaction(committingPath, 2);
        if (JSON.stringify(baseTransaction.transaction) !== JSON.stringify(committingTransaction.transaction)) {
          throw new Error("session_store_state_transaction_alias_contract_invalid");
        }
        if (this.processAlive(baseTransaction.transaction.pid)) continue;
        const takeoverPath = `${basePath}.takeover`;
        try { linkSync(basePath, takeoverPath); }
        catch (error) {
          if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new Error("session_store_state_recovery_busy");
          if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
          throw error;
        }
        this.fsyncRoot();
        const takeover = this.readStateTransaction(takeoverPath, 3);
        if (takeover.status.dev !== base.dev || takeover.status.ino !== base.ino) {
          throw new Error("session_store_state_recovery_fence_lost");
        }
        const retiredBasePath = `${basePath}.retired`;
        renameSync(basePath, retiredBasePath);
        const retiredBase = lstatSync(retiredBasePath);
        if (retiredBase.dev !== takeover.status.dev || retiredBase.ino !== takeover.status.ino) {
          try {
            linkSync(retiredBasePath, basePath);
            unlinkSync(retiredBasePath);
            this.fsyncRoot();
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
          }
          throw new Error("session_store_state_recovery_fence_lost");
        }
        const retiredCommittingPath = `${committingPath}.retired`;
        renameSync(committingPath, retiredCommittingPath);
        const retiredCommitting = lstatSync(retiredCommittingPath);
        if (retiredCommitting.dev !== takeover.status.dev || retiredCommitting.ino !== takeover.status.ino) {
          try {
            linkSync(retiredCommittingPath, committingPath);
            unlinkSync(retiredCommittingPath);
            this.fsyncRoot();
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
          }
          throw new Error("session_store_state_recovery_fence_lost");
        }
        this.rollbackStateTransaction(takeoverPath, takeover.status, [retiredBasePath, retiredCommittingPath]);
        recovered++;
        continue;
      }

      const markerPath = existsSync(basePath) ? basePath : committingPath;
      const markerStatus = lstatSync(markerPath);
      if (markerStatus.nlink !== 1) throw new Error("session_store_state_transaction_alias_contract_invalid");
      const marker = this.readStateTransaction(markerPath);
      if (this.processAlive(marker.transaction.pid)) continue;
      const takeoverPath = `${markerPath}.takeover`;
      try { linkSync(markerPath, takeoverPath); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new Error("session_store_state_recovery_busy");
        if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
        throw error;
      }
      this.fsyncRoot();
      const takeover = this.readStateTransaction(takeoverPath, 2);
      if (takeover.status.dev !== marker.status.dev || takeover.status.ino !== marker.status.ino) {
        throw new Error("session_store_state_recovery_fence_lost");
      }
      const retiredMarkerPath = `${markerPath}.retired`;
      renameSync(markerPath, retiredMarkerPath);
      const retiredMarker = lstatSync(retiredMarkerPath);
      if (retiredMarker.dev !== takeover.status.dev || retiredMarker.ino !== takeover.status.ino) {
        try {
          linkSync(retiredMarkerPath, markerPath);
          unlinkSync(retiredMarkerPath);
          this.fsyncRoot();
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        }
        throw new Error("session_store_state_recovery_fence_lost");
      }
      this.rollbackStateTransaction(takeoverPath, takeover.status, [retiredMarkerPath]);
      recovered++;
    }
    return recovered;
  }

  private assertNoStateTransaction(sessionRef: string): void {
    if (this.stateTransactionNames(sessionRef).length) throw new Error("session_store_state_recovery_busy");
  }

  private loadOrCreateReferenceSecret(): Buffer {
    const path = join(this.root, ".reference-key");
    if (!existsSync(path)) {
      try { this.writeExclusive(path, `${randomBytes(32).toString("hex")}\n`); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
    }
    const encoded = this.readReferenceSecret(path).trim();
    if (!SHA256.test(encoded)) throw new Error("reference_secret_contract_invalid");
    return Buffer.from(encoded, "hex");
  }

  private readReferenceSecret(path: string): string {
    const status = lstatSync(path);
    if (status.isSymbolicLink() || !status.isFile()) throw new Error("reference_secret_file_unsafe");
    const uid = process.getuid?.();
    if (uid !== undefined && status.uid !== uid) throw new Error("reference_secret_owner_required");
    if ((status.mode & 0o777) !== 0o600) throw new Error("reference_secret_mode_0600_required");
    if (status.nlink !== 1) throw new Error("reference_secret_single_inode_required");
    let descriptor: number;
    try { descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW); }
    catch { throw new Error("reference_secret_file_unsafe"); }
    try {
      const opened = fstatSync(descriptor);
      if (!opened.isFile() || opened.dev !== status.dev || opened.ino !== status.ino) throw new Error("reference_secret_file_unsafe");
      if (uid !== undefined && opened.uid !== uid) throw new Error("reference_secret_owner_required");
      if ((opened.mode & 0o777) !== 0o600) throw new Error("reference_secret_mode_0600_required");
      if (opened.nlink !== 1) throw new Error("reference_secret_single_inode_required");
      return readFileSync(descriptor, "utf8");
    } finally { closeSync(descriptor); }
  }

  private processAlive(pid: number): boolean {
    try { process.kill(pid, 0); return true; }
    catch (error) { return (error as NodeJS.ErrnoException).code === "EPERM"; }
  }

  private lockBytes(path: string): { bytes: string; status: Stats; metadata?: LockMetadata } {
    const status = lstatSync(path);
    const uid = process.getuid?.();
    if (status.isSymbolicLink() || !status.isFile()
      || (uid !== undefined && status.uid !== uid) || (status.mode & 0o777) !== 0o600) {
      throw new Error("session_store_lock_contract_invalid");
    }
    const bytes = this.readCustodied(path);
    let parsed: unknown;
    try { parsed = JSON.parse(bytes) as unknown; } catch { parsed = undefined; }
    return { bytes, status, metadata: lockMetadata(parsed) };
  }

  private recoveryClaimId(sessionRef: string, status: Stats, bytes: string): string {
    return createHash("sha256")
      .update("drawbridge:session-lock-recovery-claim:v1\0", "utf8")
      .update(sessionRef, "utf8")
      .update(`\0${status.dev}\0${status.ino}\0`, "utf8")
      .update(bytes, "utf8")
      .digest("hex");
  }

  private recoveryClaimPath(sessionRef: string, status: Stats, bytes: string): string {
    return join(this.root, `${sessionRef}.recovery.${this.recoveryClaimId(sessionRef, status, bytes)}`);
  }

  private recoveryOwnerPath(claimPath: string): string { return `${claimPath}.owner`; }

  private recoveryRetirePath(lockPath: string, ownerToken: string): string {
    return `${lockPath}.${ownerToken}.retired`;
  }

  private recoveryFenceNames(sessionRef?: string): string[] {
    const prefix = sessionRef ?? "[0-9a-f]{64}";
    const pattern = new RegExp(`^${prefix}(?:\\.recovery\\.[0-9a-f]{64}(?:\\.owner(?:\\.takeover)?)?|\\.lock\\.[0-9a-f]{32}\\.retired)$`);
    return readdirSync(this.root).filter((name) => pattern.test(name)).sort();
  }

  private unlinkClaim(claimPath: string, expected: Stats): void {
    const current = lstatSync(claimPath);
    if (current.dev !== expected.dev || current.ino !== expected.ino) throw new Error("session_store_recovery_fence_lost");
    unlinkSync(claimPath);
  }

  private readRecoveryOwner(path: string, linked = false): { owner: RecoveryOwner; status: Stats } {
    const status = lstatSync(path);
    const uid = process.getuid?.();
    if (status.isSymbolicLink() || !status.isFile() || status.nlink !== (linked ? 2 : 1)
      || (uid !== undefined && status.uid !== uid) || (status.mode & 0o777) !== 0o600) {
      throw new Error("session_store_recovery_owner_contract_invalid");
    }
    let parsed: unknown;
    try { parsed = JSON.parse(this.readCustodied(path)) as unknown; }
    catch { throw new Error("session_store_recovery_owner_contract_invalid"); }
    const owner = recoveryOwner(parsed);
    if (!owner) throw new Error("session_store_recovery_owner_contract_invalid");
    return { owner, status };
  }

  private unlinkRecoveryOwner(path: string, expected: Stats): void {
    const current = lstatSync(path);
    if (current.dev !== expected.dev || current.ino !== expected.ino) throw new Error("session_store_recovery_fence_lost");
    unlinkSync(path);
  }

  private releaseRecoveryClaim(claim: RecoveryClaim): void {
    if (claim.takeoverPath && claim.takeoverStatus) {
      const retiredOwnerPath = `${claim.ownerPath}.${claim.owner.token}.retired`;
      renameSync(claim.ownerPath, retiredOwnerPath);
      const retiredOwner = lstatSync(retiredOwnerPath);
      if (retiredOwner.dev !== claim.takeoverStatus.dev || retiredOwner.ino !== claim.takeoverStatus.ino) {
        try {
          linkSync(retiredOwnerPath, claim.ownerPath);
          unlinkSync(retiredOwnerPath);
          this.fsyncRoot();
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        }
        throw new Error("session_store_recovery_fence_lost");
      }
      unlinkSync(retiredOwnerPath);
      this.unlinkClaim(claim.path, claim.status);
      this.unlinkRecoveryOwner(claim.takeoverPath, claim.takeoverStatus);
    } else {
      this.unlinkClaim(claim.path, claim.status);
      this.unlinkRecoveryOwner(claim.ownerPath, claim.ownerStatus);
    }
    this.fsyncRoot();
  }

  private matchingPublicationTemporary(
    sessionRef: string,
    observed: Stats,
    metadata: LockMetadata | undefined,
  ): string | undefined {
    const matches = readdirSync(this.root).filter((name) => {
      const match = new RegExp(`^${sessionRef}\\.lock\\.([1-9][0-9]*)\\.[0-9a-f]{12}\\.locktmp$`).exec(name);
      if (!match || (metadata && Number(match[1]) !== metadata.pid)) return false;
      const status = lstatSync(join(this.root, name));
      return status.dev === observed.dev && status.ino === observed.ino;
    });
    if (matches.length > 1) throw new Error("session_store_lock_link_contract_invalid");
    return matches[0] ? join(this.root, matches[0]) : undefined;
  }

  private claimLock(
    sessionRef: string,
    lockPath: string,
    observed: Stats,
    bytes: string,
  ): RecoveryClaim {
    const claimPath = this.recoveryClaimPath(sessionRef, observed, bytes);
    const claimId = basename(claimPath).slice(-64);
    const ownerPath = this.recoveryOwnerPath(claimPath);
    const owner: RecoveryOwner = {
      schema: "tfb.drawbridge.session_lock_recovery_owner.v1",
      claimId,
      pid: process.pid,
      createdAtMs: this.now(),
      token: randomBytes(16).toString("hex"),
    };
    try {
      this.writeExclusive(ownerPath, `${JSON.stringify(owner)}\n`);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new Error("session_store_recovery_busy");
      throw error;
    }
    const ownerArtifact = this.readRecoveryOwner(ownerPath);
    try {
      linkSync(lockPath, claimPath);
    } catch (error) {
      this.unlinkRecoveryOwner(ownerPath, ownerArtifact.status);
      this.fsyncRoot();
      if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new Error("session_store_recovery_busy");
      throw error;
    }
    const claim = this.lockBytes(claimPath);
    if (claim.status.dev !== observed.dev || claim.status.ino !== observed.ino || claim.bytes !== bytes) {
      this.unlinkClaim(claimPath, claim.status);
      this.unlinkRecoveryOwner(ownerPath, ownerArtifact.status);
      this.fsyncRoot();
      throw new Error("session_store_recovery_fence_lost");
    }
    this.fsyncRoot();
    return { path: claimPath, status: claim.status, ownerPath, ownerStatus: ownerArtifact.status, owner };
  }

  private assertRecoveryClaimOwned(claim: RecoveryClaim): void {
    const currentClaim = lstatSync(claim.path);
    if (currentClaim.dev !== claim.status.dev || currentClaim.ino !== claim.status.ino) {
      throw new Error("session_store_recovery_fence_lost");
    }
    const currentOwner = this.readRecoveryOwner(claim.ownerPath);
    if (currentOwner.status.dev !== claim.ownerStatus.dev || currentOwner.status.ino !== claim.ownerStatus.ino
      || currentOwner.owner.token !== claim.owner.token || currentOwner.owner.pid !== process.pid) {
      throw new Error("session_store_recovery_fence_lost");
    }
  }

  private retireClaimedLock(
    sessionRef: string,
    lockPath: string,
    claim: RecoveryClaim,
    publicationTemporary: string | undefined,
    invokeRecoveryHook: boolean,
  ): void {
    if (invokeRecoveryHook) this.beforeRecoveryRetire?.(lockPath);
    let current: Stats;
    try { current = lstatSync(lockPath); }
    catch (error) {
      this.releaseRecoveryClaim(claim);
      if ((error as NodeJS.ErrnoException).code === "ENOENT") throw new Error("session_store_recovery_fence_lost");
      throw error;
    }
    const currentClaim = lstatSync(claim.path);
    if (current.dev !== currentClaim.dev || current.ino !== currentClaim.ino
      || currentClaim.dev !== claim.status.dev || currentClaim.ino !== claim.status.ino) {
      this.releaseRecoveryClaim({ ...claim, status: currentClaim });
      throw new Error("session_store_recovery_fence_lost");
    }
    if (invokeRecoveryHook) this.afterRecoveryFenceCheck?.(lockPath);
    const retiredPath = this.recoveryRetirePath(lockPath, claim.owner.token);
    try { renameSync(lockPath, retiredPath); }
    catch (error) {
      this.releaseRecoveryClaim({ ...claim, status: currentClaim });
      if ((error as NodeJS.ErrnoException).code === "ENOENT") throw new Error("session_store_recovery_fence_lost");
      throw error;
    }
    const retired = lstatSync(retiredPath);
    if (retired.dev !== currentClaim.dev || retired.ino !== currentClaim.ino) {
      try {
        linkSync(retiredPath, lockPath);
        unlinkSync(retiredPath);
        this.fsyncRoot();
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new Error("session_store_recovery_fence_lost");
        throw error;
      }
      this.releaseRecoveryClaim({ ...claim, status: currentClaim });
      throw new Error("session_store_recovery_fence_lost");
    }
    if (publicationTemporary) {
      const temporary = lstatSync(publicationTemporary);
      if (temporary.dev !== currentClaim.dev || temporary.ino !== currentClaim.ino) {
        throw new Error("session_store_recovery_fence_lost");
      }
      unlinkSync(publicationTemporary);
      this.crashRecoveries.temporaries++;
    }
    unlinkSync(retiredPath);
    this.releaseRecoveryClaim({ ...claim, status: currentClaim });
    this.fsyncRoot();
    if (invokeRecoveryHook) this.crashRecoveries.locks++;
  }

  private cleanupRecoveryClaims(sessionRef?: string): number {
    let recovered = 0;
    const names = readdirSync(this.root);
    const ids = new Set<string>();
    for (const name of names) {
      const match = /^([0-9a-f]{64})\.recovery\.([0-9a-f]{64})(?:\.owner(?:\.takeover)?)?$/.exec(name);
      if (match && (!sessionRef || match[1] === sessionRef)) ids.add(`${match[1]}:${match[2]}`);
    }
    for (const identity of [...ids].sort()) {
      const [claimSessionRef, claimId] = identity.split(":");
      const claimPath = join(this.root, `${claimSessionRef}.recovery.${claimId}`);
      const ownerPath = this.recoveryOwnerPath(claimPath);
      const takeoverPath = `${ownerPath}.takeover`;
      const takeovers = existsSync(takeoverPath) ? [basename(takeoverPath)] : [];
      if (takeovers.length) throw new Error("session_store_recovery_busy");
      if (!existsSync(ownerPath)) {
        if (existsSync(claimPath)) throw new Error("session_store_recovery_orphaned");
        continue;
      }
      const ownerArtifact = this.readRecoveryOwner(ownerPath);
      if (ownerArtifact.owner.claimId !== claimId) throw new Error("session_store_recovery_owner_contract_invalid");
      if (this.processAlive(ownerArtifact.owner.pid)) continue;
      try { linkSync(ownerPath, takeoverPath); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new Error("session_store_recovery_busy");
        if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
        throw error;
      }
      this.fsyncRoot();
      const takeoverArtifact = this.readRecoveryOwner(takeoverPath, true);
      if (takeoverArtifact.status.dev !== ownerArtifact.status.dev || takeoverArtifact.status.ino !== ownerArtifact.status.ino) {
        throw new Error("session_store_recovery_fence_lost");
      }
      this.afterRecoveryOwnerTakeover?.(ownerPath);
      if (!existsSync(claimPath)) {
        const retiredOwnerPath = `${ownerPath}.${ownerArtifact.owner.token}.retired`;
        renameSync(ownerPath, retiredOwnerPath);
        const retiredOwner = lstatSync(retiredOwnerPath);
        if (retiredOwner.dev !== takeoverArtifact.status.dev || retiredOwner.ino !== takeoverArtifact.status.ino) {
          linkSync(retiredOwnerPath, ownerPath);
          unlinkSync(retiredOwnerPath);
          throw new Error("session_store_recovery_fence_lost");
        }
        unlinkSync(retiredOwnerPath);
        this.unlinkRecoveryOwner(takeoverPath, takeoverArtifact.status);
        this.fsyncRoot();
        recovered++;
        continue;
      }
      const artifact = this.lockBytes(claimPath);
      if (this.recoveryClaimId(claimSessionRef, artifact.status, artifact.bytes) !== claimId) {
        throw new Error("session_store_recovery_claim_contract_invalid");
      }
      const claim: RecoveryClaim = {
        path: claimPath,
        status: artifact.status,
        ownerPath,
        ownerStatus: ownerArtifact.status,
        owner: takeoverArtifact.owner,
        takeoverPath,
        takeoverStatus: takeoverArtifact.status,
      };
      const lockPath = this.lockPath(claimSessionRef);
      const retiredPath = this.recoveryRetirePath(lockPath, claim.owner.token);
      if (existsSync(retiredPath)) {
        const retired = lstatSync(retiredPath);
        if (retired.dev !== artifact.status.dev || retired.ino !== artifact.status.ino) {
          throw new Error("session_store_recovery_fence_lost");
        }
        const temporary = this.matchingPublicationTemporary(claimSessionRef, artifact.status, artifact.metadata);
        if (temporary) unlinkSync(temporary);
        unlinkSync(retiredPath);
        this.releaseRecoveryClaim(claim);
        this.crashRecoveries.locks++;
        recovered++;
        continue;
      }
      if (!existsSync(lockPath)) {
        this.releaseRecoveryClaim(claim);
        recovered++;
        continue;
      }
      const current = lstatSync(lockPath);
      if (current.dev !== artifact.status.dev || current.ino !== artifact.status.ino) {
        this.releaseRecoveryClaim(claim);
        recovered++;
        continue;
      }
      const temporary = this.matchingPublicationTemporary(claimSessionRef, artifact.status, artifact.metadata);
      this.retireClaimedLock(claimSessionRef, lockPath, claim, temporary, true);
      recovered++;
    }
    return recovered;
  }

  private cleanupDeadOwnerTemporaries(): number {
    let recovered = 0;
    let directlyUnlinked = 0;
    for (const name of readdirSync(this.root)) {
      const stateTemporary = /^[0-9a-f]{64}\.json\.([1-9][0-9]*)\.[0-9a-f]{12}\.tmp$/.exec(name);
      const statePrior = /^[0-9a-f]{64}\.json\.([1-9][0-9]*)\.[0-9a-f]{12}\.prior$/.exec(name);
      const lockTemporary = /^[0-9a-f]{64}\.lock\.([1-9][0-9]*)\.[0-9a-f]{12}\.locktmp$/.exec(name);
      const ownerPid = stateTemporary?.[1] ?? statePrior?.[1] ?? lockTemporary?.[1];
      if (!ownerPid || this.processAlive(Number(ownerPid))) continue;
      const path = join(this.root, name);
      const observed = lstatSync(path);
      if (lockTemporary && observed.nlink === 2) {
        const artifact = this.lockBytes(path);
        if (!artifact.metadata || artifact.metadata.pid !== Number(ownerPid)) {
          throw new Error("session_store_lock_link_contract_invalid");
        }
        const sessionRef = name.slice(0, 64);
        const final = this.lockPath(sessionRef);
        if (!existsSync(final)) throw new Error("session_store_lock_link_contract_invalid");
        const finalStatus = lstatSync(final);
        if (finalStatus.dev !== observed.dev || finalStatus.ino !== observed.ino) {
          throw new Error("session_store_lock_link_contract_invalid");
        }
        if (!this.recoverStaleLock(final)) throw new Error("session_store_busy");
        recovered++;
        continue;
      }
      const uid = process.getuid?.();
      if (observed.isSymbolicLink() || !observed.isFile()
        || (uid !== undefined && observed.uid !== uid) || (observed.mode & 0o777) !== 0o600
        || observed.nlink !== 1) throw new Error("session_store_temporary_contract_invalid");
      const current = lstatSync(path);
      if (current.dev !== observed.dev || current.ino !== observed.ino) continue;
      unlinkSync(path);
      recovered++;
      directlyUnlinked++;
    }
    if (recovered) {
      this.fsyncRoot();
      this.crashRecoveries.temporaries += directlyUnlinked;
    }
    return recovered;
  }

  private recoverStaleLock(path: string): boolean {
    try {
      const sessionRef = /^([0-9a-f]{64})\.lock$/.exec(basename(path))?.[1];
      if (!sessionRef) throw new Error("session_store_lock_contract_invalid");
      this.cleanupRecoveryClaims(sessionRef);
      const observed = this.lockBytes(path);
      if (observed.metadata && this.processAlive(observed.metadata.pid)) return false;
      if (!observed.metadata && Date.now() - observed.status.mtimeMs <= this.staleLockMs) return false;
      if (observed.status.nlink > 2) throw new Error("session_store_lock_link_contract_invalid");
      const temporary = observed.status.nlink === 2
        ? this.matchingPublicationTemporary(sessionRef, observed.status, observed.metadata)
        : undefined;
      if (observed.status.nlink === 2 && !temporary) throw new Error("session_store_lock_link_contract_invalid");
      const claim = this.claimLock(sessionRef, path, observed.status, observed.bytes);
      this.retireClaimedLock(sessionRef, path, claim, temporary, true);
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return true;
      throw error;
    }
  }

  private acquireLock(sessionRef: string): { path: string; token: string } {
    const path = this.lockPath(sessionRef);
    const token = randomBytes(16).toString("hex");
    const bytes = `${JSON.stringify({ pid: process.pid, createdAtMs: this.now(), token })}\n`;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        this.cleanupRecoveryClaims(sessionRef);
        if (this.recoveryFenceNames(sessionRef).length) throw new Error("session_store_recovery_busy");
        if (this.stateTransactionNames(sessionRef).length) throw new Error("session_store_state_recovery_busy");
        this.writeLockExclusive(path, bytes);
        this.cleanupRecoveryClaims(sessionRef);
        if (this.recoveryFenceNames(sessionRef).length) throw new Error("session_store_recovery_busy");
        if (this.stateTransactionNames(sessionRef).length) throw new Error("session_store_state_recovery_busy");
        return { path, token };
      } catch (error) {
        if (error instanceof Error && error.message.startsWith("session_store_recovery_")) throw error;
        if ((error as NodeJS.ErrnoException).code !== "EEXIST" || attempt > 0 || !this.recoverStaleLock(path)) {
          throw new Error("session_store_busy");
        }
      }
    }
    throw new Error("session_store_busy");
  }

  private releaseLock(lock: { path: string; token: string }): void {
    try {
      const sessionRef = /^([0-9a-f]{64})\.lock$/.exec(basename(lock.path))?.[1];
      if (!sessionRef) throw new Error("session_store_lock_contract_invalid");
      const observed = this.lockBytes(lock.path);
      if (observed.metadata?.token !== lock.token) throw new Error("session_store_lock_ownership_lost");
      const claim = this.claimLock(sessionRef, lock.path, observed.status, observed.bytes);
      this.retireClaimedLock(sessionRef, lock.path, claim, undefined, false);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }

  private assertLockOwned(lock: { path: string; token: string }): void {
    const observed = this.lockBytes(lock.path);
    if (observed.metadata?.token !== lock.token || observed.metadata.pid !== process.pid) {
      throw new Error("session_store_lock_ownership_lost");
    }
  }

  private withLock<T>(sessionRef: string, work: (lock: { path: string; token: string }) => T): T {
    const lock = this.acquireLock(sessionRef);
    try { return work(lock); } finally { this.releaseLock(lock); }
  }

  private write(state: SessionState, lock: { path: string; token: string }): void {
    state.writerFenceToken = lock.token;
    assertSession(state, state.sessionRef);
    this.assertLockOwned(lock);
    const lockObserved = this.lockBytes(lock.path);
    const commitClaim = this.claimLock(state.sessionRef, lock.path, lockObserved.status, lockObserved.bytes);
    const path = this.statePath(state.sessionRef);
    const nonce = randomBytes(6).toString("hex");
    const temporary = `${path}.${process.pid}.${nonce}.tmp`;
    const prior = `${path}.${process.pid}.${nonce}.prior`;
    const marker = `${path}.${process.pid}.${nonce}.txn`;
    let activeMarker = marker;
    let markerStatus: Stats | undefined;
    let transactionResolved = false;
    try {
      const descriptor = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      try {
        writeFileSync(descriptor, `${JSON.stringify(state, null, 2)}\n`, "utf8");
        fsyncSync(descriptor);
      } finally { closeSync(descriptor); }
      const candidate = lstatSync(temporary);
      const original = existsSync(path) ? lstatSync(path) : undefined;
      const transaction: StateTransaction = {
        schema: "tfb.drawbridge.session_state_transaction.v1",
        sessionRef: state.sessionRef,
        pid: process.pid,
        lockToken: lock.token,
        candidateName: basename(temporary),
        candidateDev: String(candidate.dev),
        candidateIno: String(candidate.ino),
        priorName: basename(prior),
        stateExisted: !!original,
        originalDev: String(original?.dev ?? 0),
        originalIno: String(original?.ino ?? 0),
      };
      this.writeExclusive(marker, `${JSON.stringify(transaction)}\n`);
      markerStatus = lstatSync(marker);
      if (original) {
        linkSync(path, prior);
        const priorStatus = lstatSync(prior);
        if (priorStatus.dev !== original.dev || priorStatus.ino !== original.ino) {
          throw new Error("session_store_state_recovery_fence_lost");
        }
        this.fsyncRoot();
      }
      this.beforeStateCommit?.(lock.path);
      this.assertLockOwned(lock);
      this.assertRecoveryClaimOwned(commitClaim);
      this.afterStateFenceCheck?.(lock.path);
      this.assertLockOwned(lock);
      this.assertRecoveryClaimOwned(commitClaim);
      renameSync(temporary, path);
      this.fsyncRoot();
      this.afterStatePublish?.(lock.path);
      this.assertLockOwned(lock);
      this.assertRecoveryClaimOwned(commitClaim);
      const currentMarker = lstatSync(marker);
      if (!markerStatus || currentMarker.dev !== markerStatus.dev || currentMarker.ino !== markerStatus.ino) {
        throw new Error("session_store_state_recovery_fence_lost");
      }
      const committingMarker = `${marker}.committing`;
      this.beforeCommitMarkerRename?.(marker);
      renameSync(marker, committingMarker);
      activeMarker = committingMarker;
      const committedMarker = lstatSync(committingMarker);
      if (committedMarker.dev !== markerStatus.dev || committedMarker.ino !== markerStatus.ino) {
        try {
          linkSync(committingMarker, marker);
          this.afterCommitMarkerRestoreLink?.(marker, committingMarker);
          unlinkSync(committingMarker);
          activeMarker = marker;
          this.fsyncRoot();
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        }
        throw new Error("session_store_state_recovery_fence_lost");
      }
      unlinkSync(committingMarker);
      this.fsyncRoot();
      if (existsSync(prior)) {
        unlinkSync(prior);
        this.fsyncRoot();
      }
      transactionResolved = true;
    } catch (error) {
      if (markerStatus && existsSync(activeMarker)) {
        this.rollbackStateTransaction(activeMarker, markerStatus);
        transactionResolved = true;
      } else if (existsSync(temporary)) {
        unlinkSync(temporary);
        this.fsyncRoot();
      }
      throw error;
    } finally {
      if (transactionResolved && existsSync(commitClaim.path)) this.releaseRecoveryClaim(commitClaim);
    }
  }

  private updateIndexForState(state: SessionState): void {
    for (const [requestId, sessionRef] of this.requestIndex) {
      if (sessionRef === state.sessionRef) this.requestIndex.delete(requestId);
    }
    for (const turn of [...state.pending, ...state.receipts]) {
      const existing = this.requestIndex.get(turn.requestId);
      if (existing && existing !== state.sessionRef) throw new Error("session_store_request_index_conflict");
      this.requestIndex.set(turn.requestId, state.sessionRef);
    }
  }

  private rebuildRequestIndex(sessions: SessionState[]): void {
    this.requestIndex.clear();
    for (const state of sessions) this.updateIndexForState(state);
  }

  private scheduleReceiptPrune(state: SessionState): void {
    const existing = this.receiptTimers.get(state.sessionRef);
    if (existing) clearTimeout(existing);
    this.receiptTimers.delete(state.sessionRef);
    if (!state.receipts.length) return;
    const expiresAtMs = Math.min(...state.receipts.map((receipt) => receipt.completedAtMs + this.receiptTtlMs + 1));
    const timer = setTimeout(() => {
      this.receiptTimers.delete(state.sessionRef);
      try { this.pruneSession(state.sessionRef); } catch { /* root may have been explicitly erased */ }
    }, Math.min(Math.max(1, expiresAtMs - this.now()), MAX_TIMER_DELAY_MS));
    timer.unref();
    this.receiptTimers.set(state.sessionRef, timer);
  }

  private retireEmptySessionsForCapacity(): void {
    let names = this.sessionFileNames();
    if (names.length < this.maxSessions) return;
    const empty = names
      .map((name) => {
        const sessionRef = name.slice(0, -5);
        const state = this.pruneSession(sessionRef);
        return { sessionRef, state, mtimeMs: lstatSync(this.statePath(sessionRef)).mtimeMs };
      })
      .filter(({ state }) => state.pending.length === 0 && state.receipts.length === 0)
      .sort((left, right) => left.mtimeMs - right.mtimeMs || left.sessionRef.localeCompare(right.sessionRef));
    for (const candidate of empty) {
      if (names.length < this.maxSessions) break;
      if (this.eraseSessionState(candidate.sessionRef, INTERNAL_RETIRE)) names = this.sessionFileNames();
    }
  }

  sweepExpiredReceipts(): { sessions: SessionState[]; receiptsPruned: number } {
    this.assertRootIdentity();
    const before = this.sessionFileNames().reduce((total, name) => {
      try { return total + this.loadSessionUnchecked(name.slice(0, -5)).receipts.length; }
      catch { return total; }
    }, 0);
    const sessions = this.sessionFileNames().map((name) => this.pruneSession(name.slice(0, -5)));
    const after = sessions.reduce((total, state) => total + state.receipts.length, 0);
    this.rebuildRequestIndex(sessions);
    return { sessions, receiptsPruned: before - after };
  }

  reconcileExpiredPending(atMs = this.now()): { requestIds: string[]; pendingRetired: number; sessionsReclaimed: number } {
    this.assertRootIdentity();
    if (!Number.isSafeInteger(atMs) || atMs < 0) throw new Error("session_store_expiry_time_invalid");
    const requestIds: string[] = [];
    let sessionsReclaimed = 0;
    for (const name of this.sessionFileNames()) {
      const sessionRef = name.slice(0, -5);
      try {
        this.withLock(sessionRef, (lock) => {
          if (!existsSync(this.statePath(sessionRef))) return;
          const state = this.loadSessionUnchecked(sessionRef);
          let changed = false;
          state.pending.sort((left, right) => left.sequence - right.sequence);
          while (state.pending.length) {
            const oldest = state.pending[0];
            if (atMs <= oldest.requestExpiresAtMs && atMs <= oldest.regionEvidenceExpiresAtMs) break;
            state.receipts = [];
            state.pending.shift();
            state.retiredThroughSequence = oldest.sequence;
            requestIds.push(oldest.requestId);
            changed = true;
          }
          if (!changed) return;
          if (state.pending.length === 0 && state.receipts.length === 0) {
            unlinkSync(this.statePath(sessionRef));
            this.fsyncRoot();
            const timer = this.receiptTimers.get(sessionRef);
            if (timer) clearTimeout(timer);
            this.receiptTimers.delete(sessionRef);
            for (const [requestId, indexedSessionRef] of this.requestIndex) {
              if (indexedSessionRef === sessionRef) this.requestIndex.delete(requestId);
            }
            sessionsReclaimed++;
            return;
          }
          this.write(state, lock);
          this.updateIndexForState(state);
          this.scheduleReceiptPrune(state);
        });
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
    return { requestIds, pendingRetired: requestIds.length, sessionsReclaimed };
  }

  private pruneReceipts(state: SessionState): boolean {
    let changed = false;
    state.receipts.sort((left, right) => left.sequence - right.sequence);
    while (state.receipts.length) {
      const oldest = state.receipts[0];
      const atFloor = oldest.sequence === state.retiredThroughSequence + 1;
      const expired = this.now() - oldest.completedAtMs > this.receiptTtlMs;
      const overCeiling = state.receipts.length > this.maxReceipts;
      if (!atFloor || (!expired && !overCeiling)) break;
      state.receipts.shift();
      state.retiredThroughSequence = oldest.sequence;
      changed = true;
    }
    return changed;
  }

  private pruneSession(sessionRef: string): SessionState {
    return this.withLock(sessionRef, (lock) => {
      const state = this.loadSessionUnchecked(sessionRef);
      if (this.pruneReceipts(state)) this.write(state, lock);
      this.updateIndexForState(state);
      this.scheduleReceiptPrune(state);
      return clone(state);
    });
  }

  startSession(tenantId: string, sessionId: string, resumeToken?: string): StartedSessionState {
    this.reconcileExpiredPending();
    const { tenantRef, sessionRef } = this.identity(tenantId, sessionId);
    const state = this.withLock(CAPACITY_LOCK_REF, () => {
      if (existsSync(this.statePath(sessionRef))) {
        return this.withLock(sessionRef, (lock) => {
          const state = this.loadSessionUnchecked(sessionRef);
          this.assertSessionResume(state, resumeToken);
          this.pruneReceipts(state);
          state.capabilityNonce = randomBytes(32).toString("hex");
          this.write(state, lock);
          this.updateIndexForState(state);
          this.scheduleReceiptPrune(state);
          return clone(state);
        });
      }
      this.retireEmptySessionsForCapacity();
      if (this.sessionFileNames().length >= this.maxSessions) throw new Error("session_store_capacity_reached");
      return this.withLock(sessionRef, (lock) => {
        if (existsSync(this.statePath(sessionRef))) {
          const existing = this.loadSessionUnchecked(sessionRef);
          this.assertSessionResume(existing, resumeToken);
          this.pruneReceipts(existing);
          existing.capabilityNonce = randomBytes(32).toString("hex");
          this.write(existing, lock);
          this.updateIndexForState(existing);
          this.scheduleReceiptPrune(existing);
          return clone(existing);
        }
        const state: SessionState = {
          schema: "tfb.drawbridge.runtime_session.v2",
          sessionRef,
          tenantRef,
          generation: randomBytes(32).toString("hex"),
          capabilityNonce: randomBytes(32).toString("hex"),
          writerFenceToken: lock.token,
          nextSequence: 1,
          retiredThroughSequence: 0,
          pending: [],
          receipts: [],
        };
        this.write(state, lock);
        return clone(state);
      });
    });
    return {
      state,
      sessionCapability: this.sessionCapabilityForState(state),
      sessionResumeToken: this.sessionResumeTokenForState(state),
    };
  }

  private loadSessionUnchecked(sessionRef: string): SessionState {
    if (!SHA256.test(sessionRef)) throw new Error("session_store_contract_invalid");
    this.assertNoStateTransaction(sessionRef);
    let value: unknown;
    try { value = JSON.parse(this.readCustodied(this.statePath(sessionRef))) as unknown; }
    catch (error) {
      if (error instanceof SyntaxError) throw new Error("session_store_contract_invalid");
      throw error;
    }
    assertSession(value, sessionRef);
    return clone(value);
  }

  loadSession(sessionRef: string, sessionCapability: string): SessionState {
    if (!sessionCapability) throw new Error("session_capability_required");
    return this.withLock(sessionRef, () => {
      const state = this.loadSessionUnchecked(sessionRef);
      this.assertSessionCapability(state, sessionCapability);
      return clone(state);
    });
  }

  addPending(sessionRef: string, pending: PendingTurn, options: {
    sessionCapability: string;
    requireEmptyPending?: boolean;
  }): SessionState {
    if (!options?.sessionCapability) throw new Error("session_capability_required");
    return this.withLock(sessionRef, (lock) => {
      const state = this.loadSessionUnchecked(sessionRef);
      this.assertSessionCapability(state, options.sessionCapability);
      if (state.pending.some((item) => item.requestId === pending.requestId)) return state;
      if (options.requireEmptyPending && state.pending.length > 0) throw new Error("session_pending_turn_requires_recovery");
      if (pending.sequence !== state.nextSequence) throw new Error("session_sequence_conflict");
      if (state.pending.length >= this.maxPending) throw new Error("session_pending_capacity_reached");
      state.pending.push(clone(pending));
      state.nextSequence++;
      this.write(state, lock);
      this.updateIndexForState(state);
      return clone(state);
    });
  }

  complete(
    sessionRef: string,
    requestId: string,
    receipt: DurableTurnReceipt,
    sessionCapability: string,
    commitAtMs = this.now(),
  ): SessionState {
    if (!sessionCapability) throw new Error("session_capability_required");
    return this.withLock(sessionRef, (lock) => {
      const state = this.loadSessionUnchecked(sessionRef);
      this.assertSessionCapability(state, sessionCapability);
      const existing = state.receipts.find((item) => item.requestId === requestId);
      if (existing) {
        if (existing.receiptReference !== receipt.receiptReference) throw new Error("completed_request_conflict");
        return state;
      }
      const pending = state.pending.find((item) => item.requestId === requestId);
      if (!pending) throw new Error("pending_request_not_found");
      const fencedCommitAtMs = Math.max(commitAtMs, this.now());
      if (fencedCommitAtMs > pending.requestExpiresAtMs) throw new Error("request_expired_before_commit");
      if (fencedCommitAtMs > pending.regionEvidenceExpiresAtMs) throw new Error("region_evidence_expired_before_commit");
      if (receipt.requestId !== pending.requestId
        || receipt.sequence !== pending.sequence
        || receipt.promptCommitment !== pending.promptCommitment
        || receipt.regionEvidenceSha256 !== pending.regionEvidenceSha256
        || JSON.stringify(receipt.observation) !== JSON.stringify(pending.observation)
        || receipt.completedAtMs !== commitAtMs) {
        throw new Error("completed_request_binding_conflict");
      }
      const oldestPending = Math.min(...state.pending.map((item) => item.sequence));
      if (pending.sequence !== oldestPending) throw new Error("pending_completion_order_conflict");
      state.pending = state.pending.filter((item) => item.requestId !== requestId);
      state.receipts.push(clone(receipt));
      this.pruneReceipts(state);
      this.write(state, lock);
      this.updateIndexForState(state);
      this.scheduleReceiptPrune(state);
      return clone(state);
    });
  }

  abandonThrough(sessionRef: string, requestId: string, sessionCapability: string): SessionState {
    if (!sessionCapability) throw new Error("session_capability_required");
    return this.withLock(sessionRef, (lock) => {
      const state = this.loadSessionUnchecked(sessionRef);
      this.assertSessionCapability(state, sessionCapability);
      const pending = state.pending.find((item) => item.requestId === requestId);
      if (!pending) throw new Error("pending_request_not_found");
      const oldestPending = Math.min(...state.pending.map((item) => item.sequence));
      if (pending.sequence !== oldestPending) throw new Error("pending_completion_order_conflict");
      state.receipts = [];
      state.pending = state.pending.filter((item) => item.sequence > pending.sequence);
      state.retiredThroughSequence = pending.sequence;
      this.write(state, lock);
      this.updateIndexForState(state);
      this.scheduleReceiptPrune(state);
      return clone(state);
    });
  }

  private findRequestUnchecked(requestId: string): { session: SessionState; pending?: PendingTurn; receipt?: DurableTurnReceipt } | undefined {
    if (!SHA256.test(requestId)) return undefined;
    const sessionRef = this.requestIndex.get(requestId);
    if (!sessionRef) return undefined;
    const state = this.pruneSession(sessionRef);
    const pending = state.pending.find((item) => item.requestId === requestId);
    const receipt = state.receipts.find((item) => item.requestId === requestId);
    if (!pending && !receipt) {
      this.requestIndex.delete(requestId);
      return undefined;
    }
    return { session: state, pending, receipt };
  }

  findRequest(
    requestId: string,
    sessionCapability: string,
  ): { session: SessionState; pending?: PendingTurn; receipt?: DurableTurnReceipt } | undefined {
    if (!sessionCapability) throw new Error("session_capability_required");
    if (!SHA256.test(requestId)) return undefined;
    const sessionRef = this.requestIndex.get(requestId);
    if (!sessionRef) return undefined;
    const state = this.loadSession(sessionRef, sessionCapability);
    const pending = state.pending.find((item) => item.requestId === requestId);
    const receipt = state.receipts.find((item) => item.requestId === requestId);
    return pending || receipt ? { session: state, pending, receipt } : undefined;
  }

  findAgentRequest(requestId: string): AgentRequestRegistration | undefined {
    const found = this.findRequestUnchecked(requestId);
    if (!found) return undefined;
    const pending = found.pending ? {
      requestId: found.pending.requestId,
      sequence: found.pending.sequence,
      promptCommitment: found.pending.promptCommitment,
      requestExpiresAtMs: found.pending.requestExpiresAtMs,
      regionEvidenceSha256: found.pending.regionEvidenceSha256,
      regionEvidenceExpiresAtMs: found.pending.regionEvidenceExpiresAtMs,
    } : undefined;
    const receipt = found.receipt ? {
      requestId: found.receipt.requestId,
      responseCommitment: found.receipt.responseCommitment,
      receiptReference: found.receipt.receiptReference,
      assessment: clone(found.receipt.assessment),
    } : undefined;
    return {
      session: { tenantRef: found.session.tenantRef, sessionRef: found.session.sessionRef },
      pending,
      receipt,
    };
  }

  requestSessionRef(requestId: string): string | undefined {
    return SHA256.test(requestId) ? this.requestIndex.get(requestId) : undefined;
  }

  private listSessions(): SessionState[] {
    return this.sweepExpiredReceipts().sessions.map(clone);
  }

  private eraseSessionState(
    sessionRef: string,
    authority: string | typeof INTERNAL_RETIRE,
  ): SessionState | undefined {
    if (!SHA256.test(sessionRef)) return undefined;
    if (!existsSync(this.statePath(sessionRef))) return undefined;
    return this.withLock(sessionRef, () => {
      if (!existsSync(this.statePath(sessionRef))) return undefined;
      const state = this.loadSessionUnchecked(sessionRef);
      if (authority === INTERNAL_RETIRE) {
        if (state.pending.length || state.receipts.length) throw new Error("session_store_internal_retire_nonempty");
      } else this.assertSessionCapability(state, authority);
      unlinkSync(this.statePath(sessionRef));
      this.fsyncRoot();
      const timer = this.receiptTimers.get(sessionRef);
      if (timer) clearTimeout(timer);
      this.receiptTimers.delete(sessionRef);
      for (const [requestId, indexedSessionRef] of this.requestIndex) {
        if (indexedSessionRef === sessionRef) this.requestIndex.delete(requestId);
      }
      return clone(state);
    });
  }

  eraseSession(sessionRef: string, sessionCapability: string): SessionState | undefined {
    if (!sessionCapability) throw new Error("session_capability_required");
    return this.eraseSessionState(sessionRef, sessionCapability);
  }

  audit(): StoreAudit {
    ensureCustodyRoot(this.root, false);
    this.cleanupRecoveryClaims();
    this.cleanupDeadOwnerTemporaries();
    for (const name of readdirSync(this.root)) {
      if (/^[0-9a-f]{64}\.lock$/.test(name)) this.recoverStaleLock(join(this.root, name));
    }
    const secretPath = join(this.root, ".reference-key");
    if (!SHA256.test(this.readReferenceSecret(secretPath).trim())) throw new Error("reference_secret_contract_invalid");
    const allNames = readdirSync(this.root);
    if (allNames.some((name) => name !== ".reference-key" && !/^[0-9a-f]{64}\.json$/.test(name))) {
      throw new Error("session_store_unexpected_file");
    }
    const names = this.sessionFileNames();
    if (names.length > this.maxSessions) throw new Error("session_store_audit_ceiling_exceeded");
    const sessions = this.sweepExpiredReceipts().sessions;
    const pendingBindings = sessions.flatMap((state) => state.pending.map((pending) => ({
      requestId: pending.requestId,
      tenantRef: state.tenantRef,
      sessionRef: state.sessionRef,
      sequence: pending.sequence,
      promptCommitment: pending.promptCommitment,
      requestExpiresAtMs: pending.requestExpiresAtMs,
      regionEvidenceSha256: pending.regionEvidenceSha256,
      regionEvidenceExpiresAtMs: pending.regionEvidenceExpiresAtMs,
    })));
    return {
      sessionCount: sessions.length,
      pendingCount: sessions.reduce((total, state) => total + state.pending.length, 0),
      receiptCount: sessions.reduce((total, state) => total + state.receipts.length, 0),
      pendingBindings,
      receiptRequestIds: sessions.flatMap((state) => state.receipts.map((receipt) => receipt.requestId)),
    };
  }

  private sessionFileNames(): string[] {
    this.assertRootIdentity();
    return readdirSync(this.root).filter((name) => /^[0-9a-f]{64}\.json$/.test(name)).sort();
  }

  drainCrashRecoveries(): { locks: number; temporaries: number } {
    const recovered = { ...this.crashRecoveries };
    this.crashRecoveries = { locks: 0, temporaries: 0 };
    return recovered;
  }

  close(): void {
    for (const timer of this.receiptTimers.values()) clearTimeout(timer);
    this.receiptTimers.clear();
  }
}
