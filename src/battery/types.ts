// TFB Battery — types.
//
// The battery runs an app against a capability-injected boundary (BoundaryEnv)
// inside an instrumented, CSP-enforcing sandbox, under adversarial inputs, and
// emits a signed transcript of what actually crossed the boundary. The app never
// gets ambient fetch/storage — it gets a passed-in env, so the sandbox sees and
// gates every crossing. Production swaps the env for the real double-iframe
// bridge; the contract is identical.
import type { BehaviorProfile } from "../proofbay/types";

export type BoundaryKind = "egress" | "script" | "host-message" | "storage";

export interface BoundaryEvent {
  seq: number;
  kind: BoundaryKind;
  host?: string;
  directive?: string;
  capability?: string;
  bytes: number;
  ts: string;
  blocked?: boolean; // recorded but denied by the sandbox
}

export interface Violation {
  kind: "egress-blocked" | "capability-denied";
  detail: string;
  host?: string;
  capability?: string;
  atSeq: number;
}

// The capability-injected boundary an app is written against.
export interface BoundaryEnv {
  fetch(url: string, init?: { method?: string; body?: string }): Promise<{ status: number; text: string }>;
  loadScript(url: string): Promise<void>;
  connect(url: string): { send(data: string): void; close(): void };
  beacon(url: string, data: string): boolean;
  storage: { get(key: string): string | null; set(key: string, value: string): void };
  hostMessage(payload: string): void;
  random(): number; // seeded — deterministic per run
}

export type AppEntry = (env: BoundaryEnv, input: string) => void | Promise<void>;

export interface SandboxPolicy {
  hosts: Set<string>;
  directives: Set<string>;
  capabilities: Set<string>;
}

export interface Payload {
  name: string;
  input: string;
}

export interface RunRecord {
  payload: string;
  seed: number;
  events: BoundaryEvent[];
  violations: Violation[];
  fingerprint: string;
}

export interface BatteryTranscript {
  batteryId: string;
  batteryVersion: string;
  observedEgress: string[];
  behaviorProfile: BehaviorProfile;
  baseline: import("../behavior/baseline").Baseline;
  fingerprint: string;
  fingerprintVariance: number;
  seeds: number[];
  runs: number;
  result: "PASS" | "FAIL";
  violations: Violation[];
  transcriptHash: string;
  signature: string;
}
