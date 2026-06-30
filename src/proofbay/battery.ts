// Deterministic stand-in for the instrumented adversarial battery.
//
// The production battery loads the frozen artifact in an instrumented
// double-iframe sandbox and replays adversarial payloads (prompt-injection in
// tool results, malformed inputs, undeclared-domain probes, storage-escape
// attempts), recording a signed transcript. Here we derive a reproducible
// fingerprint + egress set from the artifact and seeds, so that Tier C replay
// is genuinely deterministic and a tampered attestation is caught.
import { sha256Hex } from "../crypto";
import { artifactHash, type Artifact } from "./artifact";

export interface BatteryResult {
  observedEgress: string[];
  fingerprint: string;
  variance: number;
}

export function runBattery(
  artifact: Artifact,
  declaredHosts: string[],
  seeds: number[],
): BatteryResult {
  const base = artifactHash(artifact) + ":" + seeds.join(",");
  return {
    fingerprint: sha256Hex(base).slice(0, 32),
    observedEgress: [...declaredHosts].sort(), // well-behaved app stays in policy
    variance: 0.0,
  };
}
