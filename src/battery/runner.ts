// The battery runner. Drives the app across (payloads x seeds), then aggregates:
// observed egress, behavior profile, a structural fingerprint, fingerprint
// variance (non-determinism under fixed input), and any violations. PASS iff no
// out-of-policy crossing occurred. The transcript is signed; its fields drop
// straight into the Proof Bay's dynamicAttestation.
import { sha256Hex, signBytes, verifyBytes } from "../crypto";
import { canonicalBytes } from "../canonical";
import type { BehaviorProfile, BoundaryKind as PBKind } from "../proofbay/types";
import { Sandbox } from "./sandbox";
import { deriveBaseline } from "../behavior/baseline";
import type {
  AppEntry,
  BoundaryEvent,
  BoundaryKind,
  BatteryTranscript,
  Payload,
  RunRecord,
  SandboxPolicy,
  Violation,
} from "./types";

const KINDS: BoundaryKind[] = ["egress", "script", "host-message", "storage"];

function structuralFingerprint(events: BoundaryEvent[]): string {
  const sig = events
    .map((e) => `${e.kind}:${e.host ?? ""}:${e.directive ?? ""}:${e.capability ?? ""}:${e.blocked ? "x" : ""}`)
    .join("|");
  return sha256Hex(sig).slice(0, 32);
}

function profileOf(events: BoundaryEvent[]): BehaviorProfile {
  const counts: Record<BoundaryKind, number> = { egress: 0, script: 0, "host-message": 0, storage: 0 };
  for (const e of events) counts[e.kind]++;
  const total = events.length || 1;
  const kindFreq = {} as Record<PBKind, number>;
  for (const k of KINDS) kindFreq[k as PBKind] = counts[k] / total;
  return { kindFreq, eventCount: events.length };
}

// Non-determinism under fixed input: for each payload, how often the fingerprint
// disagrees across seeds. 0 for a deterministic app.
function variance(runs: RunRecord[]): number {
  const byPayload = new Map<string, string[]>();
  for (const r of runs) {
    const list = byPayload.get(r.payload) ?? [];
    list.push(r.fingerprint);
    byPayload.set(r.payload, list);
  }
  let worst = 0;
  for (const [, fps] of byPayload) {
    const freq = new Map<string, number>();
    for (const f of fps) freq.set(f, (freq.get(f) ?? 0) + 1);
    const mostCommon = Math.max(...freq.values());
    worst = Math.max(worst, 1 - mostCommon / fps.length);
  }
  return worst;
}

export interface BatteryOptions {
  app: AppEntry;
  policy: SandboxPolicy;
  payloads: Payload[];
  seeds: number[];
  batteryId?: string;
  batteryVersion?: string;
}

export async function runBattery(
  opts: BatteryOptions,
  batteryPrivateKeyPem: string,
): Promise<BatteryTranscript> {
  const runs: RunRecord[] = [];
  for (const payload of opts.payloads) {
    for (const seed of opts.seeds) {
      const sandbox = new Sandbox(opts.policy, seed);
      try {
        await opts.app(sandbox, payload.input);
      } catch {
        // an app that throws still leaves its recorded events/violations
      }
      runs.push({
        payload: payload.name,
        seed,
        events: sandbox.events,
        violations: sandbox.violations,
        fingerprint: structuralFingerprint(sandbox.events),
      });
    }
  }

  // observed (allowed) network destinations: egress + script hosts that passed
  const observed = new Set<string>();
  for (const r of runs) {
    for (const e of r.events) {
      if ((e.kind === "egress" || e.kind === "script") && e.host && !e.blocked) observed.add(e.host);
    }
  }

  const violations: Violation[] = runs.flatMap((r) => r.violations);
  const nominal = runs.find((r) => r.payload === opts.payloads[0]?.name) ?? runs[0];

  const transcript: Omit<BatteryTranscript, "transcriptHash" | "signature"> = {
    batteryId: opts.batteryId ?? "tfb-battery",
    batteryVersion: opts.batteryVersion ?? "1.2.0",
    observedEgress: [...observed].sort(),
    behaviorProfile: profileOf(nominal?.events ?? []),
    baseline: deriveBaseline(nominal?.events ?? []),
    fingerprint: nominal ? nominal.fingerprint : "",
    fingerprintVariance: variance(runs),
    seeds: opts.seeds,
    runs: runs.length,
    result: violations.length === 0 ? "PASS" : "FAIL",
    violations,
  };

  const transcriptHash = sha256Hex(canonicalBytes(transcript));
  const signature = signBytes(Buffer.from(transcriptHash, "hex"), batteryPrivateKeyPem);
  return { ...transcript, transcriptHash, signature };
}

export function verifyTranscript(t: BatteryTranscript, batteryPublicKeyPem: string): boolean {
  const { transcriptHash, signature, ...core } = t;
  if (sha256Hex(canonicalBytes(core)) !== transcriptHash) return false;
  return verifyBytes(Buffer.from(transcriptHash, "hex"), signature, batteryPublicKeyPem);
}
