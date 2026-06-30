// The instrumented sandbox. Implements BoundaryEnv: every call is recorded as a
// boundary event and gated against the policy. Out-of-policy egress is blocked
// (recorded, not performed) and logged as a violation. A seeded RNG makes each
// run deterministic, which is what lets the store replay the battery (Tier C).
import type {
  BoundaryEnv,
  BoundaryEvent,
  BoundaryKind,
  SandboxPolicy,
  Violation,
} from "./types";

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).host;
  } catch {
    return null;
  }
}

export class Sandbox implements BoundaryEnv {
  readonly events: BoundaryEvent[] = [];
  readonly violations: Violation[] = [];
  private clock = 0;
  private rng: () => number;
  readonly storage: { get(key: string): string | null; set(key: string, value: string): void };
  private store = new Map<string, string>();

  constructor(private policy: SandboxPolicy, seed: number) {
    this.rng = mulberry32(seed);
    this.storage = {
      get: (key) => this.readStorage(key),
      set: (key, value) => this.writeStorage(key, value),
    };
  }

  private push(e: Omit<BoundaryEvent, "seq" | "ts">): BoundaryEvent {
    this.clock += 1000;
    const event: BoundaryEvent = {
      ...e,
      seq: this.events.length,
      ts: new Date(1_700_000_000_000 + this.clock).toISOString(),
    };
    this.events.push(event);
    return event;
  }

  private gateNetwork(url: string, directive: string, kind: BoundaryKind, bytes: number): boolean {
    const host = hostOf(url);
    const ok = !!host && this.policy.hosts.has(host) && this.policy.directives.has(directive);
    const e = this.push({ kind, host: host ?? undefined, directive, bytes, blocked: !ok });
    if (!ok) {
      this.violations.push({
        kind: "egress-blocked",
        detail: `${kind} to undeclared target ${host ?? url} (${directive})`,
        host: host ?? url,
        atSeq: e.seq,
      });
    }
    return ok;
  }

  async fetch(url: string, init?: { method?: string; body?: string }): Promise<{ status: number; text: string }> {
    const ok = this.gateNetwork(url, "connect-src", "egress", init?.body?.length ?? 0);
    return ok ? { status: 200, text: "{}" } : { status: 0, text: "" };
  }

  async loadScript(url: string): Promise<void> {
    this.gateNetwork(url, "script-src", "script", 0);
  }

  connect(url: string): { send(data: string): void; close(): void } {
    const ok = this.gateNetwork(url, "connect-src", "egress", 0);
    const self = this;
    const host = hostOf(url);
    return {
      send(data: string) {
        if (ok) self.push({ kind: "egress", host: host ?? undefined, directive: "connect-src", bytes: data.length });
      },
      close() {},
    };
  }

  beacon(url: string, data: string): boolean {
    return this.gateNetwork(url, "connect-src", "egress", data.length);
  }

  hostMessage(payload: string): void {
    this.push({ kind: "host-message", bytes: payload.length });
  }

  random(): number {
    return this.rng();
  }

  private readStorage(key: string): string | null {
    const ok = this.gateCapability("storage:scoped", 0);
    return ok ? this.store.get(key) ?? null : null;
  }

  private writeStorage(key: string, value: string): void {
    const ok = this.gateCapability("storage:scoped", value.length);
    if (ok) this.store.set(key, value);
  }

  private gateCapability(capability: string, bytes: number): boolean {
    const ok = this.policy.capabilities.has(capability);
    const e = this.push({ kind: "storage", capability, bytes, blocked: !ok });
    if (!ok) {
      this.violations.push({
        kind: "capability-denied",
        detail: `use of undeclared capability ${capability}`,
        capability,
        atSeq: e.seq,
      });
    }
    return ok;
  }
}
