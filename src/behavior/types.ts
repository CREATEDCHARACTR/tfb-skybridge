// TFB Span — behavioral models. A pluggable detector framework operating on the
// same boundary-event substrate the Span already records as receipts. Each
// detector observes the event stream and emits a signal at finalize; the monitor
// aggregates them. Distribution alone is blunt — these add order/timing and
// per-capability budgets, catching evasions that keep the kind-mix intact.

export type BoundaryKind = "egress" | "script" | "host-message" | "storage";

export interface BoundaryEvent {
  seq: number;
  kind: BoundaryKind;
  host?: string;
  capability?: string;
  bytes: number;
  ts: string; // ISO timestamp
}

export type DetectorStatus = "OK" | "FLAG";

export interface DetectorSignal {
  detector: string;
  status: DetectorStatus;
  reason: string;
  score: number; // 0..1, higher = more anomalous
}

export interface Detector {
  readonly name: string;
  observe(event: BoundaryEvent): void;
  finalize(): DetectorSignal;
  reset(): void;
}

export interface MonitorVerdict {
  status: DetectorStatus;     // FLAG if any detector flags
  signals: DetectorSignal[];
}
