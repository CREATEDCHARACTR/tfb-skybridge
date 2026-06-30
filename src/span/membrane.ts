// TFB Span — the runtime provenance membrane (core).
//
// observe(event)  records a signed, hash-chained receipt and checks the event
//                 against the admitted envelope (hard constraints). An
//                 out-of-envelope event is a VIOLATION and triggers revocation.
// finalize()      checks soft behavioral drift against the attested profile and,
//                 if exceeded, revokes; returns the signed session head plus any
//                 revocation record.
//
// Hard violations (e.g. egress to an undeclared host) would already be blocked
// by the enforced CSP — the Span's job is to make them visible, attributable,
// and revocable, and to catch the softer drift that static enforcement cannot.
import type {
  AdmissionEnvelope,
  BoundaryEvent,
  Receipt,
  EventVerdict,
  SessionHead,
  SessionVerdict,
  RevocationRecord,
  RevocationBody,
} from "./types";
import { canonicalBytes } from "../canonical";
import { signBytes } from "../crypto";
import { GENESIS, receiptHash, receiptCore } from "./chain";
import { fingerprintHash } from "./fingerprint";
import { buildMonitor } from "../behavior/monitor";

export interface ObserveResult {
  receipt: Receipt;
  verdict: EventVerdict;
}

export class Span {
  readonly sessionId: string;
  readonly identity: string;
  private envelope: AdmissionEnvelope;
  private privateKeyPem: string;

  private receipts: Receipt[] = [];
  private events: BoundaryEvent[] = [];
  private prevHash = GENESIS;
  private violated = false;
  private revocation: RevocationRecord | null = null;

  constructor(
    sessionId: string,
    envelope: AdmissionEnvelope,
    identity: string,
    privateKeyPem: string,
  ) {
    this.sessionId = sessionId;
    this.envelope = envelope;
    this.identity = identity;
    this.privateKeyPem = privateKeyPem;
  }

  private signAndChain(r: Receipt): void {
    r.signature = signBytes(canonicalBytes(receiptCore(r)), this.privateKeyPem);
    this.receipts.push(r);
    this.prevHash = receiptHash(r);
  }

  private inEnvelope(e: BoundaryEvent): { ok: boolean; detail: string } {
    if (e.kind === "egress" || e.kind === "script") {
      if (e.host && !this.envelope.hosts.has(e.host)) {
        return { ok: false, detail: `undeclared host ${e.host}` };
      }
      if (e.directive && !this.envelope.directives.has(e.directive)) {
        return { ok: false, detail: `undeclared directive ${e.directive}` };
      }
    }
    if (e.kind === "storage" && e.capability && !this.envelope.capabilities.has(e.capability)) {
      return { ok: false, detail: `undeclared capability ${e.capability}` };
    }
    return { ok: true, detail: "" };
  }

  private emitRevocation(body: RevocationBody): void {
    const ts = new Date().toISOString();
    const r: Receipt = {
      sessionId: this.sessionId,
      seq: this.receipts.length,
      prevHash: this.prevHash,
      kind: "revocation",
      revocation: body,
      ts,
      signature: "",
    };
    this.signAndChain(r);
    this.revocation = {
      sessionId: this.sessionId,
      artifactHash: this.envelope.artifactHash,
      reason: body.reason,
      atSeq: body.atSeq,
      detail: body.detail,
      ts,
      signature: r.signature,
    };
  }

  observe(event: BoundaryEvent): ObserveResult {
    const r: Receipt = {
      sessionId: this.sessionId,
      seq: this.receipts.length,
      prevHash: this.prevHash,
      kind: "event",
      event,
      ts: event.ts,
      signature: "",
    };
    this.signAndChain(r);
    this.events.push(event);

    const check = this.inEnvelope(event);
    if (!check.ok) {
      if (!this.violated) {
        this.violated = true;
        this.emitRevocation({ reason: "VIOLATION", atSeq: event.seq, detail: check.detail });
      }
      return { receipt: r, verdict: "VIOLATION" };
    }
    return { receipt: r, verdict: "ADMIT_CONTINUE" };
  }

  finalize(): { head: SessionHead; revocation: RevocationRecord | null } {
    let verdict: SessionVerdict = this.violated ? "VIOLATION" : "ADMITTED";

    if (!this.violated) {
      // Run the full behavioral monitor (distribution + sequence + budget) over
      // the session. Mapping: a budget breach (volume exfil / mimicry) is a hard
      // VIOLATION; a distribution or sequence anomaly is DRIFT. This is what lets
      // the Span catch the on-distribution byte-exfil that distribution alone
      // would wave through.
      const monitor = buildMonitor(this.envelope.baseline);
      for (const e of this.events) monitor.observe(e);
      const v = monitor.finalize();
      if (v.status === "FLAG") {
        const flagged = v.signals.filter((s) => s.status === "FLAG");
        const budgetHit = flagged.some((s) => s.detector === "budget");
        const detail = flagged.map((s) => `${s.detector}: ${s.reason}`).join("; ");
        if (budgetHit) {
          verdict = "VIOLATION";
          this.emitRevocation({ reason: "VIOLATION", atSeq: this.events.length, detail });
        } else {
          verdict = "DRIFT";
          const dist = flagged.find((s) => s.detector === "distribution");
          this.emitRevocation({
            reason: "DRIFT",
            atSeq: this.events.length,
            detail,
            driftDistance: dist?.score,
          });
        }
      }
    }

    const head: SessionHead = {
      sessionId: this.sessionId,
      artifactHash: this.envelope.artifactHash,
      count: this.receipts.length,
      headHash: this.prevHash,
      liveFingerprint: fingerprintHash(this.events),
      verdict,
      signature: "",
    };
    head.signature = signBytes(canonicalBytes({ ...head, signature: "" }), this.privateKeyPem);
    return { head, revocation: this.revocation };
  }

  getChain(): Receipt[] {
    return this.receipts;
  }
}
