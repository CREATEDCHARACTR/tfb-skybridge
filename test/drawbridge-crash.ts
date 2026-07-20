import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { ShadowExtractionObserver } from "../src/behavior/extraction/shadow";

const childPath = fileURLToPath(new URL("./fixtures/drawbridge-crash-child.ts", import.meta.url));
const child = spawnSync(process.execPath, ["--import", "tsx", childPath], {
  encoding: "utf8",
  timeout: 15_000,
});
const errors: string[] = [];
if (child.status !== 23) errors.push(`crash_child_exit_mismatch:${child.status}`);
let childReceipt: Record<string, unknown> = {};
try {
  childReceipt = JSON.parse(child.stdout) as Record<string, unknown>;
} catch {
  errors.push("crash_child_receipt_invalid");
}
const retainedBeforeCrash = (childReceipt.retention as { metrics?: Record<string, unknown> } | undefined)
  ?.metrics?.retained_events_total;
if (retainedBeforeCrash !== 1) errors.push("crash_child_did_not_retain_before_exit");

const restarted = new ShadowExtractionObserver();
const restartedStatus = restarted.retentionStatus();
if (restartedStatus.metrics.retained_events_total !== 0) errors.push("restart_inherited_process_local_state");
restarted.close();

const result = {
  op: "drawbridge.extraction.crash_restart_probe",
  ok: errors.length === 0,
  actions: ["retained_one_child_observation", "terminated_without_close", "constructed_fresh_observer"],
  skips: [
    "evidence_continuity_not_preserved",
    "erasure_witness_not_emitted_on_crash",
    "multi_worker_state_not_shared",
  ],
  errors,
  metrics: {
    child_exit_code: child.status,
    retained_before_crash: retainedBeforeCrash,
    retained_after_restart: restartedStatus.metrics.retained_events_total,
    restart_state: "empty_by_design",
    persistence_enabled: false,
    erasure_witness_verified: false,
    crash_cleanup_kind: "passive_os_process_state_loss",
    authority_granted: false,
  },
  next: "Treat crash as privacy-preserving state loss and evidence discontinuity; do not claim durable or cross-worker detection continuity.",
};
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
if (!result.ok) process.exit(1);
