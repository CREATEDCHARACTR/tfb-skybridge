// Example app: flaky (in-policy but non-deterministic).
// Expected CLI verdict: ⚠ ADMIT · variance warning (exit 1)
//
// Calls only declared hosts (no violations). But its control flow branches
// on env.random(), so the same input × different seeds produces different
// boundary sequences. The Battery's variance metric goes up; Tier C (sampled
// replay) would reject this even though Tier A/B admit. Stores can admit
// with a warning so the dev can decide whether to fix.

/** @param {import("tfb-skybridge/src/battery/types").BoundaryEnv} env */
export default async function flakyApp(env) {
  env.hostMessage("init");
  await env.fetch("https://api.stripe.com/v1/charges", { body: "{}" });
  if (env.random() > 0.5) env.beacon("https://metrics.acme.io/collect", "maybe");
}
