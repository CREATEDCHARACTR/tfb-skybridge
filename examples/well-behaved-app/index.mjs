// Example app: well-behaved.
// Expected CLI verdict: ✓ ADMIT · Tier B (exit 0)
//
// Deterministic, stays inside the declared envelope, treats input as data.
// Shipped as .mjs (not .ts) because Node refuses to strip TS types from
// files under node_modules/; .mjs runs natively everywhere.

/** @param {import("tfb-skybridge/src/battery/types").BoundaryEnv} env */
export default async function wellBehavedApp(env, input) {
  env.hostMessage("init");
  await env.loadScript("https://js.stripe.com/v3/");
  await env.fetch("https://api.stripe.com/v1/charges", { method: "POST", body: input.slice(0, 64) });
  const sock = env.connect("wss://realtime.acme.io/ws");
  sock.send("subscribe");
  env.beacon("https://metrics.acme.io/collect", "ok");
  env.storage.set("session", "active");
  env.hostMessage("done");
}
