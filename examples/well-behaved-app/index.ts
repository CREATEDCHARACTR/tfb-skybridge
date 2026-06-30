// Example app: well-behaved.
// Expected CLI verdict: ✓ ADMIT · Tier B (exit 0)
//
// Deterministic, stays inside the declared envelope, treats input as data.
// Cables will discover the four hosts below; the Battery will run the app
// against PAYLOADS × seeds and find zero violations.
import type { BoundaryEnv } from "../../src/battery/types";

export default async function wellBehavedApp(env: BoundaryEnv, input: string): Promise<void> {
  env.hostMessage("init");
  await env.loadScript("https://js.stripe.com/v3/");
  await env.fetch("https://api.stripe.com/v1/charges", { method: "POST", body: input.slice(0, 64) });
  const sock = env.connect("wss://realtime.acme.io/ws");
  sock.send("subscribe");
  env.beacon("https://metrics.acme.io/collect", "ok");
  env.storage.set("session", "active");
  env.hostMessage("done");
}
