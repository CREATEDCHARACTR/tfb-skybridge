// A sample agent-native app: a Stripe-checkout view. Witness spans are computed
// from the real file bytes, so the resulting bundle is correct by construction.
import { sha256Hex } from "../crypto";
import type { Artifact } from "./artifact";
import type { Grant, Witness, EgressKind, BehaviorProfile } from "./types";

export interface AppFixture {
  artifact: Artifact;
  grants: Grant[];
  cspPolicy: string[];
  capabilityManifest: string[];
  behaviorProfile: BehaviorProfile;
}

export function sampleApp(): AppFixture {
  const indexJs = [
    "const stripe = Stripe('pk_live_demo');",
    "fetch('https://api.stripe.com/v1/checkout');",
    "import('https://js.stripe.com/v3/');",
  ].join("\n");
  const styleCss = "body{font-family:Inter,system-ui}";

  const artifact: Artifact = new Map([
    ["index.js", Buffer.from(indexJs, "utf8")],
    ["style.css", Buffer.from(styleCss, "utf8")],
  ]);

  const witness = (file: string, origin: string, kind: EgressKind): Witness => {
    const text = artifact.get(file)!.toString("utf8");
    const idx = text.indexOf(origin);
    if (idx < 0) throw new Error(`origin not found in ${file}: ${origin}`);
    const span: [number, number] = [idx, idx + origin.length];
    return {
      srcRef: { file, span, contentHash: sha256Hex(Buffer.from(origin, "utf8")) },
      kind,
      url: origin,
      derivation: `${kind} literal -> ${origin}`,
    };
  };

  const grants: Grant[] = [
    {
      grant: "connect-src https://api.stripe.com",
      witnesses: [witness("index.js", "https://api.stripe.com", "fetch")],
    },
    {
      grant: "script-src https://js.stripe.com",
      witnesses: [witness("index.js", "https://js.stripe.com", "import")],
    },
  ];

  return {
    artifact,
    grants,
    cspPolicy: grants.map((g) => g.grant),
    capabilityManifest: ["network:api.stripe.com", "network:js.stripe.com"],
    // expected runtime mix the battery attests: half egress, quarter script,
    // quarter host-message. The Span treats this as the drift baseline.
    behaviorProfile: {
      kindFreq: { egress: 0.5, script: 0.25, "host-message": 0.25, storage: 0 },
      eventCount: 8,
    },
  };
}
