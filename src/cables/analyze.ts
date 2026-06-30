// TFB Cables — the static analysis pass.
//
// Scans an app's source for egress constructs, and for each emits a Grant with a
// Witness: the exact byte span in the file plus the sha256 of those bytes. The
// minimal CSP is then exactly the set of witnessed grants — nothing is allowed
// that no construct demonstrably needs. The output is consumed unchanged by the
// Proof Bay issuer/verifier, so "minimality" is derived from source, not asserted.
//
// This is a lexical (pattern-based) analyzer: zero-dependency, robust for the
// common construct shapes. A production build would back it with a real parser
// (AST) to handle dynamically built URLs and aliasing; the witness/CSP contract
// is identical either way.
import { sha256Hex } from "../crypto";
import type { Artifact } from "../proofbay/artifact";
import { directiveForKind } from "../proofbay/types";
import type { Grant, Witness, EgressKind } from "../proofbay/types";


interface Rule {
  label: string;
  re: RegExp;
  urlGroup: number;
  kind: EgressKind;
  files: RegExp;
}

const JS = /\.(js|mjs|ts|html)$/i;
const HTML = /\.html?$/i;
const CSS = /\.(css|html?)$/i;

// Each rule locates an egress construct and captures its URL literal.
const RULES: Rule[] = [
  { label: "fetch()", re: /\bfetch\s*\(\s*(['"`])(https?:\/\/[^'"`)]+)\1/g, urlGroup: 2, kind: "fetch", files: JS },
  { label: "import()", re: /\bimport\s*\(\s*(['"`])(https?:\/\/[^'"`)]+)\1/g, urlGroup: 2, kind: "import", files: JS },
  { label: "import-from", re: /\bfrom\s*(['"`])(https?:\/\/[^'"`]+)\1/g, urlGroup: 2, kind: "import", files: JS },
  { label: "import-bare", re: /\bimport\s+(['"`])(https?:\/\/[^'"`]+)\1/g, urlGroup: 2, kind: "import", files: JS },
  { label: "WebSocket", re: /new\s+WebSocket\s*\(\s*(['"`])(wss?:\/\/[^'"`)]+)\1/g, urlGroup: 2, kind: "connect", files: JS },
  { label: "sendBeacon", re: /\.sendBeacon\s*\(\s*(['"`])(https?:\/\/[^'"`)]+)\1/g, urlGroup: 2, kind: "connect", files: JS },
  { label: "importScripts", re: /importScripts\s*\(\s*(['"`])(https?:\/\/[^'"`)]+)\1/g, urlGroup: 2, kind: "import", files: JS },
  { label: "XHR.open", re: /\.open\s*\(\s*(['"`])[A-Za-z]+\1\s*,\s*(['"`])(https?:\/\/[^'"`)]+)\2/g, urlGroup: 3, kind: "connect", files: JS },
  { label: "<script src>", re: /<script\b[^>]*\bsrc\s*=\s*(['"])(https?:\/\/[^'"]+)\1/gi, urlGroup: 2, kind: "import", files: HTML },
  { label: "<img src>", re: /<img\b[^>]*\bsrc\s*=\s*(['"])(https?:\/\/[^'"]+)\1/gi, urlGroup: 2, kind: "img", files: HTML },
  { label: "<link href>", re: /<link\b[^>]*\bhref\s*=\s*(['"])(https?:\/\/[^'"]+)\1/gi, urlGroup: 2, kind: "style", files: HTML },
  { label: "@import", re: /@import\s+(['"])(https?:\/\/[^'"]+)\1/gi, urlGroup: 2, kind: "style", files: CSS },
  { label: "css url()", re: /url\(\s*(['"]?)(https?:\/\/[^'")]+)\1\s*\)/gi, urlGroup: 2, kind: "style", files: CSS },
];

const byteLen = (s: string): number => Buffer.byteLength(s, "utf8");

export interface Finding {
  grant: string;
  origin: string;
  kind: EgressKind;
  rule: string;
  file: string;
  span: [number, number];
}

export interface AnalysisReport {
  findings: Finding[];
  ignoredRelative: number; // absolute-only: relative/same-origin URLs need no grant
}

export interface AnalyzedApp {
  artifact: Artifact;
  grants: Grant[];
  cspPolicy: string[];
  capabilityManifest: string[];
  report: AnalysisReport;
}

export function analyze(artifact: Artifact): AnalyzedApp {
  const witnessesByGrant = new Map<string, Witness[]>();
  const seen = new Set<string>(); // dedupe a source location across overlapping rules
  const findings: Finding[] = [];
  const hosts = new Set<string>();
  const capabilities = new Set<string>();
  let ignoredRelative = 0;

  for (const [file, buf] of artifact) {
    const text = buf.toString("utf8");

    // capability surface (not CSP, but carried for the Span's envelope)
    if (/\b(localStorage|sessionStorage)\b/.test(text)) capabilities.add("storage:scoped");
    // count relative fetch/import that we intentionally do NOT grant
    const rel = text.match(/\bfetch\s*\(\s*['"`]\/[^'"`]/g);
    if (rel) ignoredRelative += rel.length;

    for (const rule of RULES) {
      if (!rule.files.test(file)) continue;
      rule.re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = rule.re.exec(text)) !== null) {
        const literal = m[rule.urlGroup];
        let url: URL;
        try {
          url = new URL(literal);
        } catch {
          continue;
        }
        const origin = url.origin;
        if (!origin || origin === "null") continue;

        const litCharStart = m.index + m[0].indexOf(literal);
        const byteStart = byteLen(text.slice(0, litCharStart));
        const byteEnd = byteStart + byteLen(literal);
        const locKey = `${file}:${byteStart}:${byteEnd}`;
        if (seen.has(locKey)) continue;
        seen.add(locKey);

        const contentHash = sha256Hex(buf.subarray(byteStart, byteEnd));
        const directive = directiveForKind(rule.kind);
        const grant = `${directive} ${origin}`;
        const witness: Witness = {
          srcRef: { file, span: [byteStart, byteEnd], contentHash },
          kind: rule.kind,
          url: origin,
          derivation: `${rule.label} @ ${file}[${byteStart}:${byteEnd}] requires ${grant}`,
        };

        const list = witnessesByGrant.get(grant) ?? [];
        list.push(witness);
        witnessesByGrant.set(grant, list);
        hosts.add(url.host);
        findings.push({ grant, origin, kind: rule.kind, rule: rule.label, file, span: [byteStart, byteEnd] });
      }
    }
  }

  const grants: Grant[] = [...witnessesByGrant.entries()]
    .map(([grant, witnesses]) => ({ grant, witnesses }))
    .sort((a, b) => a.grant.localeCompare(b.grant));
  const cspPolicy = grants.map((g) => g.grant);
  const capabilityManifest = [
    ...[...hosts].sort().map((h) => `network:${h}`),
    ...[...capabilities].sort(),
  ];

  return {
    artifact,
    grants,
    cspPolicy,
    capabilityManifest,
    report: { findings, ignoredRelative },
  };
}
