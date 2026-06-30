#!/usr/bin/env node
// Post-build fixes for the compiled CLI in dist/:
//   1. Replace the source shebang (#!/usr/bin/env tsx) on the CLI entry
//      with a Node shebang — the compiled output runs under Node, not tsx.
//   2. Rewrite all relative ESM imports to carry explicit `.js` extensions
//      so Node's native ESM resolver can find them. TypeScript's "bundler"
//      moduleResolution doesn't add extensions; npm consumers run Node ESM
//      directly, which requires them.
//
// Run from package root after `tsc -p tsconfig.build.json`.
import { readFile, writeFile, readdir, stat } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DIST = join(__dirname, "..", "dist");

// Relative import (and dynamic import + export-from + side-effect import)
// without an extension. Negative lookahead skips paths that already have one.
// Covers: `from "./foo"`, `import("./qux")`, `export ... from "../mod"`, and
// `import "./side-effect"` (a bare import with no binding — covered after
// Code Mechanic flagged it as a latent contract gap 2026-06-21).
const PATTERNS = [
  /(from\s+["'])(\.\.?\/[^"']+?)(?<!\.js|\.json|\.mjs)(["'])/g,
  /(import\(\s*["'])(\.\.?\/[^"']+?)(?<!\.js|\.json|\.mjs)(["']\s*\))/g,
  /(export\s+[^;]*\s+from\s+["'])(\.\.?\/[^"']+?)(?<!\.js|\.json|\.mjs)(["'])/g,
  /(import\s+["'])(\.\.?\/[^"']+?)(?<!\.js|\.json|\.mjs)(["'])/g,
];
function addJsExt(s) {
  for (const re of PATTERNS) s = s.replace(re, "$1$2.js$3");
  return s;
}

async function walk(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const e of entries) {
    const full = join(dir, e.name);
    if (e.isDirectory()) await walk(full);
    // Rewrite .js AND .d.ts — declaration files use the same `from "..."`
    // syntax and strict-mode TS consumers (moduleResolution Node16/NodeNext)
    // need the extensions to match the runtime. Code Mechanic flagged this
    // 2026-06-21; without it, every consumer with strict TS sees type errors.
    else if (e.name.endsWith(".js") || e.name.endsWith(".d.ts")) {
      const text = await readFile(full, "utf8");
      let updated = addJsExt(text);
      // Heal #1: shebang on the CLI entry.
      if (full.endsWith("bin/skybridge-cli.js") && updated.startsWith("#!/usr/bin/env tsx")) {
        updated = updated.replace(/^#!\/usr\/bin\/env tsx/, "#!/usr/bin/env node");
      }
      if (updated !== text) await writeFile(full, updated, "utf8");
    }
  }
}

try {
  await stat(DIST);
} catch {
  console.error("postbuild: dist/ not found — run `tsc -p tsconfig.build.json` first");
  process.exit(1);
}
await walk(DIST);
console.log("postbuild: ESM extensions + CLI shebang fixed in dist/");
