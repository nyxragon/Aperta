// Generalization / anti-overfit harness.
// Runs fingerprint + reconstruct over REAL third-party bundles (captured in the wild) that the
// tool has never been tuned on, and reports what it recovers. The bundles are NOT committed
// (OPSEC + they're not ours); paths live in tests/corpus.local.json (gitignored). This is how we
// catch overfitting to our own labs: if numbers are great on labs and zero here, we overfit.
//
// tests/corpus.local.json: [{ "name": "...", "expect": "angular", "path": "/abs/path/to/bundleOrDir" }]
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { reconstruct, fingerprint } from "../src/reconstruct.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const manifestPath = process.argv[2] || join(HERE, "corpus.local.json");
if (!existsSync(manifestPath)) {
  console.error(`no manifest at ${manifestPath}. Create tests/corpus.local.json (gitignored) with`);
  console.error(`  [{"name":"example-angular","expect":"angular","path":"/abs/app_main.js"}]`);
  process.exit(2);
}
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));

const pad = (s, n) => String(s).slice(0, n).padEnd(n);
console.log(pad("name", 22), pad("expect", 11), pad("detected", 11), pad("routes", 8), pad("role-gated", 11), pad("endpoints", 10));
console.log("-".repeat(78));

for (const c of manifest) {
  if (!existsSync(c.path)) { console.log(pad(c.name, 22), "MISSING PATH", c.path); continue; }
  let fp, model;
  try {
    fp = fingerprint(c.path);
    model = reconstruct(c.path);
  } catch (e) {
    console.log(pad(c.name, 22), pad(c.expect || "?", 11), "ERROR:", String(e).slice(0, 40));
    continue;
  }
  const gated = model.routes.filter((r) => r.role).length;
  const fwOk = !c.expect || fp.framework === c.expect ? "" : "  <-- FP MISMATCH";
  console.log(
    pad(c.name, 22), pad(c.expect || "?", 11), pad(fp.framework, 11),
    pad(model.routes.length, 8), pad(gated, 11), pad(model.endpoints.length, 10), fwOk
  );
}
