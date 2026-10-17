// Aperta money-shot demo, the whole thesis in one run, against the bundled lab.
//
//   reconstruct  the stripped SPA bundle -> full surface, incl. hidden /api/admin/*
//   diff         low-priv alice vs admin  -> the surface alice is GATED from (hidden delta)
//   prove        alice vs bob             -> a confirmed BOLA, via the app's own sibling oracle
//
// It drives the SHIPPED CLI (bin/aperta.mjs) exactly as a user would, so the transcript is real.
// The demo harness logs in to MINT the two sessions; in real use you supply those from your proxy
// (Aperta itself never logs in). Run: `npm run demo`  (or `node demo/demo.mjs`).
import { spawn, spawnSync, execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { writeFileSync, mkdtempSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const BIN = join(ROOT, "bin", "aperta.mjs");
const ASSETS = join(ROOT, "lab", "dist", "assets");
const PORT = 5399;
const BASE = `http://localhost:${PORT}`;
const tmp = mkdtempSync(join(tmpdir(), "aperta-demo-"));

const PACE = process.argv.includes("--pace"); // insert readable pauses (for live screen-recording)
const pause = (ms) => (PACE ? new Promise((r) => setTimeout(r, ms)) : Promise.resolve());
const bar = (t) => console.log(`\n\x1b[1m\x1b[36m${"=".repeat(3)} ${t} ${"=".repeat(Math.max(3, 64 - t.length))}\x1b[0m`);
function run(label, cmdArgs) {
  // echo a clean, copy-pasteable command: relative bundle path, bare session filenames
  const show = cmdArgs.map((a) => a.replace(ROOT + "/", "").replace(tmp + "/", "")).join(" ");
  console.log(`\n\x1b[2m$ aperta ${show}\x1b[0m`);
  const r = spawnSync("node", [BIN, ...cmdArgs], { cwd: ROOT, encoding: "utf8" });
  if (r.stdout.trim()) console.log(r.stdout.trimEnd());
  if (r.stderr.trim()) console.log(r.stderr.trimEnd());
  return r;
}
async function waitUp() {
  for (let i = 0; i < 60; i++) {
    try { const r = await fetch(`${BASE}/api/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }); if (r.status) return; } catch {}
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error("lab did not come up");
}
async function login(u, p) {
  const r = await fetch(`${BASE}/api/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: u, password: p }) });
  const j = await r.json();
  return j.token;
}
function session(name, role, token) {
  const f = join(tmp, `${name}.json`);
  writeFileSync(f, JSON.stringify({ name, role, headers: { Authorization: `Bearer ${token}` }, apiBase: "/api" }, null, 2));
  return f;
}

// Build the lab bundle on a fresh clone (dist is gitignored).
if (!existsSync(ASSETS)) {
  bar("BUILD LAB (first run only)");
  execFileSync("npm", ["install"], { cwd: join(ROOT, "lab"), stdio: "inherit" });
  execFileSync("npm", ["run", "build"], { cwd: join(ROOT, "lab"), stdio: "inherit" });
}

const lab = spawn("node", ["server/api.js"], { cwd: join(ROOT, "lab"), env: { ...process.env, PORT: String(PORT) }, stdio: "ignore" });
try {
  await waitUp();

  bar("STAGE 1 - RECONSTRUCT (no session)");
  console.log("The stripped bundle gives up its whole surface, including routes/APIs a low-priv");
  console.log("user never sees. Note the hidden /api/admin/* endpoints - assembled from minified vars,");
  console.log("so a regex JS-miner misses them; Aperta recovers them from the AST.");
  run("reconstruct", ["reconstruct", ASSETS, "--format", "endpoints"]);

  // The demo mints sessions; in real use these come from YOUR proxy history.
  const alice = session("alice", "user", await login("alice", "alice"));
  const bob = session("bob", "user", await login("bob", "bob"));
  const admin = session("admin", "admin", await login("admin", "admin"));

  bar("STAGE 2 - DIFF (low-priv alice vs admin)");
  console.log("Reconstructed surface MINUS what alice can actually reach = the role-gated surface,");
  console.log("isolated. This is the delta no traffic-only tool can see (you never clicked it).");
  run("diff", ["diff", "--base", BASE, "--js", ASSETS, "--session", alice, "--session", admin, "--format", "jsonl"]);

  bar("STAGE 3 - PROVE (attacker alice vs victim bob, sibling oracle)");
  console.log("GET /api/orders/{id} has no owner check. We confirm it NOT with a tuned response-diff");
  console.log("but with a contradiction inside the app: the sibling GET /api/me/orders is the app's");
  console.log("own statement of who owns what. alice pulls an order /api/me/orders attributes to bob,");
  console.log("with own-id=200 and nonexistent=404 controls holding in the same run.");
  run("prove", ["prove", "--base", BASE, "--object", "/api/orders/{param}", "--sibling", "/api/me/orders", "--collection", "orders", "--attacker", alice, "--victim", bob]);

  bar("STAGE 4 - ORACLES (auto-discover where the BOLA oracle applies)");
  console.log("Aperta pairs each object endpoint with its self-scoped sibling list endpoint and");
  console.log("reports applicability honestly. The id format does not matter: the victim's REAL ids");
  console.log("are sourced from the victim's own list, so this is deterministic on uuids/slugs too.");
  run("oracles", ["oracles", "--js", ASSETS, "--format", "text"]);

  bar("ATTACK SURFACE MAP (the one-shot visual)");
  const outHtml = join(ROOT, "demo", "attack-surface-map.html");
  const rep = spawnSync("node", [BIN, "report", "--base", BASE, "--js", ASSETS,
    "--session", alice, "--session", admin, "--prove", "--attacker", alice, "--victim", bob], { cwd: ROOT, encoding: "utf8" });
  if (rep.stdout) writeFileSync(outHtml, rep.stdout);
  if (rep.stderr.trim()) console.log(rep.stderr.trimEnd());
  console.log(`\nSelf-contained HTML written: demo/attack-surface-map.html (${(rep.stdout || "").length} bytes)`);

  bar("DONE");
  console.log("low-priv account -> reconstructed hidden /admin* -> proven invisible to that session ->");
  console.log("landed a cross-user BOLA, proven by the app's own sibling. No LLM in the decision path.");
} finally {
  lab.kill();
}
