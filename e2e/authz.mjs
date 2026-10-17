// Prove the HTTP-only multi-identity authz diff is framework-agnostic: run it against BOTH the
// React lab and the Angular lab with the SAME code, caller-supplied sessions, no browser.
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { reconstruct } from "../src/reconstruct.mjs";
import { authzDiff } from "../src/authz_probe.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

async function waitUp(base) {
  for (let i = 0; i < 50; i++) {
    try { const r = await fetch(`${base}/api/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }); if (r.status) return; } catch {}
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error("lab not up");
}

async function login(base, u, p) {
  const r = await fetch(`${base}/api/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: u, password: p }) });
  const j = await r.json();
  return j.token;
}

async function runLab(name, dist, distDir, port) {
  const base = `http://localhost:${port}`;
  const lab = spawn("node", ["labs/server.mjs"], { cwd: ROOT, env: { ...process.env, DIST: dist, PORT: String(port) }, stdio: "ignore" });
  try {
    await waitUp(base);
    const model = reconstruct(join(ROOT, distDir));
    // caller supplies sessions (here: log in to get tokens, then hand Aperta just the headers)
    const aliceTok = await login(base, "alice", "alice");
    const adminTok = await login(base, "admin", "admin");
    const sessions = [
      { name: "alice", role: "user", headers: { Authorization: `Bearer ${aliceTok}` } },
      { name: "admin", role: "admin", headers: { Authorization: `Bearer ${adminTok}` } },
    ];
    const diff = await authzDiff(base, model.endpoints, sessions);
    console.log(`\n=== ${name} (framework-agnostic HTTP authz diff) ===`);
    console.log("endpoints probed:", model.endpoints.map((e) => e.method + " " + e.path).join(", "));
    console.log("HIDDEN from low-priv alice (gated from her, reached by admin):");
    console.log("  " + (diff.perSession.alice.hidden.join("\n  ") || "(none)"));
  } finally {
    lab.kill();
  }
}

await runLab("REACT lab", "lab/dist", "lab/dist/assets", 5205);
await runLab("ANGULAR lab", "labs/angular/dist/angular/browser", "labs/angular/dist/angular/browser", 5206);
