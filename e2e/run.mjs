// End-to-end Stage 1+2 against the lab: reconstruct -> capture low-priv session -> diff.
// Spawns the lab API server (serves dist/ + the API), runs the pipeline, tears it down.
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { reconstruct } from "../src/reconstruct.mjs";
import { captureSessionContainer } from "../src/session_container.mjs";
import { diff } from "../src/diff.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const PORT = 5199;
const BASE = `http://localhost:${PORT}`;

function startLab() {
  const p = spawn("node", ["server/api.js"], {
    cwd: join(ROOT, "lab"),
    env: { ...process.env, PORT: String(PORT) },
    stdio: "ignore",
  });
  return p;
}

async function waitUp(url, tries = 40) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(url);
      if (r.ok || r.status === 404) return true;
    } catch {}
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error("lab did not come up");
}

const lab = startLab();
try {
  await waitUp(`${BASE}/login`);

  // Stage 1, reconstruct the full model from the stripped bundle.
  const model = reconstruct(join(ROOT, "lab", "dist", "assets"));

  // Stage 2, capture what a low-priv (alice) session actually exercises, probing every
  // reconstructed route to see which ones a guard blocks for her.
  const probeRoutes = model.routes.map((r) => r.path);
  const { exercised, routeStatus } = captureSessionContainer(
    BASE,
    { username: "alice", password: "alice" },
    probeRoutes
  );

  const d = diff(model, exercised, routeStatus);

  console.log("=== RECONSTRUCTED MODEL ===");
  console.log("routes:   ", model.routes.map((r) => `${r.path}${r.role ? ` [${r.role}]` : ""}`).join(", "));
  console.log("endpoints:", model.endpoints.map((e) => `${e.method} ${e.path}`).join(", "));
  console.log("\n=== LOW-PRIV SESSION (alice) EXERCISED ===");
  console.log(d.exercised.join("\n") || "(none)");
  console.log("\n=== HIDDEN SURFACE (reconstructed MINUS exercised) ===");
  console.log("hidden routes:   ", d.hiddenRoutes.map((r) => `${r.path}${r.role ? ` [${r.role}]` : ""}`).join(", ") || "(none)");
  console.log("hidden endpoints:", d.hiddenEndpoints.map((e) => `${e.method} ${e.path}`).join(", ") || "(none)");
} finally {
  lab.kill();
}
