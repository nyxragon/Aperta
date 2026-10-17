// Stage 3 e2e, run the sibling-endpoint oracle against the lab's BOLA endpoint.
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { siblingOracleBOLA } from "../src/oracle.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PORT = 5199;
const BASE = `http://localhost:${PORT}`;

const lab = spawn("node", ["server/api.js"], {
  cwd: join(ROOT, "lab"), env: { ...process.env, PORT: String(PORT) }, stdio: "ignore",
});

async function up() {
  for (let i = 0; i < 40; i++) {
    try { const r = await fetch(`${BASE}/login`); if (r.ok || r.status === 404) return; } catch {}
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error("lab did not start");
}

try {
  await up();
  // caller logs in externally and hands the oracle only headers (aperta never logs in)
  const login = async (u) => {
    const r = await fetch(`${BASE}/api/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: u, password: u }) });
    return (await r.json()).token;
  };
  const sess = async (u) => ({ name: u, headers: { Authorization: `Bearer ${await login(u)}` } });
  const res = await siblingOracleBOLA(BASE, {
    objectTemplate: "/api/orders/{param}",
    siblingPath: "/api/me/orders",
    collection: "orders",
    idKey: "id",
    attacker: await sess("alice"),
    victim: await sess("bob"),
  });
  console.log(JSON.stringify(res, null, 2));
} finally {
  lab.kill();
}
