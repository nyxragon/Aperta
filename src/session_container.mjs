// Bridge: run the Python Playwright capture inside the recon container (working chromium),
// return the same {exercised, routeStatus} shape as the native Node backend. The container
// is host-networked, so it reaches a host-run target directly. Dev backend only; swap for
// src/session.mjs on a host with `playwright install-deps`.
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));

export function captureSessionContainer(baseURL, identity, routes, container = "vuln-recon") {
  const script = readFileSync(join(__dirname, "session_capture.py"), "utf8");
  const args = ["exec", "-i", container, "python3", "-",
    baseURL, identity.username, identity.password, routes.join(",")];
  const r = spawnSync("docker", args, { input: script, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  if (r.status !== 0) {
    throw new Error("container capture failed: " + (r.stderr || r.stdout || "").slice(-600));
  }
  const line = r.stdout.trim().split("\n").filter(Boolean).pop();
  const data = JSON.parse(line);
  return { exercised: new Set(data.exercised), routeStatus: data.routeStatus };
}
