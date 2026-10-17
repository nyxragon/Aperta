// Generate an asciinema v2 recording (.cast) of the money-shot demo WITHOUT needing asciinema.
// Runs `node demo/demo.mjs`, captures its coloured output, and writes demo/money-shot.cast with
// readable per-line pacing (longer pause at each section banner). Convert to GIF with one binary:
//   agg demo/money-shot.cast demo/money-shot.gif
// (agg = the asciinema GIF generator; demo/record-gif.sh fetches it if you don't have it.)
import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(ROOT, "demo", "money-shot.cast");

const res = spawnSync("node", [join(ROOT, "demo", "demo.mjs")], { cwd: ROOT, encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
const text = (res.stdout || "") + (res.stderr || "");
const lines = text.replace(/\r/g, "").split("\n");

// terminal geometry: widest line (capped) + a little headroom
const width = Math.min(110, Math.max(80, ...lines.map((l) => l.replace(/\x1b\[[0-9;]*m/g, "").length))) + 2;
const header = { version: 2, width, height: 34, timestamp: Math.floor(Date.now() / 1000),
  env: { TERM: "xterm-256color", SHELL: "/bin/bash" }, title: "Aperta money-shot" };

let t = 0.4;
const events = [[t, "o", "\u001b[2m$ npm run demo\u001b[0m\r\n"]];
for (const line of lines) {
  const isBanner = /===/.test(line.replace(/\x1b\[[0-9;]*m/g, ""));
  const isCmd = /^\s*\x1b\[2m\$ aperta/.test(line);
  t += isBanner ? 1.3 : isCmd ? 0.6 : 0.08;
  events.push([Number(t.toFixed(3)), "o", line + "\r\n"]);
}
t += 2.0;
events.push([Number(t.toFixed(3)), "o", ""]); // hold the final frame

writeFileSync(OUT, [JSON.stringify(header), ...events.map((e) => JSON.stringify(e))].join("\n") + "\n");
console.log(`wrote ${OUT} (${events.length} frames, ~${Math.ceil(t)}s, ${width}x34)`);
console.log("make the GIF with:  agg demo/money-shot.cast demo/money-shot.gif");
