// MCP server (stdio, JSON-RPC 2.0), typed Aperta tools for any MCP client (Cursor, Claude
// Desktop, Cline). Dependency-free: newline-delimited JSON-RPC by hand so the lean core stays
// AST + fetch only. Per ARCHITECTURE: each tool returns a COMPACT summary + an artifact path;
// the raw reconstructed surface is written to a file and never streamed into the model context.
import { writeFileSync, mkdtempSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { reconstruct, fingerprint } from "./reconstruct.mjs";
import { authzDiff, hiddenToJSONL } from "./authz_probe.mjs";
import { siblingOracleBOLA } from "./oracle.mjs";
import { graphqlOracleBOLA } from "./oracle_graphql.mjs";
import { collectionOverReturnBOLA } from "./oracle_collection.mjs";
import { ownerFieldOracleBOLA } from "./oracle_owner.mjs";
import { discoverOracles, applicabilityLine } from "./oracle_discovery.mjs";
import { classifyFindings } from "./authz_matrix.mjs";
import { toHTMLReport } from "./report.mjs";
import { toSARIF, toNucleiTemplate } from "./emit.mjs";

const SERVER = { name: "aperta", version: "0.1.0" };
const ARTIFACTS = mkdtempSync(join(tmpdir(), "aperta-mcp-"));
let artifactSeq = 0;
function writeArtifact(name, data) {
  const p = join(ARTIFACTS, `${++artifactSeq}-${name}`);
  writeFileSync(p, typeof data === "string" ? data : JSON.stringify(data, null, 2));
  return p;
}
// A session arg may be an inline object or a path to a JSON file.
function asSession(s) {
  if (typeof s === "string") return JSON.parse(readFileSync(s, "utf8"));
  return s;
}

const TOOLS = [
  {
    name: "aperta_fingerprint",
    description: "Detect the SPA framework of a JS bundle directory/file (react/angular/vue/nuxt/nextjs/angularjs/svelte/aura).",
    inputSchema: { type: "object", properties: { path: { type: "string", description: "dir or .js file of collected bundles" } }, required: ["path"] },
  },
  {
    name: "aperta_reconstruct",
    description: "Reconstruct the full route + REST + GraphQL surface (incl. hidden role-gated routes) from a stripped bundle. Returns counts + a sample and writes the full surface to an artifact file (path returned). No session needed.",
    inputSchema: { type: "object", properties: { path: { type: "string" }, format: { type: "string", enum: ["json", "openapi"], default: "json" } }, required: ["path"] },
  },
  {
    name: "aperta_diff",
    description: "Runtime multi-identity authorization diff: probe the reconstructed endpoints as each supplied identity and isolate the surface a low-priv identity is gated from but a higher-priv one reaches. Returns per-identity counts + the hidden set, writes JSONL+SARIF artifacts. Probes live (≤1 req/s). Aperta never logs in, supply each identity's auth.",
    inputSchema: {
      type: "object",
      properties: {
        base: { type: "string", description: "target origin, e.g. https://app.example.com" },
        surfacePath: { type: "string", description: "path to a reconstruct --format json/openapi artifact, OR" },
        jsPath: { type: "string", description: "a bundle dir/file to reconstruct inline" },
        sessions: { type: "array", items: { type: "object" }, description: "[{name,role?,headers,apiBase?,traffic?}] or file paths" },
        apiBase: { type: "string", default: "/api" },
        as: { type: "string", description: "which session is the low-priv one to report hidden for (default: first)" },
      },
      required: ["base", "sessions"],
    },
  },
  {
    name: "aperta_prove",
    description: "Prove a BOLA deterministically using the app's own endpoints as the oracle. mode: 'sibling' (per-object GET /x/{id}, default), 'auto' (discover every object+sibling pair from a surface and prove each), 'graphql' (opaque global-id oracle, otherwise UNREACHABLE over MCP), 'overreturn' (an unscoped collection list leaking other users' rows). A CONFIRMED result carries the gate tape + a nuclei template path; reportable is true ONLY for CONFIRMED (never promote a NOT-CONFIRMED / CORRECTLY-SCOPED / INAPPLICABLE).",
    inputSchema: {
      type: "object",
      properties: {
        base: { type: "string" },
        mode: { type: "string", enum: ["sibling", "auto", "graphql", "overreturn", "owner-field"], default: "sibling" },
        ownId: { type: "string", description: "owner-field mode: an object id the attacker OWNS (calibrates the owner value)" },
        foreignIds: { type: "array", items: { type: "string" }, description: "owner-field mode: other object ids to test (observed / neighbour)" },
        object: { type: "string", description: 'sibling mode: object endpoint template, e.g. "/api/orders/{param}"' },
        sibling: { type: "string", description: 'sibling/overreturn mode: owner-filtered list, e.g. "/api/me/orders"' },
        collection: { type: "string", description: "JSON key (or dot path via collectionPath) holding the array" },
        collectionList: { type: "string", description: 'overreturn mode: the bare (unscoped) list path, e.g. "/api/orders"' },
        ownerKey: { type: "string", description: "overreturn mode: owner/tenant field name (auto-detected if omitted)" },
        idKey: { type: "string", default: "id" },
        surfacePath: { type: "string", description: "auto mode: a reconstruct --format json artifact" },
        jsPath: { type: "string", description: "auto mode: a bundle dir/file to reconstruct inline" },
        endpoint: { type: "string", description: "graphql mode: the GraphQL endpoint (default /graphql)" },
        objectQuery: { type: "string", description: "graphql mode: object-by-id query with an $id:ID! var" },
        objectPath: { type: "string", description: "graphql mode: dot path to the object node in data" },
        siblingQuery: { type: "string", description: "graphql mode: the caller's own-list query" },
        collectionPath: { type: "string", description: "graphql mode: dot path to the caller's list in data" },
        attacker: { type: "object", description: "{name,headers} or a file path" },
        victim: { type: "object", description: "{name,headers} or a file path (optional for overreturn)" },
      },
      required: ["base", "attacker"],
    },
  },
  {
    name: "aperta_oracles",
    description: "Auto-discover sibling-oracle BOLA candidates from a reconstructed surface and report the applicability rate (how many object endpoints have a usable self-scoped sibling list endpoint). No session, no network. Returns the applicability + candidate pairs; use these to drive aperta_prove.",
    inputSchema: { type: "object", properties: { surfacePath: { type: "string" }, jsPath: { type: "string" } } },
  },
  {
    name: "aperta_report",
    description: "Build a self-contained HTML attack-surface map (privilege matrix + hidden surface + oracle applicability + BFLA + any proven BOLA) and write it to an artifact file. Returns a compact summary + the artifact path (never the raw HTML). Runs the live diff; supply sessions. Optional prove:{attacker,victim} auto-proves discovered candidates.",
    inputSchema: {
      type: "object",
      properties: {
        base: { type: "string" },
        surfacePath: { type: "string" }, jsPath: { type: "string" },
        sessions: { type: "array", items: { type: "object" }, description: "[{name,role?,headers,apiBase?}] or file paths" },
        apiBase: { type: "string", default: "/api" },
        prove: { type: "object", description: "optional {attacker,victim} (objects or file paths) to auto-prove discovered candidates" },
      },
      required: ["base", "sessions"],
    },
  },
];

async function callTool(name, a = {}) {
  if (name === "aperta_fingerprint") {
    return fingerprint(a.path);
  }
  if (name === "aperta_reconstruct") {
    const model = reconstruct(a.path);
    const fw = fingerprint(a.path).framework;
    const full = a.format === "openapi" ? model : { framework: fw, ...model };
    const artifact = writeArtifact("surface.json", full);
    const hiddenRoutes = model.routes.filter((r) => r.role);
    return {
      framework: fw,
      counts: { routes: model.routes.length, endpoints: model.endpoints.length, graphqlOperations: model.operations.length, roleGatedRoutes: hiddenRoutes.length },
      sampleRoleGatedRoutes: hiddenRoutes.slice(0, 10),
      sampleEndpoints: model.endpoints.slice(0, 10).map((e) => `${e.method} ${e.path}`),
      artifactPath: artifact,
      note: "Full surface written to artifactPath (not inlined). Feed artifactPath to aperta_diff.surfacePath.",
    };
  }
  if (name === "aperta_diff") {
    let model;
    if (a.surfacePath) model = JSON.parse(readFileSync(a.surfacePath, "utf8"));
    else if (a.jsPath) model = reconstruct(a.jsPath);
    else throw new Error("surfacePath or jsPath required");
    const endpoints = model.endpoints || [];
    const sessions = a.sessions.map(asSession);
    const gating = {
      gatedStatus: a.gatedStatus ? new Set([401, 403, ...a.gatedStatus]) : undefined,
      gatedRedirect: a.gatedRedirect ? new RegExp(a.gatedRedirect) : null,
      contentMarker: a.contentMarker ? new RegExp(a.contentMarker) : null,
      denyMarker: a.denyMarker ? new RegExp(a.denyMarker) : null,
    };
    const diff = await authzDiff(a.base, endpoints, sessions, a.apiBase || "/api", gating);
    const as = a.as || sessions[0].name;
    const jsonl = writeArtifact("hidden.jsonl", hiddenToJSONL(diff, as) || "");
    const sarif = writeArtifact("findings.sarif", toSARIF({ diff, session: as }));
    return {
      perSession: Object.fromEntries(Object.entries(diff.perSession).map(([n, p]) => [n, { role: p.role, base: p.base, reachable: p.reachable.length, gated: p.gated.length, hidden: p.hidden.length }])),
      hiddenFor: as,
      hidden: diff.perSession[as]?.hidden || [],
      warnings: diff.warnings || [],
      artifacts: { jsonl, sarif },
    };
  }
  if (name === "aperta_prove") {
    const mode = a.mode || "sibling";
    const attacker = asSession(a.attacker);
    const victim = a.victim ? asSession(a.victim) : null;
    const idKey = a.idKey || "id";
    // reportable is the machine-readable contract: only a CONFIRMED verdict may be promoted to a
    // finding. A driving agent must never report a NOT-CONFIRMED / CORRECTLY-SCOPED / INAPPLICABLE.
    const pack = (res) => {
      const out = { verdict: res.verdict, reportable: res.reportable === true, class: res.class, subclass: res.subclass, endpoint: res.endpoint, oracle: res.oracle, gates: res.gates || [], reason: res.reason, evidence: res.evidence };
      if (res.verdict === "CONFIRMED") out.nucleiTemplatePath = writeArtifact("aperta-bola.yaml", toNucleiTemplate(res));
      return out;
    };
    if (mode === "auto") {
      // discover candidate (object, sibling) pairs from a surface and prove each (the deterministic
      // engine picks the pairs; the agent only supplies the two identities).
      if (!victim) return { error: "auto mode needs a victim identity", reportable: false };
      const model = a.surfacePath ? JSON.parse(readFileSync(a.surfacePath, "utf8")) : reconstruct(a.jsPath);
      const disc = discoverOracles(model);
      const results = [];
      for (const c of disc.pairs.filter((p) => p.best)) {
        results.push(await siblingOracleBOLA(a.base, { objectTemplate: c.objectTemplate, siblingPath: c.best, collection: c.collection, idKey, attacker, victim }));
      }
      const confirmed = results.filter((r) => r.verdict === "CONFIRMED");
      return {
        applicability: disc.applicability,
        proved: results.map((r) => ({ endpoint: r.endpoint, verdict: r.verdict, reportable: r.reportable === true, gates: r.gates })),
        confirmed: confirmed.length,
        nucleiTemplatePaths: confirmed.map((r) => writeArtifact("aperta-bola.yaml", toNucleiTemplate(r))),
      };
    }
    if (mode === "graphql") {
      if (!victim) return { error: "graphql mode needs a victim identity", reportable: false };
      return pack(await graphqlOracleBOLA(a.base, { endpoint: a.endpoint || "/graphql", objectQuery: a.objectQuery, objectPath: a.objectPath, siblingQuery: a.siblingQuery, collectionPath: a.collectionPath, idField: idKey, attacker, victim }));
    }
    if (mode === "overreturn") {
      return pack(await collectionOverReturnBOLA(a.base, { collectionPath: a.collectionList, siblingPath: a.sibling, collection: a.collection, idKey, ownerKey: a.ownerKey, attacker, victim: victim || undefined }));
    }
    if (mode === "owner-field") {
      return pack(await ownerFieldOracleBOLA(a.base, { objectTemplate: a.object, ownId: a.ownId, foreignIds: a.foreignIds || [], ownerKey: a.ownerKey, idKey, attacker }));
    }
    // default: the per-object sibling oracle
    if (!victim) return { error: "sibling mode needs a victim identity", reportable: false };
    return pack(await siblingOracleBOLA(a.base, { objectTemplate: a.object, siblingPath: a.sibling, collection: a.collection, idKey, attacker, victim }));
  }
  if (name === "aperta_oracles") {
    const model = a.surfacePath ? JSON.parse(readFileSync(a.surfacePath, "utf8")) : reconstruct(a.jsPath);
    const disc = discoverOracles(model);
    return {
      applicability: disc.applicability,
      summary: applicabilityLine(disc),
      pairs: disc.pairs,
      artifactPath: writeArtifact("oracles.json", disc),
    };
  }
  if (name === "aperta_report") {
    const model = a.surfacePath ? JSON.parse(readFileSync(a.surfacePath, "utf8")) : reconstruct(a.jsPath);
    const sessions = a.sessions.map(asSession);
    const diff = await authzDiff(a.base, model.endpoints || [], sessions, a.apiBase || "/api");
    const discovery = discoverOracles(model);
    const findings = classifyFindings(diff);
    let proves = [];
    if (a.prove) {
      const attacker = asSession(a.prove.attacker), victim = asSession(a.prove.victim);
      for (const c of discovery.pairs.filter((p) => p.best)) {
        proves.push(await siblingOracleBOLA(a.base, { objectTemplate: c.objectTemplate, siblingPath: c.best, collection: c.collection, idKey: "id", attacker, victim }));
      }
    }
    const html = toHTMLReport({ base: a.base, model, diff, discovery, proves, findings });
    return {
      artifactPath: writeArtifact("attack-surface-map.html", html),
      summary: applicabilityLine(discovery),
      findings: { bfla: findings.bfla.length, bolaCandidates: findings.bolaCandidates.length, confirmedBOLA: proves.filter((p) => p.verdict === "CONFIRMED").length },
      warnings: diff.warnings || [],
    };
  }
  throw new Error(`unknown tool: ${name}`);
}

// JSON-RPC dispatch (pure: request in -> response object out, or null for a notification).
export async function dispatch(req) {
  // A JSON-RPC notification has no `id` and must NEVER get a response (id:0 is a real request).
  if (req == null || req.id === undefined || req.id === null) return null;
  const reply = (result) => ({ jsonrpc: "2.0", id: req.id, result });
  const errorReply = (code, message) => ({ jsonrpc: "2.0", id: req.id, error: { code, message } });
  try {
    switch (req.method) {
      case "initialize":
        return reply({
          protocolVersion: req.params?.protocolVersion || "2025-06-18",
          capabilities: { tools: {} },
          serverInfo: SERVER,
        });
      case "notifications/initialized":
      case "notifications/cancelled":
        return null; // notification, no response
      case "ping":
        return reply({});
      case "tools/list":
        return reply({ tools: TOOLS });
      case "tools/call": {
        const result = await callTool(req.params?.name, req.params?.arguments);
        return reply({ content: [{ type: "text", text: JSON.stringify(result, null, 2) }] });
      }
      default:
        return errorReply(-32601, `method not found: ${req.method}`);
    }
  } catch (e) {
    // tool errors are returned as a tool result with isError so the client can show them
    if (req.method === "tools/call") {
      return { jsonrpc: "2.0", id: req.id, result: { content: [{ type: "text", text: `ERROR: ${e.message}` }], isError: true } };
    }
    return errorReply(-32603, e.message);
  }
}

// stdio transport: newline-delimited JSON-RPC.
export function serve() {
  let buf = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => {
    buf += chunk;
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      let req;
      try { req = JSON.parse(line); } catch { continue; }
      dispatch(req).then((res) => { if (res) process.stdout.write(JSON.stringify(res) + "\n"); });
    }
  });
  process.stderr.write(`aperta mcp server (stdio) ready, ${TOOLS.length} tools\n`);
}

// ---- self-test (offline, in-process; no stdio, no network) -----------------------------
async function selfTest() {
  let pass = 0, fail = 0;
  const check = (c, m) => (c ? pass++ : (fail++, console.error("FAIL:", m)));

  const init = await dispatch({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } });
  check(init.result.serverInfo.name === "aperta", "initialize returns serverInfo");
  check(init.result.capabilities.tools, "advertises tools capability");

  check((await dispatch({ jsonrpc: "2.0", id: 2, method: "notifications/initialized" })) === null, "notification -> no response");

  const list = await dispatch({ jsonrpc: "2.0", id: 3, method: "tools/list" });
  check(list.result.tools.length === 6, "6 tools listed");
  check(list.result.tools.every((t) => t.name && t.description && t.inputSchema), "tools well-formed (name/desc/schema)");

  // reconstruct a fixture via the tool; assert compact summary + artifact path (not raw surface)
  const fx = writeArtifact("fx.js", `var cr="/api";const routes=[{path:"/admin",element:G({need:"admin"})}];fetch(\`\${cr}/orders/\${x}\`);createBrowserRouter(routes);`);
  const rc = await dispatch({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "aperta_reconstruct", arguments: { path: fx } } });
  const payload = JSON.parse(rc.result.content[0].text);
  check(payload.framework === "react", "reconstruct tool returns framework");
  check(payload.counts.endpoints >= 1 && payload.artifactPath, "reconstruct returns counts + artifact path (surface not inlined)");
  check(!("routes" in payload) || Array.isArray(payload.sampleRoleGatedRoutes), "raw routes array not streamed (only a sample)");

  // aperta_oracles: offline discovery over a surface with an object endpoint + self-scoped sibling
  const surf = writeArtifact("surf.json", { routes: [], operations: [], endpoints: [{ method: "GET", path: "/api/orders/{param}" }, { method: "GET", path: "/api/me/orders" }] });
  const orc = await dispatch({ jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: "aperta_oracles", arguments: { surfacePath: surf } } });
  const orcPayload = JSON.parse(orc.result.content[0].text);
  check(orcPayload.applicability.withOracle === 1 && orcPayload.applicability.objectEndpoints === 1, "aperta_oracles computes applicability");
  check(orcPayload.artifactPath && !("matrix" in orcPayload), "aperta_oracles returns summary + artifact path");

  // aperta_prove now exposes modes and the deterministic GraphQL oracle over MCP (was unreachable)
  const prraw = list.result.tools.find((t) => t.name === "aperta_prove");
  check(prraw.inputSchema.properties.mode && ["auto", "graphql", "overreturn"].every((m) => prraw.inputSchema.properties.mode.enum.includes(m)), "aperta_prove exposes auto/graphql/overreturn modes");
  check(JSON.stringify(prraw.inputSchema.required) === JSON.stringify(["base", "attacker"]), "aperta_prove requires only base+attacker (the mode supplies the rest)");
  const noVic = await dispatch({ jsonrpc: "2.0", id: 8, method: "tools/call", params: { name: "aperta_prove", arguments: { base: "http://127.0.0.1:0", mode: "auto", attacker: { name: "a", headers: {} } } } });
  check(JSON.parse(noVic.result.content[0].text).error && /victim/.test(noVic.result.content[0].text), "auto mode without a victim is a clean error, not a crash");

  const bad = await dispatch({ jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "aperta_diff", arguments: { base: "x", sessions: [] } } });
  check(bad.result.isError, "tool error surfaced as isError result");

  const nf = await dispatch({ jsonrpc: "2.0", id: 6, method: "does/not/exist" });
  check(nf.error && nf.error.code === -32601, "unknown method -> -32601");

  console.log(`mcp self-test: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

if (process.argv[1] && process.argv[1].endsWith("mcp.mjs")) {
  if (process.argv.includes("--self-test")) selfTest();
  else serve();
}
