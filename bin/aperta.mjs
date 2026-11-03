#!/usr/bin/env node
// aperta, the plug-and-play engine CLI. Owns reconstruct / diff / prove; owns NO recon, proxy, or
// auth. Consumes already-collected JS + caller-supplied sessions; emits standard formats on stdout.
// See ARCHITECTURE.md. Each subcommand is stdin/file -> stdout, so it drops into any pipeline.
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { reconstruct, fingerprint } from "../src/reconstruct.mjs";
import { endpointsFromHar, endpointsFromList, sourcesFromSourceMap, chunksFromManifest, mergeEndpoints } from "../src/ingest.mjs";
import { verifyEndpoints, verifyLine } from "../src/verify.mjs";
import { authzDiff, hiddenToJSONL } from "../src/authz_probe.mjs";
import { buildSession } from "../src/session_import.mjs";
import { siblingOracleBOLA, verdictHash } from "../src/oracle.mjs";
import { collectionOverReturnBOLA } from "../src/oracle_collection.mjs";
import { graphqlOracleBOLA } from "../src/oracle_graphql.mjs";
import { discoverOracles, applicabilityLine } from "../src/oracle_discovery.mjs";
import { probeBypasses } from "../src/bypass.mjs";
import { classifyFindings, findingsLine } from "../src/authz_matrix.mjs";
import { toSARIF, toNucleiTemplate, toReproScript } from "../src/emit.mjs";
import { toHTMLReport } from "../src/report.mjs";
import { serve as serveMCP } from "../src/mcp.mjs";

const args = process.argv.slice(2);
const cmd = args.shift();

function opt(name, def) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : def;
}
function optAll(name) {
  const out = [];
  for (let i = 0; i < args.length; i++) if (args[i] === name) out.push(args[i + 1]);
  return out;
}
function positional() {
  return args.find((a) => !a.startsWith("--") && args[args.indexOf(a) - 1]?.startsWith("--") === false);
}

// ---- output formatters ---------------------------------------------------------------
function toOpenAPI(model) {
  const paths = {};
  for (const e of model.endpoints) {
    const p = e.path.replace(/\{param\}/g, "{id}");
    (paths[p] ||= {})[e.method.toLowerCase()] = { responses: { "200": { description: "ok" } } };
  }
  return {
    openapi: "3.0.0",
    info: { title: "Reconstructed by Aperta", version: "0" },
    paths,
    "x-aperta-routes": model.routes,
    "x-aperta-graphql-operations": model.operations,
  };
}
function toEndpoints(model) {
  const rest = model.endpoints.map((e) => `${e.method} ${e.path}`);
  const gql = model.operations.map((o) => `GRAPHQL ${o.type} ${o.name}`);
  return [...rest, ...gql].join("\n");
}

// ---- commands ------------------------------------------------------------------------
function cmdReconstruct() {
  const path = args.find((a) => !a.startsWith("--")) || process.cwd();
  const format = opt("--format", "json");
  const model = reconstruct(path);
  if (format === "openapi") console.log(JSON.stringify(toOpenAPI(model), null, 2));
  else if (format === "endpoints") console.log(toEndpoints(model));
  else console.log(JSON.stringify({ framework: fingerprint(path).framework, ...model }, null, 2));
}

function cmdFingerprint() {
  const path = args.find((a) => !a.startsWith("--")) || process.cwd();
  console.log(JSON.stringify(fingerprint(path), null, 2));
}

async function cmdDiff() {
  // inputs: --base <url>, endpoints from --surface <json|-> or --js <path>, --session <file>...
  const base = opt("--base");
  if (!base) throw new Error("--base <target origin> required");
  let model;
  const surface = opt("--surface");
  const js = opt("--js");
  if (surface) model = JSON.parse(surface === "-" ? readFileSync(0, "utf8") : readFileSync(surface, "utf8"));
  else if (js) model = reconstruct(js);
  else throw new Error("provide --surface <json|-> or --js <path>");
  const endpoints = model.endpoints || [];
  const sessions = optAll("--session").map((f) => JSON.parse(readFileSync(f, "utf8")));
  if (!sessions.length) throw new Error("at least one --session <file> required (caller supplies auth; Aperta never logs in)");
  const apiBase = opt("--api-base", "/api");
  const format = opt("--format", "jsonl");
  const gating = parseGatingOpts();
  const diff = await authzDiff(base, endpoints, sessions, apiBase, gating);
  const findings = classifyFindings(diff);
  const lowest = sessions[0].name;
  const as = opt("--as", lowest);
  if (format === "sarif") {
    console.log(JSON.stringify(toSARIF({ diff, session: as, findings }), null, 2));
  } else {
    // default: emit the hidden surface for the first (assumed lowest-priv) session as JSONL
    console.log(hiddenToJSONL(diff, as) || "");
  }
  // compact summary to stderr so stdout stays pipe-clean
  for (const s of sessions) {
    const p = diff.perSession[s.name];
    console.error(`[${s.name}${s.role ? "/" + s.role : ""}] reachable:${p.reachable.length} gated:${p.gated.length} hidden:${p.hidden.length}`);
  }
  console.error(findingsLine(findings));
  // surface the degenerate-diff diagnostics loudly, so a no-signal result is never silent
  for (const warn of diff.warnings || []) console.error(`\nWARNING: ${warn}`);
  // CI gate: exit 3 (distinct from error=2) when the chosen class of finding is present.
  const failOn = opt("--fail-on");
  if (failOn) {
    const anyHidden = Object.values(diff.perSession).some((p) => p.hidden.length);
    const trip = failOn === "bfla" ? findings.bfla.length > 0
      : (failOn === "hidden" || failOn === "any") ? (anyHidden || findings.bfla.length > 0)
      : false;
    if (trip) { console.error(`--fail-on ${failOn}: findings present, failing the build (exit 3)`); process.exit(3); }
  }
}

// Build the gating model from CLI flags (default = 401/403 only). See authz_probe.buildGatingOpts.
function parseGatingOpts() {
  const gatedStatus = new Set([401, 403]);
  for (const spec of optAll("--gated-status")) for (const n of String(spec).split(",")) { const v = parseInt(n, 10); if (v) gatedStatus.add(v); }
  const gr = opt("--gated-redirect");
  const cm = opt("--content-marker");
  const dm = opt("--deny-marker");
  return {
    gatedStatus,
    gatedRedirect: gr ? new RegExp(gr) : null,
    contentMarker: cm ? new RegExp(cm) : null,
    denyMarker: dm ? new RegExp(dm) : null,
    unsafe: args.includes("--unsafe"), // opt-in to fire state-changing verbs live (lab / authorized only)
  };
}

function cmdSession() {
  const name = opt("--name");
  if (!name) throw new Error("--name <identity> required");
  const role = opt("--role");
  const jar = opt("--cookie-jar");
  const harFile = opt("--from-har");
  const apiBase = opt("--api-base");
  const host = opt("--host");
  if (!jar && !harFile) throw new Error("provide --cookie-jar <netscape jar> and/or --from-har <file>");
  const jarText = jar ? readFileSync(jar, "utf8") : null;
  const har = harFile ? JSON.parse(readFileSync(harFile, "utf8")) : null;
  console.log(JSON.stringify(buildSession({ name, role, jarText, har, apiBase, host }), null, 2));
}

// Load a reconstructed surface from --surface <json|-> or --js <path>.
function loadModel() {
  const surface = opt("--surface");
  const js = opt("--js");
  if (surface) {
    const m = JSON.parse(surface === "-" ? readFileSync(0, "utf8") : readFileSync(surface, "utf8"));
    // Accept an OpenAPI doc too: `reconstruct --format openapi` emits { paths } (no `endpoints`), and
    // feeding that straight back used to make diff/prove/report silently do nothing. Convert paths ->
    // endpoints so the canonical surface round-trips and an OpenAPI spec is a valid --surface input.
    if ((!Array.isArray(m.endpoints) || !m.endpoints.length) && m.paths && typeof m.paths === "object") {
      m.endpoints = [];
      for (const [p, ops] of Object.entries(m.paths)) {
        if (!ops || typeof ops !== "object") continue;
        const tmpl = p.replace(/\{[^}]+\}/g, "{param}");
        for (const method of Object.keys(ops)) {
          if (!/^(get|post|put|patch|delete|head|options)$/i.test(method)) continue;
          m.endpoints.push({ method: method.toUpperCase(), path: tmpl, file: "openapi" });
        }
      }
      if (Array.isArray(m["x-aperta-routes"])) m.routes = m.routes || m["x-aperta-routes"];
    }
    if (!Array.isArray(m.endpoints) || !m.endpoints.length) {
      process.stderr.write("aperta: WARNING - this surface has 0 endpoints; diff/prove/report will find nothing. Reconstruct with `--format json` (not openapi/endpoints) to feed the full model.\n");
    }
    return m;
  }
  if (js) return reconstruct(js);
  throw new Error("provide --surface <json|-> or --js <path>");
}

async function cmdProve() {
  // prove a BOLA via the sibling-endpoint oracle. Sessions = caller-supplied auth (no login).
  const base = opt("--base");
  const attacker = JSON.parse(readFileSync(opt("--attacker"), "utf8"));
  const victimF = opt("--victim");
  const victim = victimF ? JSON.parse(readFileSync(victimF, "utf8")) : null; // optional (over-return can run with one identity)
  const needVictim = () => { if (!victim) throw new Error("--victim <f.json> required for this oracle"); };
  const idKey = opt("--id-key", "id");
  const format = opt("--format", "json");
  if (!base) throw new Error("--base required");

  // --replay N: re-run the oracle N times and prove the verdict hash is byte-identical every run
  // (the determinism claim as a live artifact; a mismatch exits 2, a real nondeterminism regression).
  // --assert-scoped: CI gate - exit 0 only if the endpoint is PROVEN correctly-scoped; a CONFIRMED
  // break is an authz regression (exit 3); anything else is "not asserted" (exit 1).
  const replayN = Math.max(1, parseInt(opt("--replay", "1"), 10) || 1);
  const assertScoped = args.includes("--assert-scoped");
  async function emitProve(res, remake) {
    res.verdictHash = verdictHash(res);
    if (replayN > 1 && remake) {
      const hashes = [res.verdictHash];
      for (let i = 1; i < replayN; i++) hashes.push(verdictHash(await remake()));
      const identical = hashes.every((h) => h === res.verdictHash);
      res.determinism = { runs: replayN, verdictHash: res.verdictHash, identical };
      if (!identical) console.error(`DETERMINISM FAILURE: verdict hash varied across ${replayN} runs (${[...new Set(hashes)].join(" vs ")})`);
    }
    if (format === "sarif") console.log(JSON.stringify(toSARIF({ bolas: [res] }), null, 2));
    else if (format === "nuclei") { if (res.verdict !== "CONFIRMED") { console.error("not confirmed, no template emitted"); process.exit(1); } console.log(toNucleiTemplate(res)); }
    else if (format === "repro") { if (res.verdict !== "CONFIRMED") { console.error("not confirmed, no repro script emitted"); process.exit(1); } console.log(toReproScript(res)); }
    else console.log(JSON.stringify(res, null, 2));
    if (res.determinism && !res.determinism.identical) process.exit(2);
    if (assertScoped) {
      if (res.verdict === "CORRECTLY-SCOPED") process.exit(0);
      if (res.verdict === "CONFIRMED") { console.error("ASSERT-SCOPED FAILED: endpoint is CONFIRMED vulnerable (authz regression)"); process.exit(3); }
      console.error(`ASSERT-SCOPED: not asserted (verdict ${res.verdict}; needs two identities + a reachable object to prove scoping)`); process.exit(1);
    }
    process.exit(res.verdict === "CONFIRMED" ? 0 : 1);
  }

  // --auto: discover candidate (object, sibling) pairs from the reconstructed surface and prove each,
  // instead of hand-specifying --object/--sibling/--collection.
  if (args.includes("--auto")) {
    needVictim();
    const disc = discoverOracles(loadModel());
    const candidates = disc.pairs.filter((p) => p.best);
    console.error(applicabilityLine(disc) + `; proving ${candidates.length} candidate(s)`);
    const results = [];
    for (const c of candidates) {
      results.push(await siblingOracleBOLA(base, {
        objectTemplate: c.objectTemplate, siblingPath: c.best, collection: c.collection, idKey, attacker, victim,
      }));
    }
    if (format === "sarif") console.log(JSON.stringify(toSARIF({ bolas: results }), null, 2));
    else console.log(JSON.stringify(results, null, 2));
    process.exit(results.some((r) => r.verdict === "CONFIRMED") ? 0 : 1);
  }

  // --collection-overreturn: prove an unscoped collection list over-returns other users' rows.
  if (args.includes("--collection-overreturn")) {
    const collectionPath = opt("--collection-list");
    const siblingPath = opt("--sibling");
    const collection = opt("--collection");
    if (!collectionPath || !siblingPath || !collection) throw new Error("--collection-overreturn needs --collection-list <bare path> --sibling <self-scoped path> --collection <name>");
    const ownerKey = opt("--owner-key");
    const mk = () => collectionOverReturnBOLA(base, { collectionPath, siblingPath, collection, idKey, ownerKey, attacker, victim: victim || undefined });
    return emitProve(await mk(), mk);
  }

  // --graphql: the sibling oracle over GraphQL global-ids (node(id:)/typed-by-id queries).
  if (args.includes("--graphql")) {
    const endpoint = opt("--endpoint", "/graphql");
    const objectQuery = opt("--object-query");
    const objectPath = opt("--object-path");
    const siblingQuery = opt("--sibling-query");
    const collectionPath = opt("--collection-path");
    if (!objectQuery || !objectPath || !siblingQuery || !collectionPath) {
      throw new Error("--graphql needs --object-query --object-path --sibling-query --collection-path");
    }
    needVictim();
    const mk = () => graphqlOracleBOLA(base, { endpoint, objectQuery, objectPath, siblingQuery, collectionPath, idField: idKey, attacker, victim });
    return emitProve(await mk(), mk);
  }

  const objectTemplate = opt("--object");
  const siblingPath = opt("--sibling");
  const collection = opt("--collection");
  if (!objectTemplate || !siblingPath || !collection) {
    throw new Error("--object <tmpl> --sibling <path> --collection <name> required (or --auto, --graphql, or --collection-overreturn)");
  }
  needVictim();
  const mk = () => siblingOracleBOLA(base, { objectTemplate, siblingPath, collection, idKey, attacker, victim });
  return emitProve(await mk(), mk);
}

function cmdIngest() {
  // seed the surface from artifacts you already hold (Aperta still fetches nothing itself).
  const manF = opt("--manifest");
  if (manF) {
    const chunks = chunksFromManifest(JSON.parse(readFileSync(manF, "utf8")));
    console.log(chunks.join("\n"));
    console.error(`${chunks.length} JS chunk(s) listed; feed these to your harvester (getJS/katana)`);
    return;
  }
  const mapF = opt("--source-map");
  if (mapF) {
    const src = sourcesFromSourceMap(JSON.parse(readFileSync(mapF, "utf8")));
    if (!src.length) throw new Error("source map has no sourcesContent to reconstruct from");
    const dir = mkdtempSync(join(tmpdir(), "aperta-src-"));
    src.forEach((s, i) => writeFileSync(join(dir, `src_${i}.js`), s.content));
    const model = reconstruct(dir);
    console.log(JSON.stringify({ framework: fingerprint(dir).framework, ...model }, null, 2));
    console.error(`reconstructed from ${src.length} original source(s) carried in the map`);
    return;
  }
  const listF = opt("--endpoints");
  if (listF) {
    const extra = endpointsFromList(readFileSync(listF, "utf8"));
    const base = (opt("--surface") || opt("--js")) ? loadModel() : { routes: [], endpoints: [], operations: [] };
    console.log(JSON.stringify(mergeEndpoints(base, extra), null, 2));
    console.error(`merged ${extra.length} endpoint(s) from the list (agent-recovered surface)`);
    return;
  }
  const harF = opt("--har");
  if (harF) {
    const extra = endpointsFromHar(JSON.parse(readFileSync(harF, "utf8")));
    const base = (opt("--surface") || opt("--js")) ? loadModel() : { routes: [], endpoints: [], operations: [] };
    console.log(JSON.stringify(mergeEndpoints(base, extra), null, 2));
    console.error(`merged ${extra.length} API endpoint(s) observed in the HAR`);
    return;
  }
  throw new Error("provide --har <f> | --source-map <f.js.map> | --manifest <f> | --endpoints <f>");
}

async function cmdVerify() {
  // opt-in live existence check of reconstructed endpoints (HEAD/GET; never logs in, never mutates).
  const base = opt("--base");
  if (!base) throw new Error("--base <target origin> required");
  const model = loadModel();
  const sessFile = opt("--session");
  const headers = sessFile ? (JSON.parse(readFileSync(sessFile, "utf8")).headers || {}) : {};
  const results = await verifyEndpoints(base, model.endpoints || [], headers);
  console.log(JSON.stringify(results, null, 2));
  console.error(verifyLine(results));
}

function cmdOracles() {
  // auto-discover sibling-oracle BOLA candidates from the reconstructed surface + report applicability.
  const disc = discoverOracles(loadModel());
  const format = opt("--format", "json");
  if (format === "json") {
    console.log(JSON.stringify(disc, null, 2));
  } else {
    for (const p of disc.pairs) {
      console.log(`${p.confidence.padEnd(6)}  ${p.objectTemplate}  ->  ${p.best || "(no sibling oracle)"}`);
    }
  }
  console.error(applicabilityLine(disc));
}

async function cmdBypass() {
  // bypass wave: for every endpoint gated from a low-priv identity, try known authz-bypass transforms.
  const base = opt("--base");
  if (!base) throw new Error("--base <target origin> required");
  const model = loadModel();
  const sessFile = opt("--session");
  if (!sessFile) throw new Error("--session <low-priv f.json> required");
  const session = JSON.parse(readFileSync(sessFile, "utf8"));
  const apiBase = opt("--api-base", "/api");
  const gatingOpts = parseGatingOpts();
  // classify what is gated for this identity, then attack only those
  const diff = await authzDiff(base, model.endpoints || [], [session], apiBase, gatingOpts);
  const gated = (diff.perSession[session.name]?.gated || []).map((l) => {
    const [method, ...rest] = l.split(" ");
    return { method, path: rest.join(" ") };
  });
  console.error(`${gated.length} endpoint(s) gated from '${session.name}'; probing bypass transforms`);
  const findings = await probeBypasses(base, gated, session, gatingOpts);
  if (findings.skippedUnsafe && !gatingOpts.unsafe) console.error(`${findings.skippedUnsafe} state-changing transform(s) skipped for safety; pass --unsafe on an authorized lab to include verb-swaps to POST/PUT/PATCH/DELETE`);
  console.log(JSON.stringify(findings, null, 2));
  console.error(findings.length ? `${findings.length} bypass(es) flipped gated -> reached (confirm impact with 'prove')` : "no bypass flipped a gated endpoint");
  process.exit(findings.length ? 0 : 1);
}

async function cmdReport() {
  // one-shot visual attack-surface map: reconstruct -> diff (-> optional auto-prove) -> self-contained HTML.
  const base = opt("--base");
  if (!base) throw new Error("--base <target origin> required");
  const model = loadModel();
  if (!model.framework && opt("--js")) model.framework = fingerprint(opt("--js")).framework;
  const sessions = optAll("--session").map((f) => JSON.parse(readFileSync(f, "utf8")));
  if (!sessions.length) throw new Error("at least one --session <file> required");
  const apiBase = opt("--api-base", "/api");
  const diff = await authzDiff(base, model.endpoints || [], sessions, apiBase, parseGatingOpts());
  const discovery = discoverOracles(model);
  const findings = classifyFindings(diff);
  let proves = [];
  if (args.includes("--prove")) {
    const aF = opt("--attacker"), vF = opt("--victim");
    if (!aF || !vF) throw new Error("--prove needs --attacker <f> and --victim <f>");
    const attacker = JSON.parse(readFileSync(aF, "utf8"));
    const victim = JSON.parse(readFileSync(vF, "utf8"));
    const idKey = opt("--id-key", "id");
    for (const c of discovery.pairs.filter((p) => p.best)) {
      proves.push(await siblingOracleBOLA(base, { objectTemplate: c.objectTemplate, siblingPath: c.best, collection: c.collection, idKey, attacker, victim }));
    }
  }
  console.log(toHTMLReport({ base, model, diff, discovery, proves, findings }));
  for (const s of sessions) {
    const p = diff.perSession[s.name];
    console.error(`[${s.name}${s.role ? "/" + s.role : ""}] reachable:${p.reachable.length} gated:${p.gated.length} hidden:${p.hidden.length}`);
  }
  console.error(applicabilityLine(discovery));
  console.error(findingsLine(findings));
}

const HELP = `aperta, prove broken access control in a web app, deterministically, using the app's
own behaviour as the oracle. One path: MAP the surface -> DIFF out the hidden part -> PROVE the break.

THE ONE PATH (everything else is a helper for one of these):
  aperta report  --base <url> (--surface <json|->|--js <path>) --session <f.json> [--session ...]
                 [--prove --attacker <f.json> --victim <f.json>] > map.html
       run all three steps -> one self-contained HTML attack-surface map. Start here.

  1. aperta reconstruct <jsDirOrFile> [--format json|openapi|endpoints]      MAP from JavaScript
  2. aperta diff  --base <url> (--surface <json|->|--js <path>) --session <f.json> [--session ...]
                  [--as <name>] [--format jsonl|sarif] [--fail-on any|hidden|bfla]      DIFF
       gating (default 401/403): [--gated-status 302] [--gated-redirect <re>] [--content-marker <re>] [--deny-marker <re>]
  3. aperta prove --base <url> --attacker <f.json> [--victim <f.json>] [--format json|nuclei|sarif|repro]   PROVE
       [--replay N] determinism proof (identical verdict hash)   [--assert-scoped] CI gate (exit 0 iff proven scoped)
       manual:  --object "/api/orders/{param}" --sibling "/api/me/orders" --collection orders
       auto:    --auto (--surface|--js ...)        discover + prove every candidate pair
       graphql: --graphql --object-query <q> --object-path <p> --sibling-query <q> --collection-path <p>
       list:    --collection-overreturn --collection-list "/api/orders" --sibling "/api/me/orders" --collection orders

HELPERS:
  aperta fingerprint <jsDirOrFile>                           which framework (picks the MAP lens)
  aperta oracles (--surface|--js ...) [--format json|text]   where PROVE applies + applicability %
  aperta session --name <id> [--role r] (--cookie-jar <jar>|--from-har <f>) [--host <h>]   build a session
  aperta ingest  (--har <f>|--source-map <f.js.map>|--manifest <f>|--endpoints <f>) [--surface|--js]   seed the MAP
  aperta verify  --base <url> (--surface|--js ...) [--session <f>]   confirm reconstructed endpoints are live
  aperta bypass  --base <url> (--surface|--js ...) --session <low-priv f.json>   authz-bypass transforms on gated eps
  aperta mcp                                                 stdio MCP server (6 typed tools) for any agent

The PROVE verdict is deterministic and framework-agnostic: it sources the victim's REAL object ids
(uuid/slug/int) from the victim's own list endpoint, so confirmation needs no id guessing and the
app's code structure is irrelevant. A session is JSON { "name","role?","headers":{...},"apiBase?" }
you supply; aperta never logs in. If 'diff' finds no delta, the app likely denies by redirect or a
soft 200: re-run with --gated-redirect / --content-marker. See ARCHITECTURE.md.`;

try {
  if (cmd === "reconstruct") cmdReconstruct();
  else if (cmd === "fingerprint") cmdFingerprint();
  else if (cmd === "session") cmdSession();
  else if (cmd === "diff") await cmdDiff();
  else if (cmd === "ingest") cmdIngest();
  else if (cmd === "verify") await cmdVerify();
  else if (cmd === "oracles") cmdOracles();
  else if (cmd === "bypass") await cmdBypass();
  else if (cmd === "prove") await cmdProve();
  else if (cmd === "report") await cmdReport();
  else if (cmd === "mcp") serveMCP(); // stdio MCP server; stays alive on stdin
  else { console.log(HELP); process.exit(cmd ? 1 : 0); }
} catch (e) {
  console.error("ERROR:", e.message);
  process.exit(2);
}
