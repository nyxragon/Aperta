// Aperta's visual attack-surface map: one self-contained, offline HTML page that makes the whole
// analysis legible at a glance. NOT a cosmetic dashboard, it renders the actual engine output:
//   - the privilege MATRIX (endpoint x identity), each cell = reachable / gated / HIDDEN, taken
//     from the authoritative per-session classification (so it respects any custom gating model),
//   - the HIDDEN surface each low-priv identity is gated from but a higher role reaches,
//   - the auto-discovered sibling-oracle candidates + the honest applicability rate,
//   - each CONFIRMED BOLA as a chain: attacker -> object(foreign id)=200 -> sibling says victim ->
//     controls (own=200, missing=404) -> CONFIRMED.
// Zero external dependencies (inline CSS, no CDN, works air-gapped). Every target-derived string is
// HTML-escaped: endpoint paths come from the target bundle and are untrusted (CLAUDE.md §5).

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

// Cell state for (endpoint label, session) from the authoritative per-session lists.
function cellState(perSession, name, label) {
  const p = perSession[name];
  if (!p) return "unknown";
  if (p.hidden.includes(label)) return "hidden";
  if (p.gated.includes(label)) return "gated";
  if (p.reachable.includes(label)) return "reachable";
  return "unknown";
}

function matrixSection(diff) {
  if (!diff || !diff.matrix?.length) return "";
  const names = Object.keys(diff.perSession);
  const rows = diff.matrix.map((r) => ({ label: `${r.method} ${r.path}`, status: r.status }));
  const head = names.map((n) => {
    const role = diff.perSession[n].role;
    return `<th><div class="idt">${esc(n)}</div>${role ? `<div class="role">${esc(role)}</div>` : ""}</th>`;
  }).join("");
  const body = rows.map((row) => {
    const cells = names.map((n) => {
      const st = cellState(diff.perSession, n, row.label);
      const code = row.status[n] ?? 0;
      const glyph = { reachable: "reach", gated: "gated", hidden: "HIDDEN", unknown: "-" }[st];
      return `<td class="c ${st}" title="HTTP ${esc(code)}">${glyph}</td>`;
    }).join("");
    return `<tr><td class="ep">${esc(row.label)}</td>${cells}</tr>`;
  }).join("");
  return `<section><h2>Privilege matrix</h2>
  <p class="sub">Every reconstructed endpoint probed as every identity. <b class="hidden-k">HIDDEN</b> = gated from this identity but reached by a higher-privilege one: the role-gated surface a low-priv session never sees.</p>
  <div class="scroll"><table class="matrix"><thead><tr><th class="ep">endpoint</th>${head}</tr></thead><tbody>${body}</tbody></table></div></section>`;
}

function hiddenSection(diff) {
  if (!diff) return "";
  const blocks = Object.entries(diff.perSession).map(([name, p]) => {
    if (!p.hidden.length) return "";
    const items = p.hidden.map((h) => `<li><code>${esc(h)}</code></li>`).join("");
    return `<div class="hidden-block"><h3>Hidden from <b>${esc(name)}</b>${p.role ? ` <span class="role">${esc(p.role)}</span>` : ""} (${p.hidden.length})</h3><ul>${items}</ul></div>`;
  }).filter(Boolean).join("");
  if (!blocks) return "";
  return `<section><h2>Hidden surface</h2>${blocks}</section>`;
}

function oracleSection(discovery) {
  if (!discovery) return "";
  const a = discovery.applicability;
  const pct = Math.round(a.rate * 100);
  const bar = `<div class="bar"><div class="fill" style="width:${pct}%"></div><span>${a.withOracle}/${a.objectEndpoints} object endpoints have a usable sibling oracle (${pct}%)</span></div>`;
  const rows = discovery.pairs.map((p) => `<tr>
    <td><code>${esc(p.objectTemplate)}</code></td>
    <td>${p.best ? `<code>${esc(p.best)}</code>` : '<span class="none">none</span>'}</td>
    <td class="conf ${esc(p.confidence)}">${esc(p.confidence)}</td></tr>`).join("");
  return `<section><h2>Sibling-oracle applicability</h2>
  <p class="sub">Where Aperta's deterministic BOLA oracle applies on this surface, reported honestly. High = a self-scoped list endpoint (a true ownership statement); medium = only a bare collection list; none = no sibling, the oracle cannot confirm here.</p>
  ${bar}
  <table class="pairs"><thead><tr><th>object endpoint</th><th>sibling oracle</th><th>confidence</th></tr></thead><tbody>${rows}</tbody></table></section>`;
}

function bolaChain(b) {
  const ok = b.verdict === "CONFIRMED";
  const fid = b.evidence?.foreign_id_tested;
  const repro = b.evidence?.reproductions;
  const steps = [
    { t: `attacker<br><b>${esc(b.attacker)}</b>`, k: "actor" },
    { t: `${esc(b.method || "GET")} ${esc(String(b.endpoint).replace("{param}", esc(fid ?? "id")))}<br>-> object returned`, k: ok ? "good" : "muted" },
    { t: `sibling says<br>owner = <b>${esc(b.victim)}</b>`, k: ok ? "good" : "muted" },
    { t: `controls hold<br>own + nonexistent${repro ? `<br>reproduced ${esc(repro)}` : ""}`, k: ok ? "good" : "muted" },
    { t: ok ? "CONFIRMED<br>BOLA" : "not<br>confirmed", k: ok ? "verdict" : "muted" },
  ];
  const flow = steps.map((s, i) => `<div class="step ${s.k}">${s.t}</div>${i < steps.length - 1 ? '<div class="arrow">&rarr;</div>' : ""}`).join("");
  // show the actual cross-user data the attacker received: the evidence a triager accepts, not prose.
  let received = "";
  const body = b.evidence?.attacker_get_foreign?.body;
  if (ok && body != null) {
    let snippet;
    try { snippet = JSON.stringify(body, null, 2); } catch { snippet = String(body); }
    if (snippet.length > 1200) snippet = snippet.slice(0, 1200) + "\n...";
    received = `<div class="received"><div class="received-h">Data <b>${esc(b.attacker)}</b> received that belongs to <b>${esc(b.victim)}</b>:</div><pre>${esc(snippet)}</pre></div>`;
  }
  return `<div class="chain ${ok ? "confirmed" : "unconfirmed"}">
    <div class="chain-head"><code>${esc(b.method || "GET")} ${esc(b.endpoint)}</code> <span class="tag ${ok ? "crit" : "muted"}">${ok ? "CONFIRMED" : "NOT CONFIRMED"}</span></div>
    <div class="flow">${flow}</div>
    ${received}
    <p class="reason">${esc(b.reason)}</p></div>`;
}

function proveSection(proves) {
  if (!proves || !proves.length) return "";
  return `<section><h2>Confirmed authorization breaks</h2>
  <p class="sub">Each BOLA proven by the app's own sibling endpoint (its own statement of ownership), with controls holding in the same run. No tuned response-diff, no LLM in the decision path.</p>
  ${proves.map(bolaChain).join("")}</section>`;
}

function findingsSection(findings) {
  if (!findings || (!findings.bfla.length && !findings.anonReach.length)) return "";
  const rows = findings.bfla.map((b) => {
    const who = b.reachedBy.map((r) => `${esc(r.name)}${r.role ? ` <span class="role">(${esc(r.role)})</span>` : ""}`).join(", ");
    return `<tr><td><code>${esc(b.endpoint)}</code></td><td>${who}</td><td class="conf ${b.severity === "critical" ? "none" : "medium"}" style="font-weight:700;color:var(--crit)">${esc(b.severity)}</td></tr>`;
  }).join("");
  return `<section><h2>Broken function-level authz (vertical priv-esc)</h2>
  <p class="sub">A privileged-looking endpoint (an /admin, /manage, /internal path, or a route the bundle marked role-gated) reached by a NON-privileged or anonymous identity. Unlike a BOLA candidate, this is a direct broken-function-level-authz signal: a low-priv user is calling a privileged route.</p>
  <table class="pairs"><thead><tr><th>privileged endpoint</th><th>reached by (should not)</th><th>severity</th></tr></thead><tbody>${rows}</tbody></table></section>`;
}

/**
 * toHTMLReport({ base, model, diff, discovery, proves, findings }) -> self-contained HTML string.
 */
export function toHTMLReport({ base = "", model = {}, diff = null, discovery = null, proves = [], findings = null } = {}) {
  const fw = model.framework || "unknown";
  const counts = {
    routes: model.routes?.length || 0,
    endpoints: model.endpoints?.length || 0,
    operations: model.operations?.length || 0,
    identities: diff ? Object.keys(diff.perSession).length : 0,
  };
  const confirmed = (proves || []).filter((b) => b.verdict === "CONFIRMED").length;
  const bflaCount = findings?.bfla?.length || 0;
  const stat = (n, l) => `<div class="stat"><div class="n">${esc(n)}</div><div class="l">${esc(l)}</div></div>`;
  const warnings = (diff?.warnings || []).map((w) => `<div class="warn">${esc(w)}</div>`).join("");
  const date = new Date().toISOString().slice(0, 10);

  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Aperta attack surface map</title>
<style>
:root{--bg:#f7f8fa;--card:#fff;--ink:#1a1d24;--sub:#5a6472;--line:#e3e7ee;--accent:#4f46e5;
--reach:#1f9d55;--reach-bg:#e4f5ec;--gate:#b7791f;--gate-bg:#fbf3e2;--hide:#d4302f;--hide-bg:#fbe6e6;
--unknown:#9aa3b0;--unknown-bg:#eef0f3;--crit:#d4302f;--good:#1f9d55;}
:root:not([data-theme=light]) @media (prefers-color-scheme:dark){}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0f1218;--card:#161b23;--ink:#e7ebf2;--sub:#9aa6b6;--line:#262d38;--accent:#8b84ff;
--reach:#54d88a;--reach-bg:#13301f;--gate:#e3b65c;--gate-bg:#33280f;--hide:#ff6b6a;--hide-bg:#3a1414;
--unknown:#6b7585;--unknown-bg:#1c222b;--crit:#ff6b6a;--good:#54d88a;}}
:root[data-theme=dark]{--bg:#0f1218;--card:#161b23;--ink:#e7ebf2;--sub:#9aa6b6;--line:#262d38;--accent:#8b84ff;
--reach:#54d88a;--reach-bg:#13301f;--gate:#e3b65c;--gate-bg:#33280f;--hide:#ff6b6a;--hide-bg:#3a1414;
--unknown:#6b7585;--unknown-bg:#1c222b;--crit:#ff6b6a;--good:#54d88a;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;}
.wrap{max-width:1040px;margin:0 auto;padding:32px 16px 64px}
header h1{margin:0 0 4px;font-size:26px;letter-spacing:-.02em}
header .tgt{color:var(--sub);font-family:ui-monospace,Menlo,monospace;font-size:13px}
.stats{display:flex;flex-wrap:wrap;gap:12px;margin:20px 0 8px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:92px}
.stat .n{font-size:24px;font-weight:700;color:var(--accent)}
.stat .l{font-size:12px;color:var(--sub);text-transform:uppercase;letter-spacing:.04em}
.stat.crit .n{color:var(--crit)}
section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px 22px;margin:18px 0}
h2{margin:0 0 6px;font-size:18px}
h3{margin:14px 0 6px;font-size:14px;font-weight:600}
.sub{margin:0 0 14px;color:var(--sub);font-size:13px}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}
.matrix th,.matrix td{border:1px solid var(--line);padding:7px 9px;text-align:center}
.matrix th.ep,.matrix td.ep{text-align:left;font-family:ui-monospace,Menlo,monospace;white-space:nowrap}
.idt{font-weight:700}.role{font-size:11px;color:var(--sub);font-weight:400}
td.c{font-weight:700;font-size:11px;letter-spacing:.03em}
.c.reachable{background:var(--reach-bg);color:var(--reach)}
.c.gated{background:var(--gate-bg);color:var(--gate)}
.c.hidden{background:var(--hide-bg);color:var(--hide)}
.c.unknown{background:var(--unknown-bg);color:var(--unknown)}
.hidden-k{color:var(--hide)}
.hidden-block ul{margin:4px 0 0;padding-left:20px}.hidden-block code{color:var(--hide)}
.pairs{font-size:13px}.pairs th,.pairs td{border-bottom:1px solid var(--line);padding:7px 9px;text-align:left}
.conf.high{color:var(--good);font-weight:700}.conf.medium{color:var(--gate);font-weight:600}.conf.none{color:var(--unknown)}
.none{color:var(--unknown)}
.bar{position:relative;background:var(--unknown-bg);border-radius:8px;height:30px;margin:6px 0 16px;overflow:hidden}
.bar .fill{position:absolute;left:0;top:0;bottom:0;background:linear-gradient(90deg,var(--accent),var(--good));opacity:.25}
.bar span{position:relative;display:block;line-height:30px;padding:0 12px;font-size:12px;font-weight:600}
.chain{border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:12px 0}
.chain.confirmed{border-color:var(--crit)}
.chain-head{display:flex;align-items:center;gap:10px;font-family:ui-monospace,Menlo,monospace;font-size:13px;margin-bottom:10px;flex-wrap:wrap}
.tag{font-family:ui-sans-serif,system-ui;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}
.tag.crit{background:var(--hide-bg);color:var(--crit)}.tag.muted{background:var(--unknown-bg);color:var(--unknown)}
.flow{display:flex;align-items:stretch;gap:6px;flex-wrap:wrap}
.step{flex:1;min-width:120px;background:var(--unknown-bg);border-radius:8px;padding:10px;font-size:12px;text-align:center;line-height:1.35;display:flex;align-items:center;justify-content:center}
.step.actor{background:var(--card);border:1px solid var(--line)}
.step.good{background:var(--reach-bg);color:var(--reach)}
.step.verdict{background:var(--hide-bg);color:var(--crit);font-weight:700}
.step.muted{opacity:.6}
.arrow{display:flex;align-items:center;color:var(--sub);font-size:18px}
.reason{margin:10px 0 0;font-size:12px;color:var(--sub)}
.received{margin:10px 0 0}
.received-h{font-size:12px;color:var(--sub);margin-bottom:4px}
.received pre{margin:0;background:var(--hide-bg);border:1px solid var(--line);border-radius:8px;padding:10px;font-size:12px;overflow-x:auto;color:var(--ink)}
.warn{background:var(--gate-bg);color:var(--gate);border-radius:8px;padding:10px 12px;font-size:12px;margin:8px 0}
footer{color:var(--sub);font-size:12px;margin-top:24px;text-align:center}
code{font-family:ui-monospace,Menlo,monospace}
</style></head>
<body><div class="wrap">
<header><h1>Attack surface map</h1><div class="tgt">${esc(base || "(no base)")} &middot; framework: ${esc(fw)}</div></header>
<div class="stats">${stat(counts.routes, "routes")}${stat(counts.endpoints, "endpoints")}${counts.operations ? stat(counts.operations, "graphql ops") : ""}${stat(counts.identities, "identities")}${bflaCount ? stat(bflaCount, "BFLA") : ""}${stat(confirmed, "confirmed BOLA")}</div>
${warnings}
${matrixSection(diff)}
${findingsSection(findings)}
${hiddenSection(diff)}
${oracleSection(discovery)}
${proveSection(proves)}
<footer>Generated by Aperta ${esc(date)} &middot; deterministic, no LLM in the decision path &middot; <code>github.com/nyxragon/Aperta</code></footer>
</div></body></html>`;
}

// --- self-test (offline) ----------------------------------------------------------------
function selfTest() {
  let pass = 0, fail = 0;
  const check = (c, m) => (c ? pass++ : (fail++, console.error("FAIL:", m)));

  const diff = {
    matrix: [
      { method: "GET", path: "/api/admin/users", status: { alice: 403, admin: 200 } },
      { method: "GET", path: "/api/me/orders", status: { alice: 200, admin: 200 } },
    ],
    perSession: {
      alice: { role: "user", reachable: ["GET /api/me/orders"], gated: ["GET /api/admin/users"], hidden: ["GET /api/admin/users"] },
      admin: { role: "admin", reachable: ["GET /api/admin/users", "GET /api/me/orders"], gated: [], hidden: [] },
    },
    warnings: [],
  };
  const model = { framework: "react", routes: [{ path: "/admin", role: "admin" }], endpoints: [{ method: "GET", path: "/api/orders/{param}" }], operations: [] };
  const discovery = { pairs: [{ objectTemplate: "/api/orders/{param}", best: "/api/me/orders", confidence: "high" }], applicability: { objectEndpoints: 1, withOracle: 1, rate: 1 } };
  const prove = { verdict: "CONFIRMED", method: "GET", endpoint: "/api/orders/{param}", attacker: "alice", victim: "bob",
    reason: "alice retrieved orders 2001 attributed to bob.",
    evidence: { foreign_id_tested: "2001", attacker_get_foreign: { status: 200, body: { id: 2001, owner: "bob", item: "Monitor" } } } };

  const findings = { bfla: [{ endpoint: "GET /api/admin/users", reachedBy: [{ name: "alice", role: "user" }], severity: "high" }], anonReach: [], bolaCandidates: [] };
  const html = toHTMLReport({ base: "http://localhost:5173", model, diff, discovery, proves: [prove], findings });
  check(html.includes("Broken function-level authz"), "BFLA section rendered");
  check(html.startsWith("<!doctype html>"), "valid doctype");
  check(html.includes("<title>Aperta attack surface map</title>"), "has title");
  check(/data-theme=dark/.test(html) && /prefers-color-scheme:dark/.test(html), "dark-mode theming present");
  check(html.includes("Privilege matrix"), "matrix section rendered");
  check((html.match(/class="c hidden"/g) || []).length === 1, "exactly one HIDDEN cell (admin/users for alice)");
  check(html.includes("Hidden from <b>alice</b>"), "hidden surface for alice");
  check(html.includes("CONFIRMED<br>BOLA"), "confirmed BOLA chain rendered");
  check(html.includes("received that belongs to") && html.includes("Monitor"), "received cross-user data shown as evidence");
  check(html.includes("1/1 object endpoints have a usable sibling oracle (100%)"), "applicability bar text");
  // XSS/untrusted-data escaping: a malicious endpoint path must be escaped
  const evil = { framework: "react", endpoints: [], routes: [], operations: [] };
  const evilDiff = { matrix: [{ method: "GET", path: "/x/<script>alert(1)</script>", status: { a: 200 } }],
    perSession: { a: { role: "user", reachable: ["GET /x/<script>alert(1)</script>"], gated: [], hidden: [] } }, warnings: [] };
  const evilHtml = toHTMLReport({ base: "x", model: evil, diff: evilDiff });
  check(!evilHtml.includes("<script>alert(1)</script>"), "target-derived path is HTML-escaped (no raw script)");
  check(evilHtml.includes("&lt;script&gt;"), "escaped form present");

  console.log(`report self-test: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

if (process.argv[1] && process.argv[1].endsWith("report.mjs") && process.argv.includes("--self-test")) selfTest();
