// Stage 1, reconstruct the client-side attack-surface model from a stripped SPA bundle.
//
// What regex (LinkFinder) cannot do and this does:
//   - resolve API paths assembled from a minified base var + template holes
//     (`${cr}/orders/${e}`  with  cr="/api"  ->  GET /api/orders/{param})
//   - recover the FULL react-router route table incl. role-gated / lazy routes that a
//     normal session never renders (path:"..." survives in the bundle)
//   - attach the role each route requires, read from the guard prop (need:"admin")
//
// The LLM is NOT used here: everything below is deterministic AST. The LLM is a later
// fallback only for gates this static pass cannot resolve.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import { parseNextBuildManifest, parseModuleFederation } from "./frameworks_modern.mjs";
const traverse = _traverse.default || _traverse;

function listJs(dir) {
  const s0 = statSync(dir);
  if (s0.isFile()) return dir.endsWith(".js") ? [dir] : [];
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const s = statSync(p);
    if (s.isDirectory()) out.push(...listJs(p));
    else if (name.endsWith(".js")) out.push(p);
  }
  return out;
}

// Generic, content-based framework fingerprint (no site-specific strings).
// Order matters: most specific first.
const FINGERPRINTS = [
  ["aura", /\/sfsites\/aura|apex:\/\/|"markup:\/\/|\$A\.(get|enqueueAction)/],
  ["nextjs", /_buildManifest|__NEXT_DATA__|\/_next\/static|__next_f|\bself\.__next/],
  ["nuxt", /__NUXT__|nuxtApp|\/_nuxt\//],
  ["angularjs", /\$routeProvider|\$stateProvider|angular\.module\(|\.directive\(["']|\$http\s*[:=]/],
  ["angular", /ɵcmp|ɵmod|NgModule|ngDevMode|ɵɵdefineComponent|platformBrowser|ɵɵ/],
  ["vue", /createRouter\(|vue-router|createApp\(|__vue__|_createElementVNode|createVNode|createElementBlock|__v_is[A-Z]|resolveComponent/],
  ["svelte", /\$\$invalidate|svelte\/internal|SvelteComponent|\$\$self/],
  ["react", /react-router|createBrowserRouter|createRoutesFromElements|__REACT_DEVTOOLS|react\.production|jsxDEV|react-dom|hydrateRoot|"react\.element"|react\.memo|useLayoutEffect/],
];

export function fingerprint(target) {
  const files = listJs(target);
  const counts = {};
  // Sample EACH chunk (framework markers are spread across code-split chunks), head + a middle
  // slice, so multi-chunk apps are detected even when the router chunk is late/large.
  for (const f of files.slice(0, 400)) {
    let code;
    try { code = readFileSync(f, "utf8"); } catch { continue; }
    const sample = code.length > 600_000
      ? code.slice(0, 300_000) + code.slice(Math.floor(code.length / 2), Math.floor(code.length / 2) + 300_000)
      : code;
    for (const [name, re] of FINGERPRINTS) {
      if (re.test(sample)) counts[name] = (counts[name] || 0) + 1;
    }
  }
  // Prefer SPECIFICITY over frequency: a Next app is also React, but should read "nextjs".
  // FINGERPRINTS is ordered most-specific-first; return the first present framework.
  const present = FINGERPRINTS.map(([name]) => name).filter((n) => counts[n]);
  return { framework: present[0] || "unknown", signals: counts };
}

// Collect string-valued identifiers for constant propagation (minified `cr="/api"`).
function collectConsts(ast) {
  const consts = new Map();
  traverse(ast, {
    VariableDeclarator(path) {
      const { id, init } = path.node;
      if (id.type === "Identifier" && init && init.type === "StringLiteral") {
        consts.set(id.name, init.value);
      }
    },
    AssignmentExpression(path) {
      const { left, right } = path.node;
      if (left.type === "Identifier" && right.type === "StringLiteral" && !consts.has(left.name)) {
        consts.set(left.name, right.value);
      }
    },
  });
  return consts;
}

// Turn a template-literal / string / concat first-arg of fetch into a path template.
function resolvePath(node, consts) {
  if (!node) return null;
  if (node.type === "StringLiteral") return node.value;
  if (node.type === "TemplateLiteral") {
    let out = "";
    node.quasis.forEach((q, i) => {
      out += q.value.cooked;
      if (i < node.expressions.length) {
        const e = node.expressions[i];
        if (e.type === "Identifier" && consts.has(e.name)) out += consts.get(e.name);
        else out += "{param}"; // dynamic hole -> a path parameter
      }
    });
    return out;
  }
  // `"/api".concat("/x").concat(id)` style
  if (node.type === "CallExpression" && node.callee.type === "MemberExpression" &&
      node.callee.property.name === "concat") {
    const base = resolvePath(node.callee.object, consts) ?? "";
    const arg = node.arguments[0];
    const piece = arg && arg.type === "StringLiteral" ? arg.value : "{param}";
    return base + piece;
  }
  if (node.type === "BinaryExpression" && node.operator === "+") {
    return (resolvePath(node.left, consts) ?? "{param}") + (resolvePath(node.right, consts) ?? "{param}");
  }
  if (node.type === "Identifier" && consts.has(node.name)) return consts.get(node.name);
  return null;
}

function methodOf(optsNode) {
  if (optsNode && optsNode.type === "ObjectExpression") {
    for (const p of optsNode.properties) {
      if (p.type === "ObjectProperty" && (p.key.name === "method" || p.key.value === "method") &&
          p.value.type === "StringLiteral") {
        return p.value.value.toUpperCase();
      }
    }
  }
  return "GET";
}

// Rightmost identifier of a (possibly namespaced) reference: Un.AuthenticatedUserGuard -> "AuthenticatedUserGuard".
function refName(node) {
  if (!node) return null;
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberExpression") return refName(node.property) || refName(node.object);
  if (node.type === "CallExpression") return refName(node.callee);
  return null;
}

// Find a React guard prop (need:"...") inside a node's subtree, used on the route's `element`
// value, where the guard wraps the component: element: Guard({ need:"admin", children:... }).
function needInSubtree(node) {
  const stack = [node];
  while (stack.length) {
    const n = stack.pop();
    if (!n || typeof n !== "object") continue;
    if (n.type === "ObjectProperty" && (n.key.name === "need" || n.key.value === "need") &&
        n.value && n.value.type === "StringLiteral") {
      return n.value.value;
    }
    for (const k of Object.keys(n)) {
      const v = n[k];
      if (Array.isArray(v)) v.forEach((c) => c && typeof c.type === "string" && stack.push(c));
      else if (v && typeof v.type === "string") stack.push(v);
    }
  }
  return null;
}

// The role a route requires: Angular (canActivate/canLoad:[Guard] as a direct prop) or
// React (need:"..." nested in the route's element). Child routes live in `children` arrays,
// which we don't descend here, so siblings don't cross-contaminate.
function roleOfRoute(objNode) {
  const guards = [];
  let elementNode = null, metaNode = null;
  for (const p of objNode.properties) {
    if (p.type !== "ObjectProperty") continue;
    const k = p.key.name || p.key.value;
    if ((k === "canActivate" || k === "canLoad") && p.value && p.value.type === "ArrayExpression") {
      for (const el of p.value.elements) {
        const n = refName(el);
        if (n) guards.push(n);
      }
    }
    if (k === "element") elementNode = p.value;      // React
    if (k === "meta") metaNode = p.value;            // Vue (meta:{requiresAuth, roles})
  }
  if (guards.length) return guards.join("+");
  if (metaNode && metaNode.type === "ObjectExpression") {
    // An explicit role/roles is more specific than a boolean auth flag, so prefer it REGARDLESS of
    // property order (minifiers reorder object keys). Two passes: role/roles first, flags second.
    for (const mp of metaNode.properties) {
      if (mp.type !== "ObjectProperty") continue;
      const mk = mp.key.name || mp.key.value;
      if ((mk === "role" || mk === "roles") && mp.value.type === "StringLiteral") return mp.value.value;
      if ((mk === "role" || mk === "roles") && mp.value.type === "ArrayExpression") {
        const r = mp.value.elements.map((e) => e && e.type === "StringLiteral" ? e.value : null).filter(Boolean);
        if (r.length) return r.join(",");
      }
    }
    for (const mp of metaNode.properties) {
      if (mp.type !== "ObjectProperty") continue;
      const mk = mp.key.name || mp.key.value;
      if ((mk === "requiresAuth" || mk === "requiresAdmin" || mk === "auth") &&
          (mp.value.type === "BooleanLiteral" ? mp.value.value : true)) return mk === "requiresAdmin" ? "admin" : "auth";
    }
  }
  if (elementNode) return needInSubtree(elementNode); // React
  return null;
}

// Normalise a route path: app-relative, leading slash, drop index/wildcard/empty.
function normRoute(p) {
  if (p === "" || p === "*" || p === "**") return null;
  return p.startsWith("/") || p.startsWith(":") ? p : "/" + p;
}

// Parse a GraphQL document string -> { type, name, rootFields[] }. Many large SaaS SPAs expose
// their whole surface as GraphQL operations, not REST paths;
// the operations ARE the endpoints and the diff/authz testing happens at the operation/field level.
function parseGraphQLOps(doc) {
  const ops = [];
  const re = /\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(\([^)]*\))?\s*\{/g;
  let m;
  while ((m = re.exec(doc))) {
    // root fields = identifiers right after the opening brace of the operation
    const after = doc.slice(m.index + m[0].length, m.index + m[0].length + 400);
    const fields = [...after.matchAll(/(?:^|\s)([a-zA-Z_][a-zA-Z0-9_]*)\s*[({:]/g)].slice(0, 6).map((x) => x[1]);
    ops.push({ type: m[1], name: m[2], rootFields: [...new Set(fields)] });
  }
  return ops;
}

// Next.js routes from chunk-path / module-id strings:
//   .../app/dashboard/page-HASH.js        -> /dashboard
//   .../pages/account/billing-HASH.js      -> /account/billing
//   app/(marketing)/pricing/page           -> /pricing   (route groups dropped)
//   app/users/[id]/page                     -> /users/{param}
// (Next App Router keeps most routing server-side (RSC), so this recovers only what the client
// chunks actually reveal, an inherent limit, not a bug.)
function parseNextRoutes(code) {
  const out = new Set();
  const clean = (segs, isPages) => {
    const parts = segs.split("/").filter(Boolean)
      .filter((s) => !/^\(.+\)$/.test(s))                          // route groups
      .filter((s) => !(isPages && /^_(app|document|error)$/.test(s)))
      .map((s) => s.replace(/\[\.{3}.+?\]|\[.+?\]/g, "{param}"));
    if (isPages && parts[parts.length - 1] === "index") parts.pop();
    return "/" + parts.join("/");
  };
  for (const m of code.matchAll(/(?:chunks\/|["'`])app\/((?:[\w\-.@]+|\([\w\- ]+\)|\[[^\]]+\])(?:\/(?:[\w\-.@]+|\([\w\- ]+\)|\[[^\]]+\]))*)\/(?:page|route|default)\b/g)) {
    const r = clean(m[1], false); if (r.length > 1) out.add(r);
  }
  for (const m of code.matchAll(/(?:chunks\/|["'`])pages\/((?:[\w\-.@]+)(?:\/[\w\-.@]+)*?)(?:[-.][0-9a-f]{6,}|\.js|["'`])/g)) {
    const r = clean(m[1], true); if (r.length >= 1 && !/\/_/.test(r)) out.add(r || "/");
  }
  return [...out];
}

export function reconstruct(distDir) {
  const endpoints = new Map(); // key method+path
  const routes = new Map(); // key path
  const operations = new Map(); // key type+name (GraphQL)
  let federation = { federated: false, exposes: [], remotes: [] };
  const AST_LIMIT = 4_000_000; // a >4MB minified file produces a multi-GB AST, regex-only it
  for (const file of listJs(distDir)) {
    const code = readFileSync(file, "utf8");
    // Next.js routes live in chunk-path strings, not the AST, scan raw code for every file.
    if (/\b(?:chunks\/|["'`])(?:app|pages)\//.test(code)) {
      for (const rp of parseNextRoutes(code)) if (!routes.has(rp)) routes.set(rp, { path: rp, role: null });
    }
    // Next.js build manifest (sortedPages / App Router "/x/page" keys): routes even when chunk names are opaque.
    if (/sortedPages|__BUILD_MANIFEST|\/(page|route)["'`]/.test(code)) {
      for (const rp of parseNextBuildManifest(code)) if (!routes.has(rp)) routes.set(rp, { path: rp, role: null });
    }
    // Webpack Module Federation: exposed modules + remotes (surface other tools do not enumerate).
    if (!federation.federated || federation.exposes.length === 0) {
      const mf = parseModuleFederation(code);
      if (mf.federated) {
        federation = {
          federated: true,
          exposes: [...new Set([...federation.exposes, ...mf.exposes])],
          remotes: [...new Set([...federation.remotes, ...mf.remotes])],
        };
      }
    }
    if (code.length > AST_LIMIT) {
      // memory-safe fallback: pull GraphQL operations by regex (the high-value, AST-independent signal)
      if (/\b(query|mutation|subscription)\s+[A-Za-z_]/.test(code)) {
        for (const op of parseGraphQLOps(code)) {
          const k = op.type + " " + op.name;
          if (!operations.has(k)) operations.set(k, op);
        }
      }
      continue;
    }
    let ast;
    try {
      ast = parse(code, { sourceType: "unambiguous", plugins: ["jsx"], errorRecovery: true });
    } catch {
      continue;
    }
    const consts = collectConsts(ast);
    // GraphQL: gql`...` tagged templates + any string/template literal holding a named operation.
    const seenDocs = new Set();
    const addDoc = (doc) => {
      if (!doc || doc.length < 12 || seenDocs.has(doc)) return;
      seenDocs.add(doc);
      if (!/\b(query|mutation|subscription)\s+[A-Za-z_]/.test(doc)) return;
      for (const op of parseGraphQLOps(doc)) {
        const k = op.type + " " + op.name;
        if (!operations.has(k)) operations.set(k, op);
      }
    };
    traverse(ast, {
      TaggedTemplateExpression(path) {
        const tag = refName(path.node.tag);
        if (tag === "gql" || tag === "graphql") {
          addDoc(path.node.quasi.quasis.map((q) => q.value.cooked).join(" "));
        }
      },
      TemplateLiteral(path) {
        const raw = path.node.quasis.map((q) => q.value.cooked).join(" ");
        if (/\b(query|mutation|subscription)\s+[A-Za-z_]\w*\s*[({]/.test(raw)) addDoc(raw);
      },
      StringLiteral(path) {
        if (/\b(query|mutation|subscription)\s+[A-Za-z_]\w*\s*[({]/.test(path.node.value)) addDoc(path.node.value);
      },
      CallExpression(path) {
        const c = path.node.callee;
        // AngularJS routes: $routeProvider.when("/path", {...}) ; ui-router .state(...,{url})
        if (c.type === "MemberExpression" && c.property.name === "when" &&
            path.node.arguments[0] && path.node.arguments[0].type === "StringLiteral") {
          const rp = normRoute(path.node.arguments[0].value);
          if (rp && !routes.has(rp)) routes.set(rp, { path: rp, role: null });
        }
        const isFetch = c.type === "Identifier" && c.name === "fetch";
        const isAxios = c.type === "MemberExpression" && ["get","post","put","delete","patch"].includes(c.property.name);
        // AngularJS: $resource("/api/x/:id"), $http({url,method}), $http.get(...)
        const isResource = c.type === "Identifier" && /resource$/i.test(c.name);
        const isHttpCfg = c.type === "Identifier" && /^(.*\$)?http$/i.test(c.name) &&
          path.node.arguments[0] && path.node.arguments[0].type === "ObjectExpression";
        if (isResource) {
          const u = resolvePath(path.node.arguments[0], consts);
          if (u && u.includes("/")) { const k = "GET " + u.replace(/:([A-Za-z_]+)/g, "{param}"); if (!endpoints.has(k)) endpoints.set(k, { method: "GET", path: u.replace(/:([A-Za-z_]+)/g, "{param}"), file: file.split("/").pop() }); }
          return;
        }
        if (isHttpCfg) {
          let u = null, m = "GET";
          for (const p of path.node.arguments[0].properties) {
            if (p.type !== "ObjectProperty") continue;
            const k = p.key.name || p.key.value;
            if (k === "url") u = resolvePath(p.value, consts);
            if (k === "method" && p.value.type === "StringLiteral") m = p.value.value.toUpperCase();
          }
          if (u && u.includes("/")) { const key = m + " " + u; if (!endpoints.has(key)) endpoints.set(key, { method: m, path: u, file: file.split("/").pop() }); }
          return;
        }
        if (!isFetch && !isAxios) return;
        const url = resolvePath(path.node.arguments[0], consts);
        if (!url || !url.includes("/")) return;
        if (!url.startsWith("/") && !url.startsWith("{")) return; // keep app-relative paths
        // drop paths with no literal segment (e.g. bare "/", or only params), framework noise
        if (url.replace(/\{param\}/g, "").replace(/\//g, "").length === 0) return;
        const method = isAxios ? c.property.name.toUpperCase() : methodOf(path.node.arguments[1]);
        const key = method + " " + url;
        if (!endpoints.has(key)) endpoints.set(key, { method, path: url, file: file.split("/").pop() });
      },
      ObjectExpression(path) {
        // Next.js _buildManifest: { sortedPages: ["/","/admin",...], "/path":[chunks] }
        const sp = path.node.properties.find(
          (p) => p.type === "ObjectProperty" && (p.key.name || p.key.value) === "sortedPages" &&
                 p.value.type === "ArrayExpression"
        );
        if (sp) {
          for (const el of sp.value.elements) {
            if (el && el.type === "StringLiteral" && el.value.startsWith("/") && !el.value.startsWith("/_")) {
              const rp = el.value;
              if (!routes.has(rp)) routes.set(rp, { path: rp, role: null });
            }
          }
        }
        // route config (react-router { path, element } OR angular { path, component, canActivate })
        const pathProp = path.node.properties.find(
          (p) => p.type === "ObjectProperty" &&
                 (p.key.name === "path" || p.key.value === "path") &&
                 p.value.type === "StringLiteral"
        );
        if (!pathProp) return;
        // must look like a route config, not some other {path:"..."} object: require a sibling
        // routing key (component/element/children/loadChildren/redirectTo/canActivate/loadComponent)
        const keys = path.node.properties
          .filter((p) => p.type === "ObjectProperty")
          .map((p) => p.key.name || p.key.value);
        const ROUTE_KEYS = ["component", "element", "children", "loadChildren", "redirectTo",
          "canActivate", "canLoad", "loadComponent", "pathMatch", "outlet"];
        if (!keys.some((k) => ROUTE_KEYS.includes(k))) return;
        const rp = normRoute(pathProp.value.value);
        if (!rp) return;
        const role = roleOfRoute(path.node);
        if (!routes.has(rp) || (role && !routes.get(rp).role)) routes.set(rp, { path: rp, role });
      },
    });
  }
  const model = {
    routes: [...routes.values()].sort((a, b) => a.path.localeCompare(b.path)),
    endpoints: [...endpoints.values()].sort((a, b) => (a.path + a.method).localeCompare(b.path + b.method)),
    operations: [...operations.values()].sort((a, b) => (a.type + a.name).localeCompare(b.type + b.name)),
  };
  if (federation.federated) model.moduleFederation = federation;
  return model;
}

// CLI
if (import.meta.url === `file://${process.argv[1]}`) {
  const dir = process.argv[2];
  if (!dir) {
    console.error("usage: node src/reconstruct.mjs <dist/assets dir>");
    process.exit(2);
  }
  console.log(JSON.stringify(reconstruct(dir), null, 2));
}
