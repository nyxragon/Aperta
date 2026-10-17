// Modern-framework reconstruction that the chunk-path scan alone misses.
//
//  - Next.js build manifest: `self.__BUILD_MANIFEST` (Pages: a `sortedPages` array) and the App
//    Router manifest (keys like "/admin/[id]/page" / "/dashboard/route"). When chunk filenames are
//    opaque hashes, the manifest still names every route. App Router keeps most routing server-side,
//    so this recovers what the CLIENT manifest reveals, which is more than nothing and more than the
//    filename scan catches.
//  - Webpack Module Federation: a `remoteEntry` container exposes modules ("./routes", "./Button")
//    and consumes remotes. That exposed surface is attack surface other tools do not enumerate.

// Normalize a Next route segment string to a route path. [id]/[...slug] -> {param}; (group) dropped.
function normNextRoute(raw) {
  const parts = String(raw).split("/").filter(Boolean)
    .filter((s) => !/^\(.+\)$/.test(s))                      // route groups
    .filter((s) => !/^(page|route|default|layout|loading|error|not-found|template)$/.test(s)) // app files
    .filter((s) => !/^_(app|document|error|next)$/.test(s))  // pages internals
    .map((s) => s.replace(/\[\.{3}.+?\]|\[.+?\]/g, "{param}"));
  if (parts[parts.length - 1] === "index") parts.pop();
  return "/" + parts.join("/");
}

// Routes from a Next.js build manifest embedded in the code.
export function parseNextBuildManifest(code) {
  const out = new Set();
  // Pages Router: sortedPages: ["/", "/about", "/blog/[slug]", "/_app", ...]
  // (a naive [^\]]* capture breaks on the "]" inside "[slug]", so scan a window for route strings)
  const spi = code.indexOf("sortedPages");
  if (spi >= 0) {
    const win = code.slice(spi, spi + 3000);
    for (const m of win.matchAll(/["'`](\/[^"'`]*)["'`]/g)) {
      const r = normNextRoute(m[1]);
      if (r && r.length > 1 && !/^\/_/.test(r)) out.add(r);
    }
  }
  // App Router manifest keys: "/admin/[id]/page", "/dashboard/route", "/(app)/settings/page"
  for (const m of code.matchAll(/["'`](\/[^"'`]*?)\/(page|route)["'`]/g)) {
    const r = normNextRoute(m[1]);
    if (r && r.length > 1) out.add(r);
  }
  return [...out];
}

// Webpack Module Federation: detect, and extract exposed module + remote names.
export function parseModuleFederation(code) {
  const federated =
    /module[_-]?federation|__webpack_require__\.federation|webpack\/container\/(entry|reference)|remoteEntry|__webpack_share_scopes__/i.test(code);
  if (!federated) return { federated: false, exposes: [], remotes: [] };
  const exposes = new Set();
  // exposed modules are keyed like "./Button", "./routes" in the container's module map
  for (const m of code.matchAll(/["'`](\.\/[A-Za-z0-9_\-./]+)["'`]\s*:/g)) exposes.add(m[1]);
  const remotes = new Set();
  // remotes referenced as "name@url" or a remotes map; capture the container name before '@'
  for (const m of code.matchAll(/["'`]([a-zA-Z0-9_]+)@https?:\/\/[^"'`]+["'`]/g)) remotes.add(m[1]);
  return { federated: true, exposes: [...exposes].slice(0, 100), remotes: [...remotes].slice(0, 50) };
}

// --- self-test (offline) ----------------------------------------------------------------
function selfTest() {
  let pass = 0, fail = 0;
  const check = (c, m) => (c ? pass++ : (fail++, console.error("FAIL:", m)));

  const pagesManifest = `self.__BUILD_MANIFEST={__rewrites:{},sortedPages:["/","/about","/blog/[slug]","/account/settings","/_app","/_error"]};`;
  const pr = parseNextBuildManifest(pagesManifest);
  check(pr.includes("/about") && pr.includes("/blog/{param}") && pr.includes("/account/settings"), "pages sortedPages routes recovered + [slug]->{param}");
  check(!pr.some((r) => /_app|_error|^\/$/.test(r)), "pages internals and index dropped");

  const appManifest = `{"/page":["a.js"],"/dashboard/page":["b.js"],"/(admin)/admin/[id]/page":["c.js"],"/api/hook/route":["d.js"]}`;
  const ar = parseNextBuildManifest(appManifest);
  check(ar.includes("/dashboard"), "app router /dashboard recovered");
  check(ar.includes("/admin/{param}"), "app router route group dropped + [id]->{param}");
  check(ar.includes("/api/hook"), "app router route handler recovered");

  const mf = `var moduleMap={"./routes":()=>x,"./Button":()=>y};__webpack_require__.federation;var r=["shell@https://cdn.example.com/remoteEntry.js"];`;
  const f = parseModuleFederation(mf);
  check(f.federated === true, "module federation detected");
  check(f.exposes.includes("./routes") && f.exposes.includes("./Button"), "exposed modules extracted");
  check(f.remotes.includes("shell"), "remote container name extracted");
  check(parseModuleFederation("const x=1;").federated === false, "non-federated code not flagged");

  console.log(`frameworks_modern self-test: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

if (process.argv[1] && process.argv[1].endsWith("frameworks_modern.mjs") && process.argv.includes("--self-test")) selfTest();
