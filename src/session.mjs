// Stage 2a, capture what a given (low-priv) session ACTUALLY exercises.
//
// Drives the real SPA in a headless browser as one identity, records every API request the
// app fires, and visits the routes that identity can reach. The result is the "exercised set"
// we subtract from the reconstructed model to isolate the hidden/role-gated surface.
import { chromium } from "playwright";

// Normalise a concrete path to the reconstructor's template form: numeric/uuid/long-id
// segments become {param}, so /api/orders/1001 matches the reconstructed /api/orders/{param}.
export function templatize(pathname) {
  return pathname
    .split("/")
    .map((seg) =>
      /^\d+$/.test(seg) ||
      /^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(seg) ||
      /^[0-9a-f]{16,}$/i.test(seg)
        ? "{param}"
        : seg
    )
    .join("/");
}

// Substitute a sample value for :params so a route can actually be navigated.
function sampleRoute(route) {
  return route.replace(/:([A-Za-z0-9_]+)/g, "1");
}

/**
 * @param {string} baseURL   e.g. http://localhost:5173
 * @param {object} identity  { username, password }
 * @param {string[]} probeRoutes  reconstructed routes to try navigating as this identity
 * @returns {Promise<{exercised:Set<string>, routeStatus:Record<string,'reached'|'blocked'>}>}
 */
export async function captureSession(baseURL, identity, probeRoutes = ["/dashboard"]) {
  const browser = await chromium.launch();
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const origin = new URL(baseURL).origin;
  const exercised = new Set();

  page.on("request", (req) => {
    try {
      const u = new URL(req.url());
      if (u.origin !== origin) return;
      if (/\.(js|css|png|svg|ico|woff2?|map|json)$/.test(u.pathname)) return; // assets
      if (!/\/api\//.test(u.pathname)) return; // app API only
      exercised.add(`${req.method()} ${templatize(u.pathname)}`);
    } catch {}
  });

  await page.goto(`${baseURL}/login`, { waitUntil: "networkidle" });
  await page.fill('input[placeholder="username"]', identity.username);
  await page.fill('input[placeholder="password"]', identity.password);
  await page.click('button[type="submit"]');
  await page.waitForTimeout(400);

  const routeStatus = {};
  for (const route of probeRoutes) {
    const target = sampleRoute(route);
    await page.goto(`${baseURL}${target}`, { waitUntil: "networkidle" }).catch(() => {});
    await page.waitForTimeout(250);
    // did the SPA keep us on the route, or did a guard redirect us away?
    const landed = new URL(page.url()).pathname;
    routeStatus[route] = landed === target ? "reached" : "blocked";
  }

  await browser.close();
  return { exercised, routeStatus };
}
