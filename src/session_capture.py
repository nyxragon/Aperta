#!/usr/bin/env python3
"""Stage 2a (container backend), capture what a low-priv session exercises.

Runs inside the recon container (which has a working Playwright chromium) and drives the
host-run SPA over host networking. Emits JSON {exercised, routeStatus} on stdout for the
Node orchestrator. This is the dev backend; a provisioned host can run the Node equivalent
in src/session.mjs. The JSON interface is identical, so the diff doesn't care which ran.

argv: <baseURL> <username> <password> <routesCSV>
"""
import json
import re
import sys
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

ASSET = re.compile(r"\.(js|css|png|svg|ico|woff2?|map|json)$")


def templatize(path: str) -> str:
    out = []
    for seg in path.split("/"):
        if re.fullmatch(r"\d+", seg) or re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-.*", seg, re.I) \
                or re.fullmatch(r"[0-9a-f]{16,}", seg, re.I):
            out.append("{param}")
        else:
            out.append(seg)
    return "/".join(out)


def main() -> int:
    base, user, pw, routes_csv = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    routes = [r for r in routes_csv.split(",") if r]
    origin = urlparse(base)
    exercised: set[str] = set()
    route_status: dict[str, str] = {}

    def on_request(req):
        try:
            u = urlparse(req.url)
            if (u.hostname, u.port) != (origin.hostname, origin.port):
                return
            if ASSET.search(u.path) or "/api/" not in u.path:
                return
            exercised.add(f"{req.method} {templatize(u.path)}")
        except Exception:
            pass

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.on("request", on_request)

        page.goto(f"{base}/login", wait_until="networkidle")
        page.fill('input[placeholder="username"]', user)
        page.fill('input[placeholder="password"]', pw)
        page.click('button[type="submit"]')
        page.wait_for_timeout(400)

        for route in routes:
            target = re.sub(r":([A-Za-z0-9_]+)", "1", route)
            try:
                page.goto(f"{base}{target}", wait_until="networkidle")
                page.wait_for_timeout(250)
                landed = urlparse(page.url).path
                route_status[route] = "reached" if landed == target else "blocked"
            except Exception:
                route_status[route] = "blocked"
        browser.close()

    print(json.dumps({"exercised": sorted(exercised), "routeStatus": route_status}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
