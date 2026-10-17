// Shared vulnerable backend for all framework labs. Serves a built SPA (DIST env) on one origin
// and the same deliberately-vulnerable API (BOLA /api/orders/:id + correctly-filtering sibling
// /api/me/orders + admin-only surface). Run: DIST=labs/angular/dist/angular/browser PORT=5199 node labs/server.mjs
import express from "express";
import cors from "cors";
import { join, isAbsolute } from "node:path";

const app = express();
app.use(cors());
app.use(express.json());

const USERS = {
  alice: { id: 1, username: "alice", role: "user", password: "alice", ssn: "111-11-1111" },
  bob: { id: 2, username: "bob", role: "user", password: "bob", ssn: "222-22-2222" },
  admin: { id: 99, username: "admin", role: "admin", password: "admin", ssn: "999-99-9999" },
};
const ORDERS = [
  { id: 1001, owner: "alice", item: "Keyboard", total: 80 },
  { id: 1002, owner: "alice", item: "Mouse", total: 30 },
  { id: 2001, owner: "bob", item: "Monitor", total: 300 },
  { id: 2002, owner: "bob", item: "Secret briefcase", total: 99999 },
];
const auth = (req) => {
  const h = req.headers.authorization || "";
  const name = h.startsWith("Bearer ") ? h.slice(7) : null;
  return name && USERS[name] ? USERS[name] : null;
};

app.post("/api/login", (req, res) => {
  const u = USERS[(req.body || {}).username];
  if (!u || u.password !== req.body.password) return res.status(401).json({ error: "bad creds" });
  res.json({ token: u.username, role: u.role, id: u.id });
});
app.get("/api/me/orders", (req, res) => {
  const u = auth(req); if (!u) return res.status(401).json({ error: "unauth" });
  res.json({ orders: ORDERS.filter((o) => o.owner === u.username) });
});
app.get("/api/orders/:id", (req, res) => {
  const u = auth(req); if (!u) return res.status(401).json({ error: "unauth" });
  const o = ORDERS.find((x) => String(x.id) === String(req.params.id));
  if (!o) return res.status(404).json({ error: "no such order" });
  res.json(o); // BOLA: no owner check
});
app.get("/api/admin/users", (req, res) => {
  const u = auth(req); if (!u || u.role !== "admin") return res.status(403).json({ error: "forbidden" });
  res.json({ users: Object.values(USERS).map(({ password, ...r }) => r) });
});
app.get("/api/admin/users/:userId", (req, res) => {
  const u = auth(req); if (!u || u.role !== "admin") return res.status(403).json({ error: "forbidden" });
  const t = Object.values(USERS).find((x) => String(x.id) === String(req.params.userId));
  if (!t) return res.status(404).json({ error: "no such user" });
  const { password, ...r } = t; res.json(r);
});

const DIST = process.env.DIST || "lab/dist";
const distPath = isAbsolute(DIST) ? DIST : join(process.cwd(), DIST);
app.use(express.static(distPath));
app.get("*", (_req, res) => res.sendFile(join(distPath, "index.html")));

const PORT = process.env.PORT || 5199;
app.listen(PORT, () => console.log(`aperta-lab [${DIST}] on http://localhost:${PORT}`));
