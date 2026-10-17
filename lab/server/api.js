// Aperta lab API. Serves the built SPA (dist/) and the API on one origin.
// The vulnerability is deliberate and minimal:
//   GET /api/me/orders   -> returns ONLY the caller's orders   (correct: the oracle of intent)
//   GET /api/orders/:id  -> returns ANY order, no owner check   (BOLA)
//   GET /api/admin/*     -> admin-only, enforced server-side    (the hidden surface)
import express from "express";
import cors from "cors";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
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

function auth(req) {
  const h = req.headers.authorization || "";
  const name = h.startsWith("Bearer ") ? h.slice(7) : null; // token == username, for the lab
  return name && USERS[name] ? USERS[name] : null;
}

app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  const u = USERS[username];
  if (!u || u.password !== password) return res.status(401).json({ error: "bad creds" });
  res.json({ token: u.username, role: u.role, id: u.id });
});

// SIBLING / oracle of intent: correctly scoped to the caller.
app.get("/api/me/orders", (req, res) => {
  const u = auth(req);
  if (!u) return res.status(401).json({ error: "unauthenticated" });
  res.json({ orders: ORDERS.filter((o) => o.owner === u.username) });
});

// BOLA: returns any order regardless of owner.
app.get("/api/orders/:id", (req, res) => {
  const u = auth(req);
  if (!u) return res.status(401).json({ error: "unauthenticated" });
  const o = ORDERS.find((x) => String(x.id) === String(req.params.id));
  if (!o) return res.status(404).json({ error: "no such order" });
  res.json(o); // <-- no `o.owner === u.username` check
});

// Admin-only hidden surface (correctly enforced, this is NOT the bug; it's the surface a
// normal session never reaches, which Aperta reconstructs and then still finds the BOLA under).
app.get("/api/admin/users", (req, res) => {
  const u = auth(req);
  if (!u || u.role !== "admin") return res.status(403).json({ error: "forbidden" });
  res.json({ users: Object.values(USERS).map(({ password, ...rest }) => rest) });
});
app.get("/api/admin/users/:userId", (req, res) => {
  const u = auth(req);
  if (!u || u.role !== "admin") return res.status(403).json({ error: "forbidden" });
  const target = Object.values(USERS).find((x) => String(x.id) === String(req.params.userId));
  if (!target) return res.status(404).json({ error: "no such user" });
  const { password, ...rest } = target;
  res.json(rest);
});

// Serve the built SPA.
app.use(express.static(join(__dirname, "..", "dist")));
app.get("*", (_req, res) => res.sendFile(join(__dirname, "..", "dist", "index.html")));

const PORT = process.env.PORT || 5173;
app.listen(PORT, () => console.log(`aperta-lab on http://localhost:${PORT}`));
