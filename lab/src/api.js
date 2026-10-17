// The app's API client. These call-sites are what Aperta must recover from the stripped
// bundle, including the dynamically-constructed `/api/orders/${id}` path and the
// admin-only endpoints a normal user session never triggers.
const BASE = "/api";

function authHeaders() {
  const t = localStorage.getItem("token");
  return t ? { Authorization: `Bearer ${t}` } : {};
}

export async function login(username, password) {
  const r = await fetch(`${BASE}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  return r.json();
}

// SIBLING ENDPOINT (correctly filters to the caller's own orders), the oracle of intent.
export async function myOrders() {
  const r = await fetch(`${BASE}/me/orders`, { headers: authHeaders() });
  return r.json();
}

// BOLA ENDPOINT (returns ANY order by id, no owner check), dynamically constructed path.
export async function getOrder(id) {
  const r = await fetch(`${BASE}/orders/${id}`, { headers: authHeaders() });
  return r.json();
}

// ADMIN-ONLY endpoints, only ever called from the lazy-loaded /admin route, so a
// normal user's session never exercises them. This is the hidden surface.
export async function adminListUsers() {
  const r = await fetch(`${BASE}/admin/users`, { headers: authHeaders() });
  return r.json();
}

export async function adminGetUser(userId) {
  const r = await fetch(`${BASE}/admin/users/${userId}`, { headers: authHeaders() });
  return r.json();
}
