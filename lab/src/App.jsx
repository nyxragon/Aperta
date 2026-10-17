import React, { Suspense, lazy } from "react";
import { BrowserRouter, Routes, Route, Navigate, Link } from "react-router-dom";
import { Login } from "./pages/Login.jsx";
import { Dashboard } from "./pages/Dashboard.jsx";
import { OrderView } from "./pages/Dashboard.jsx";

// Code-split, role-gated admin area. The chunk ships to EVERY browser; the route is only
// linked/rendered for admins. This is exactly the hidden surface Aperta reconstructs.
const Admin = lazy(() => import("./pages/Admin.jsx"));
const AdminUser = lazy(() => import("./pages/Admin.jsx").then((m) => ({ default: m.AdminUser })));

function role() {
  return localStorage.getItem("role") || "anon";
}

function RequireRole({ need, children }) {
  if (role() !== need) return <Navigate to="/login" replace />;
  return children;
}

export function App() {
  return (
    <BrowserRouter>
      <nav>
        <Link to="/dashboard">Dashboard</Link>
        {role() === "admin" && <Link to="/admin">Admin</Link>}
      </nav>
      <Suspense fallback={<p>Loading…</p>}>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/orders/:id" element={<OrderView />} />
          <Route
            path="/admin"
            element={
              <RequireRole need="admin">
                <Admin />
              </RequireRole>
            }
          />
          <Route
            path="/admin/users/:userId"
            element={
              <RequireRole need="admin">
                <AdminUser />
              </RequireRole>
            }
          />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </Suspense>
    </BrowserRouter>
  );
}
