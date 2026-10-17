import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { login } from "../api.js";

export function Login() {
  const [u, setU] = useState("alice");
  const [p, setP] = useState("alice");
  const nav = useNavigate();

  async function submit(e) {
    e.preventDefault();
    const res = await login(u, p);
    if (res.token) {
      localStorage.setItem("token", res.token);
      localStorage.setItem("role", res.role);
      nav("/dashboard");
    }
  }

  return (
    <form onSubmit={submit}>
      <h2>Aperta Lab login</h2>
      <input value={u} onChange={(e) => setU(e.target.value)} placeholder="username" />
      <input value={p} onChange={(e) => setP(e.target.value)} placeholder="password" type="password" />
      <button type="submit">Sign in</button>
      <p>alice/alice (user) · admin/admin (admin)</p>
    </form>
  );
}
