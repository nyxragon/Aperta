import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { adminListUsers, adminGetUser } from "../api.js";

// This whole module is lazy-loaded (its own chunk). A normal user's session never renders
// it and never calls adminListUsers / adminGetUser, so these endpoints are the hidden,
// role-gated surface Aperta isolates via the privilege diff.
export default function Admin() {
  const [users, setUsers] = useState([]);
  useEffect(() => {
    adminListUsers().then((d) => setUsers(d.users || []));
  }, []);
  return (
    <div>
      <h2>Admin, all users</h2>
      <ul>
        {users.map((u) => (
          <li key={u.id}>
            {u.id}: {u.username} ({u.role})
          </li>
        ))}
      </ul>
    </div>
  );
}

export function AdminUser() {
  const { userId } = useParams();
  const [user, setUser] = useState(null);
  useEffect(() => {
    adminGetUser(userId).then(setUser);
  }, [userId]);
  if (!user) return <p>Loading…</p>;
  return (
    <div>
      <h2>User {user.username}</h2>
      <pre>{JSON.stringify(user, null, 2)}</pre>
    </div>
  );
}
