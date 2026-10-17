import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { myOrders, getOrder } from "../api.js";

export function Dashboard() {
  const [orders, setOrders] = useState([]);
  useEffect(() => {
    myOrders().then((d) => setOrders(d.orders || []));
  }, []);
  return (
    <div>
      <h2>Your orders</h2>
      <ul>
        {orders.map((o) => (
          <li key={o.id}>
            #{o.id}: {o.item} (${o.total})
          </li>
        ))}
      </ul>
    </div>
  );
}

export function OrderView() {
  const { id } = useParams();
  const [order, setOrder] = useState(null);
  useEffect(() => {
    getOrder(id).then(setOrder);
  }, [id]);
  if (!order) return <p>Loading…</p>;
  return (
    <div>
      <h2>Order #{order.id}</h2>
      <p>{order.item}, ${order.total}, owner: {order.owner}</p>
    </div>
  );
}
