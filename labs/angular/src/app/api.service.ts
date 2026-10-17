import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
// Realistic Angular pattern: base URL is a RUNTIME value, not a module constant, so static
// extraction cannot resolve the endpoints, the runtime capture must. (Mirrors real prod Angular.)
@Injectable({ providedIn: 'root' })
export class ApiService {
  private baseUrl: string;
  constructor(private http: HttpClient) {
    this.baseUrl = (window as any).__APP_CONFIG__?.apiBase || '/api';
  }
  private auth(): Record<string, string> { const t = localStorage.getItem('token'); return t ? { Authorization: `Bearer ${t}` } : {}; }
  login(u: string, p: string) { return this.http.post(this.baseUrl + '/login', { username: u, password: p }); }
  myOrders() { return this.http.get(this.baseUrl + '/me/orders', { headers: this.auth() }); }
  getOrder(id: string) { return this.http.get(this.baseUrl + '/orders/' + id, { headers: this.auth() }); }
  adminUsers() { return this.http.get(this.baseUrl + '/admin/users', { headers: this.auth() }); }
  adminUser(id: string) { return this.http.get(this.baseUrl + '/admin/users/' + id, { headers: this.auth() }); }
}
