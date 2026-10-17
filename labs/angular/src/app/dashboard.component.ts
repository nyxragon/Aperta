import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService } from './api.service';
@Component({ selector: 'app-dash', standalone: true, imports: [CommonModule],
  template: `<h2>Your orders</h2><ul><li *ngFor="let o of orders">#{{o.id}} {{o.item}}</li></ul>` })
export class DashboardComponent implements OnInit {
  orders: any[] = [];
  constructor(private api: ApiService) {}
  ngOnInit() { this.api.myOrders().subscribe((d: any) => this.orders = d.orders || []); }
}
