import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute } from '@angular/router';
import { ApiService } from './api.service';
@Component({ selector: 'app-order', standalone: true, imports: [CommonModule],
  template: `<div *ngIf="order"><h2>Order {{order.id}}</h2><p>{{order.item}} owner {{order.owner}}</p></div>` })
export class OrderComponent implements OnInit {
  order: any = null;
  constructor(private route: ActivatedRoute, private api: ApiService) {}
  ngOnInit() { const id = this.route.snapshot.paramMap.get('id')!; this.api.getOrder(id).subscribe((d: any) => this.order = d); }
}
