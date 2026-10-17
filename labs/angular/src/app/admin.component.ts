import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute } from '@angular/router';
import { ApiService } from './api.service';
@Component({ selector: 'app-admin', standalone: true, imports: [CommonModule],
  template: `<h2>Admin users</h2><ul><li *ngFor="let u of users">{{u.id}} {{u.username}}</li></ul>` })
export class AdminComponent implements OnInit {
  users: any[] = [];
  constructor(private api: ApiService) {}
  ngOnInit() { this.api.adminUsers().subscribe((d: any) => this.users = d.users || []); }
}
@Component({ selector: 'app-admin-user', standalone: true, imports: [CommonModule],
  template: `<pre>{{user | json}}</pre>` })
export class AdminUserComponent implements OnInit {
  user: any = null;
  constructor(private route: ActivatedRoute, private api: ApiService) {}
  ngOnInit() { const id = this.route.snapshot.paramMap.get('userId')!; this.api.adminUser(id).subscribe((d: any) => this.user = d); }
}
