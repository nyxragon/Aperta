import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ApiService } from './api.service';
@Component({
  selector: 'app-login', standalone: true, imports: [FormsModule],
  template: `<h2>Login</h2>
    <input placeholder="username" [(ngModel)]="u">
    <input placeholder="password" type="password" [(ngModel)]="p">
    <button type="submit" (click)="submit()">Sign in</button>`,
})
export class LoginComponent {
  u = 'alice'; p = 'alice';
  constructor(private api: ApiService, private router: Router) {}
  submit() {
    this.api.login(this.u, this.p).subscribe((r: any) => {
      if (r.token) { localStorage.setItem('token', r.token); localStorage.setItem('role', r.role); this.router.navigate(['/dashboard']); }
    });
  }
}
