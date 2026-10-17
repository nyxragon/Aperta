import { Routes } from '@angular/router';
import { AdminGuard } from './admin.guard';
export const routes: Routes = [
  { path: '', redirectTo: 'login', pathMatch: 'full' },
  { path: 'login', loadComponent: () => import('./login.component').then(m => m.LoginComponent) },
  { path: 'dashboard', loadComponent: () => import('./dashboard.component').then(m => m.DashboardComponent) },
  { path: 'orders/:id', loadComponent: () => import('./order.component').then(m => m.OrderComponent) },
  { path: 'admin', canActivate: [AdminGuard], loadComponent: () => import('./admin.component').then(m => m.AdminComponent) },
  { path: 'admin/users/:userId', canActivate: [AdminGuard], loadComponent: () => import('./admin.component').then(m => m.AdminUserComponent) },
];
