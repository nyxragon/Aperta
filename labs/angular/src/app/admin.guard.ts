import { CanActivateFn, Router } from '@angular/router';
import { inject } from '@angular/core';
export const AdminGuard: CanActivateFn = () => {
  const router = inject(Router);
  if (localStorage.getItem('role') === 'admin') return true;
  router.navigate(['/login']);
  return false;
};
