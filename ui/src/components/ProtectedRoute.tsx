import { ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth, hasRole, type UserRole } from '@/contexts/AuthContext';
import { useConfig } from '@/contexts/ConfigContext';
import { TxePersonGate } from '@/features/txe/identity';

type ProtectedRouteProps = {
  children: ReactNode;
  requiredRole?: UserRole;
  // personApp, when given, is what a person signed in through the identity
  // provider sees instead of children (see TxePersonGate).
  personApp?: ReactNode;
};

export function ProtectedRoute({
  children,
  requiredRole,
  personApp,
}: ProtectedRouteProps) {
  const config = useConfig();
  const { isAuthenticated, isLoading, setupRequired, user } = useAuth();
  const location = useLocation();

  if (config.authMode !== 'builtin') {
    return <>{children}</>;
  }

  if (isLoading) {
    return null;
  }

  if (setupRequired && !isAuthenticated) {
    return <Navigate to="/setup" replace />;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (requiredRole && user && !hasRole(user.role, requiredRole)) {
    return <Navigate to="/" replace />;
  }

  if (personApp !== undefined) {
    return <TxePersonGate personApp={personApp}>{children}</TxePersonGate>;
  }

  return <>{children}</>;
}
