import React, { useEffect } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../auth/useAuth.ts';

interface ProtectedRouteProps {
  children: React.ReactNode;
}

export function ProtectedRoute({ children }: ProtectedRouteProps) {
  const { isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      // Save attempted destination path to sessionStorage so MSAL redirects back here
      const fullPath = location.pathname + location.search;
      if (fullPath !== '/login') {
        sessionStorage.setItem('secureshare_intended_path', fullPath);
      }
    }
  }, [isLoading, isAuthenticated, location]);

  if (isLoading) {
    return (
      <div className="auth-loading-screen">
        <div className="loading-spinner-ring" />
        <p className="loading-text">Verifying Entra ID Session...</p>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <>{children}</>;
}
