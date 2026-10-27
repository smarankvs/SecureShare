import { useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/useAuth.ts';
import {
  MicrosoftIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  ShieldIcon,
  UploadCloudIcon,
} from '../components/Icons.tsx';

export function LoginPage() {
  const { isAuthenticated, login, isLoading, error, clearError, isEntraConfigured } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  // If already authenticated, redirect to destination or dashboard
  useEffect(() => {
    if (isAuthenticated) {
      const state = location.state as { from?: { pathname: string; search: string } } | undefined;
      const target = state?.from
        ? `${state.from.pathname}${state.from.search}`
        : sessionStorage.getItem('secureshare_intended_path') || '/';
      sessionStorage.removeItem('secureshare_intended_path');
      navigate(target, { replace: true });
    }
  }, [isAuthenticated, navigate, location]);

  const handleLoginClick = async () => {
    clearError();
    const state = location.state as { from?: { pathname: string; search: string } } | undefined;
    const targetPath = state?.from
      ? `${state.from.pathname}${state.from.search}`
      : sessionStorage.getItem('secureshare_intended_path') || '/';

    await login(targetPath);
  };

  return (
    <div className="login-page">
      <div className="login-container">
        <div className="login-card">
          <div className="login-header">
            <div className="login-icon-badge">
              <ShieldCheckIcon size={32} />
            </div>
            <h1 className="login-title">SecureShare</h1>
            <p className="login-subtitle">
              Cloud-Native Secure Document Sharing & Identity Protection
            </p>
          </div>

          {!isEntraConfigured && (
            <div className="alert alert-warning">
              <ShieldAlertIcon size={20} />
              <div>
                <strong>Entra ID Configuration Required</strong>
                <p className="alert-sub">
                  Copy <code>frontend/.env.example</code> to <code>frontend/.env</code> and provide your{' '}
                  <code>VITE_ENTRA_CLIENT_ID</code> and <code>VITE_ENTRA_TENANT_ID</code> to enable live
                  authentication.
                </p>
              </div>
            </div>
          )}

          {error && (
            <div className="alert alert-error" role="alert">
              <ShieldAlertIcon size={20} />
              <span>{error}</span>
            </div>
          )}

          <div className="login-action-box">
            <button
              type="button"
              className="btn btn-entra"
              onClick={handleLoginClick}
              disabled={isLoading}
            >
              {isLoading ? (
                <>
                  <span className="btn-spinner" />
                  <span>Connecting to Microsoft Identity...</span>
                </>
              ) : (
                <>
                  <MicrosoftIcon size={20} />
                  <span>Sign in with Microsoft Entra ID</span>
                </>
              )}
            </button>
            <p className="entra-hint">
              Work or school accounts authenticated directly against Azure AD tenant JWKS
            </p>
          </div>

          <div className="security-pillars-grid">
            <div className="pillar-item">
              <ShieldIcon size={18} className="pillar-icon" />
              <div>
                <span className="pillar-title">Zero-Trust Cloud</span>
                <p className="pillar-desc">
                  RS256 JWT tokens verified via tenant JWKS with immutable OID binding
                </p>
              </div>
            </div>

            <div className="pillar-item">
              <UploadCloudIcon size={18} className="pillar-icon" />
              <div>
                <span className="pillar-title">Private Blob Storage</span>
                <p className="pillar-desc">
                  Short-lived SAS URLs with randomized UUID key segregation
                </p>
              </div>
            </div>

            <div className="pillar-item">
              <ShieldCheckIcon size={18} className="pillar-icon" />
              <div>
                <span className="pillar-title">4-Gate Gatekeeper</span>
                <p className="pillar-desc">
                  Atomic quota decrement, time limit, and recipient-only verification
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
