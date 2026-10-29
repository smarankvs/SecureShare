import React, { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/useAuth.ts';
import {
  EyeIcon,
  EyeOffIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  ShieldIcon,
  UploadCloudIcon,
  UserIcon,
} from '../components/Icons.tsx';

export function LoginPage() {
  const { isAuthenticated, login, register, isLoading, error, clearError } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);

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

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    clearError();
    setValidationError(null);

    const state = location.state as { from?: { pathname: string; search: string } } | undefined;
    const targetPath = state?.from
      ? `${state.from.pathname}${state.from.search}`
      : sessionStorage.getItem('secureshare_intended_path') || '/';

    if (!email.trim() || !password) {
      setValidationError('Please provide both email and password.');
      return;
    }

    if (mode === 'register') {
      if (!name.trim()) {
        setValidationError('Please provide your full name.');
        return;
      }
      if (password.length < 8) {
        setValidationError('Password must be at least 8 characters long.');
        return;
      }
      try {
        await register(name.trim(), email.trim().toLowerCase(), password, targetPath);
      } catch {
        // Error state handled by AuthContext
      }
    } else {
      try {
        await login(email.trim().toLowerCase(), password, targetPath);
      } catch {
        // Error state handled by AuthContext
      }
    }
  };

  const handleTabSwitch = (newMode: 'login' | 'register') => {
    clearError();
    setValidationError(null);
    setShowPassword(false);
    setMode(newMode);
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

          {/* Mode Switcher Tabs */}
          <div
            style={{
              display: 'flex',
              background: 'var(--bg-base)',
              padding: '4px',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border-subtle)',
              marginBottom: '1.5rem',
            }}
          >
            <button
              type="button"
              onClick={() => handleTabSwitch('login')}
              style={{
                flex: 1,
                padding: '0.5rem 1rem',
                border: 'none',
                borderRadius: 'var(--radius-sm)',
                background: mode === 'login' ? 'var(--primary)' : 'transparent',
                color: mode === 'login' ? '#ffffff' : 'var(--text-secondary)',
                fontWeight: 600,
                fontSize: '0.875rem',
                cursor: 'pointer',
                transition: 'all var(--transition-fast)',
              }}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => handleTabSwitch('register')}
              style={{
                flex: 1,
                padding: '0.5rem 1rem',
                border: 'none',
                borderRadius: 'var(--radius-sm)',
                background: mode === 'register' ? 'var(--primary)' : 'transparent',
                color: mode === 'register' ? '#ffffff' : 'var(--text-secondary)',
                fontWeight: 600,
                fontSize: '0.875rem',
                cursor: 'pointer',
                transition: 'all var(--transition-fast)',
              }}
            >
              Create Account
            </button>
          </div>

          {(validationError || error) && (
            <div className="alert alert-error" role="alert">
              <ShieldAlertIcon size={20} />
              <span>{validationError || error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} style={{ textAlign: 'left', marginBottom: '1.75rem' }}>
            {mode === 'register' && (
              <div className="form-group">
                <label className="form-label" htmlFor="user-name">
                  Full Name
                </label>
                <input
                  id="user-name"
                  type="text"
                  className="input"
                  placeholder="e.g. Alice Cyber"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  disabled={isLoading}
                  required
                />
              </div>
            )}

            <div className="form-group">
              <label className="form-label" htmlFor="user-email">
                Email Address
              </label>
              <input
                id="user-email"
                type="email"
                className="input"
                placeholder="name@organization.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={isLoading}
                required
                autoComplete="email"
              />
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="user-password">
                Password
              </label>
              <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                <input
                  id="user-password"
                  type={showPassword ? 'text' : 'password'}
                  className="input"
                  style={{ paddingRight: '2.5rem', width: '100%' }}
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={isLoading}
                  required
                  autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((prev) => !prev)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  title={showPassword ? 'Hide password' : 'Show password'}
                  style={{
                    position: 'absolute',
                    right: '0.75rem',
                    background: 'none',
                    border: 'none',
                    color: 'var(--text-muted)',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    padding: '0.25rem',
                    borderRadius: '4px',
                  }}
                >
                  {showPassword ? <EyeOffIcon size={18} /> : <EyeIcon size={18} />}
                </button>
              </div>
              {mode === 'register' && (
                <span className="form-hint" style={{ marginTop: '0.25rem', display: 'block' }}>
                  Min 8 chars with uppercase, lowercase, digit, & special character (@$!%*?&#^_-).
                </span>
              )}
            </div>

            <button
              type="submit"
              className="btn btn-primary"
              style={{ width: '100%', marginTop: '0.5rem', padding: '0.75rem 1rem' }}
              disabled={isLoading}
            >
              {isLoading ? (
                <>
                  <span className="btn-spinner" />
                  <span>{mode === 'login' ? 'Authenticating...' : 'Creating Account...'}</span>
                </>
              ) : (
                <>
                  <UserIcon size={18} />
                  <span>{mode === 'login' ? 'Sign In to SecureShare' : 'Create Secure Account'}</span>
                </>
              )}
            </button>
          </form>

          <div className="security-pillars-grid">
            <div className="pillar-item">
              <ShieldIcon size={18} className="pillar-icon" />
              <div>
                <span className="pillar-title">Zero-Trust Cloud</span>
                <p className="pillar-desc">
                  Argon2id credential derivation & AES-256-GCM envelope encryption
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
