import { useAuth } from '../auth/useAuth.ts';
import { LogOutIcon, ShieldCheckIcon, UserIcon } from './Icons.tsx';

export function Navbar() {
  const { isAuthenticated, user, logout } = useAuth();

  return (
    <header className="navbar">
      <div className="navbar-container">
        <div className="navbar-brand">
          <div className="brand-logo-badge">
            <ShieldCheckIcon size={24} className="brand-icon" />
          </div>
          <div className="brand-text">
            <span className="brand-title">SecureShare</span>
            <span className="brand-badge">Zero-Trust Cloud</span>
          </div>
        </div>

        {isAuthenticated && user && (
          <div className="navbar-user-section">
            <div className="user-info-card">
              <div className="user-avatar">
                <UserIcon size={16} />
              </div>
              <div className="user-details">
                <span className="user-name">{user.name}</span>
                <span className="user-email" title={user.email}>
                  {user.email}
                </span>
              </div>
              <span className="entra-badge" title="Authenticated via Microsoft Entra ID">
                Entra ID
              </span>
            </div>

            <button
              type="button"
              className="btn btn-secondary btn-sm logout-btn"
              onClick={() => logout()}
              title="Sign out of Microsoft Entra ID"
            >
              <LogOutIcon size={16} />
              <span>Sign Out</span>
            </button>
          </div>
        )}
      </div>
    </header>
  );
}
