import { useState } from 'react';
import { useAuth } from '../auth/useAuth.ts';
import { LogOutIcon, ShieldCheckIcon, UserIcon } from './Icons.tsx';
import { ProfileModal } from './ProfileModal.tsx';

export function Navbar() {
  const { isAuthenticated, user, logout } = useAuth();
  const [isProfileOpen, setIsProfileOpen] = useState<boolean>(false);

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
            <div
              className="user-info-card"
              role="button"
              tabIndex={0}
              onClick={() => setIsProfileOpen(true)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  setIsProfileOpen(true);
                }
              }}
              title="Click to view and edit profile"
            >
              <div className="user-avatar">
                <UserIcon size={16} />
              </div>
              <div className="user-details">
                <span className="user-name">{user.name}</span>
                <span className="user-email" title={user.email}>
                  {user.email}
                </span>
              </div>
            </div>
            <button
              type="button"
              className="btn btn-secondary btn-sm logout-btn"
              onClick={() => logout()}
              title="Sign out of SecureShare"
            >
              <LogOutIcon size={16} />
              <span>Sign Out</span>
            </button>
          </div>
        )}
      </div>

      <ProfileModal
        isOpen={isProfileOpen}
        onClose={() => setIsProfileOpen(false)}
      />
    </header>
  );
}
