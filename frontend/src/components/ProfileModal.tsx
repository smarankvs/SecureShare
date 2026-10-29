import React, { useCallback, useEffect, useState } from 'react';
import { updateUserProfile } from '../api/apiClient.ts';
import { useAuth } from '../auth/useAuth.ts';
import {
  CloseIcon,
  LockIcon,
  ShieldCheckIcon,
  UserIcon,
} from './Icons.tsx';

interface ProfileModalProps {
  isOpen: boolean;
  onClose: () => void;
}

interface ProfileModalDialogProps {
  onClose: () => void;
}

function ProfileModalDialog({ onClose }: ProfileModalDialogProps) {
  const { user, updateUser } = useAuth();

  const [name, setName] = useState<string>(() => user?.name || '');
  const [isSaving, setIsSaving] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [successNotice, setSuccessNotice] = useState<string | null>(null);

  const handleClose = useCallback(() => {
    if (isSaving) return;
    setError(null);
    setSuccessNotice(null);
    onClose();
  }, [isSaving, onClose]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !isSaving) {
        handleClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isSaving, handleClose]);

  if (!user) {
    return null;
  }

  const trimmedName = name.trim();
  const isNameChanged = trimmedName !== user.name;
  const isNameValid = trimmedName.length >= 2 && trimmedName.length <= 100;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isNameValid || isSaving) return;

    setIsSaving(true);
    setError(null);
    setSuccessNotice(null);

    try {
      const updated = await updateUserProfile({ name: trimmedName });
      updateUser({ name: updated.name });
      setSuccessNotice('Profile display name updated successfully.');
      setTimeout(() => {
        handleClose();
      }, 1200);
    } catch (err: unknown) {
      const errorObj = err as Error;
      setError(errorObj.message || 'Failed to update profile. Please try again.');
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div
      className="modal-backdrop"
      onClick={handleClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="profile-modal-title"
    >
      <div
        className="modal-card profile-modal-card"
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: '480px' }}
      >
        <div className="modal-header">
          <div className="modal-title-group">
            <div className="modal-icon-badge">
              <UserIcon size={20} />
            </div>
            <div>
              <h2 id="profile-modal-title" className="modal-title">
                User Profile
              </h2>
              <p className="modal-subtitle">View your account details and update your display name.</p>
            </div>
          </div>
          <button
            type="button"
            className="modal-close-btn"
            onClick={handleClose}
            disabled={isSaving}
            aria-label="Close dialog"
          >
            <CloseIcon size={18} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="modal-body profile-modal-body">
          {error && (
            <div className="alert alert-error" role="alert" style={{ marginBottom: '1rem' }}>
              <span>{error}</span>
            </div>
          )}

          {successNotice && (
            <div className="alert alert-success" role="status" style={{ marginBottom: '1rem' }}>
              <ShieldCheckIcon size={18} />
              <span>{successNotice}</span>
            </div>
          )}

          {/* Read-Only Email Field */}
          <div className="form-group">
            <label className="form-label" htmlFor="profile-email">
              Registered Email Address
            </label>
            <div className="input-with-icon-wrap" style={{ position: 'relative' }}>
              <input
                id="profile-email"
                type="email"
                className="form-input form-input-disabled"
                value={user.email}
                disabled
                readOnly
                aria-readonly="true"
                style={{
                  paddingRight: '2.5rem',
                  backgroundColor: 'rgba(15, 23, 42, 0.6)',
                  cursor: 'not-allowed',
                  opacity: 0.85,
                }}
              />
              <div
                style={{
                  position: 'absolute',
                  right: '0.875rem',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  color: 'var(--text-muted)',
                  display: 'flex',
                  alignItems: 'center',
                }}
                title="Email is permanent and cannot be modified"
              >
                <LockIcon size={16} />
              </div>
            </div>
            <p className="form-helper-text" style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', marginTop: '0.375rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              <span>Registered email address is immutable and cannot be changed for security &amp; zero-trust access control.</span>
            </p>
          </div>

          {/* Editable Display Name */}
          <div className="form-group" style={{ marginTop: '1.25rem' }}>
            <label className="form-label" htmlFor="profile-name">
              Display Name <span style={{ color: 'var(--primary)' }}>*</span>
            </label>
            <input
              id="profile-name"
              type="text"
              className="form-input"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Alice Smith"
              minLength={2}
              maxLength={100}
              required
              disabled={isSaving}
              autoFocus
            />
            <p className="form-helper-text" style={{ marginTop: '0.375rem', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              Between 2 and 100 characters. Visible to recipients on shared documents.
            </p>
          </div>

          {/* Account Security Metadata */}
          <div
            className="account-meta-box"
            style={{
              marginTop: '1.5rem',
              padding: '0.875rem 1rem',
              background: 'rgba(19, 28, 49, 0.6)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-md)',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.5rem',
              fontSize: '0.75rem',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-secondary)' }}>
              <span>Account Status:</span>
              <span style={{ color: 'var(--success)', fontWeight: 600 }}>Active</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-secondary)' }}>
              <span>Authentication:</span>
              <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>Local DB (Argon2id)</span>
            </div>
            {user.id && (
              <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-secondary)' }}>
                <span>User ID:</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                  {user.id.slice(0, 8)}...{user.id.slice(-6)}
                </span>
              </div>
            )}
          </div>

          <div className="modal-footer" style={{ marginTop: '1.5rem', padding: 0 }}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={handleClose}
              disabled={isSaving}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={isSaving || !isNameValid || !isNameChanged}
            >
              {isSaving ? (
                <>
                  <span className="btn-spinner" />
                  <span>Saving...</span>
                </>
              ) : (
                <span>Save Changes</span>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export function ProfileModal({ isOpen, onClose }: ProfileModalProps) {
  if (!isOpen) return null;
  return <ProfileModalDialog onClose={onClose} />;
}
