import React, { useCallback, useEffect, useState } from 'react';
import { createShare } from '../api/apiClient.ts';
import type { FileItem, ShareCreatedResponse } from '../types/index.ts';
import {
  CheckIcon,
  CloseIcon,
  CopyIcon,
  ShareIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
} from './Icons.tsx';

interface ShareModalProps {
  isOpen: boolean;
  file: FileItem | null;
  onClose: () => void;
  onSuccess?: () => void;
}

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_EXPIRY_DAYS = 90;
const MAX_DOWNLOADS_CAP = 100;

export function ShareModal({ isOpen, file, onClose, onSuccess }: ShareModalProps) {
  const [recipientEmail, setRecipientEmail] = useState('');
  const [expiryOption, setExpiryOption] = useState<'1h' | '24h' | '7d' | '30d' | 'custom'>('24h');
  const [customExpiryDate, setCustomExpiryDate] = useState(() => {
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    tomorrow.setMinutes(0, 0, 0);
    return tomorrow.toISOString().slice(0, 16);
  });
  const [maxDownloads, setMaxDownloads] = useState<number>(1);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [shareResult, setShareResult] = useState<ShareCreatedResponse | null>(null);
  const [copied, setCopied] = useState(false);

  const resetForm = useCallback(() => {
    setRecipientEmail('');
    setExpiryOption('24h');
    setMaxDownloads(1);
    setIsSubmitting(false);
    setError(null);
    setShareResult(null);
    setCopied(false);
  }, []);

  const handleClose = useCallback(() => {
    if (isSubmitting) return;
    resetForm();
    onClose();
  }, [isSubmitting, resetForm, onClose]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen && !isSubmitting) {
        handleClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, isSubmitting, handleClose]);

  const computeExpiresAt = (): Date | null => {
    const now = new Date();
    switch (expiryOption) {
      case '1h':
        return new Date(now.getTime() + 60 * 60 * 1000);
      case '24h':
        return new Date(now.getTime() + 24 * 60 * 60 * 1000);
      case '7d':
        return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
      case '30d':
        return new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
      case 'custom':
        if (!customExpiryDate) return null;
        return new Date(customExpiryDate);
      default:
        return new Date(now.getTime() + 24 * 60 * 60 * 1000);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file || isSubmitting) return;

    setError(null);

    const emailTrimmed = recipientEmail.trim().toLowerCase();
    if (!emailTrimmed) {
      setError('Recipient email is required.');
      return;
    }

    if (!EMAIL_REGEX.test(emailTrimmed)) {
      setError('Please provide a valid email address (e.g. user@organization.com).');
      return;
    }

    const expiryDate = computeExpiresAt();
    if (!expiryDate || isNaN(expiryDate.getTime())) {
      setError('Please specify a valid expiration date.');
      return;
    }

    const now = new Date();
    if (expiryDate <= now) {
      setError('Expiration date must be in the future.');
      return;
    }

    const maxAllowedFuture = new Date(now.getTime() + MAX_EXPIRY_DAYS * 24 * 60 * 60 * 1000);
    if (expiryDate > maxAllowedFuture) {
      setError(`Expiration cannot exceed ${MAX_EXPIRY_DAYS} days.`);
      return;
    }

    const quota = Number(maxDownloads);
    if (!quota || quota < 1 || quota > MAX_DOWNLOADS_CAP) {
      setError(`Maximum downloads must be between 1 and ${MAX_DOWNLOADS_CAP}.`);
      return;
    }

    setIsSubmitting(true);

    try {
      const response = await createShare({
        file_id: file.id,
        recipient_email: emailTrimmed,
        expires_at: expiryDate.toISOString(),
        max_downloads: quota,
      });

      setShareResult(response);
      if (onSuccess) onSuccess();
    } catch (err: unknown) {
      const errorObj = err as Error;
      setError(errorObj.message || 'Failed to create share grant.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const getFullShareUrl = (): string => {
    if (!shareResult) return '';
    // Use window.location.origin + shareResult.share_url
    return `${window.location.origin}${shareResult.share_url}`;
  };

  const handleCopyLink = async () => {
    const url = getFullShareUrl();
    if (!url) return;
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    } catch {
      // Fallback
      const input = document.createElement('input');
      input.value = url;
      document.body.appendChild(input);
      input.select();
      document.execCommand('copy');
      document.body.removeChild(input);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    }
  };

  if (!isOpen || !file) return null;

  return (
    <div className="modal-backdrop" onClick={handleClose} role="dialog" aria-modal="true">
      <div
        className="modal-card"
        onClick={(e) => e.stopPropagation()}
        aria-labelledby="share-modal-title"
      >
        <div className="modal-header">
          <div className="modal-title-group">
            <div className="modal-icon-badge">
              <ShareIcon size={20} />
            </div>
            <h2 id="share-modal-title" className="modal-title">
              Share Document
            </h2>
          </div>
          <button
            type="button"
            className="btn-icon"
            onClick={handleClose}
            disabled={isSubmitting}
            aria-label="Close modal"
          >
            <CloseIcon size={18} />
          </button>
        </div>

        <div className="modal-body">
          <div className="target-file-summary">
            <span className="target-label">Selected Document:</span>
            <span className="target-filename" title={file.original_name}>
              {file.original_name}
            </span>
          </div>

          {error && (
            <div className="alert alert-error" role="alert">
              <ShieldAlertIcon size={18} />
              <span>{error}</span>
            </div>
          )}

          {shareResult ? (
            <div className="share-result-container">
              <div className="alert alert-success" role="status">
                <ShieldCheckIcon size={20} />
                <div>
                  <strong>Secure Share Link Generated</strong>
                  <p className="alert-sub">
                    Only <strong>{shareResult.recipient_email}</strong> can access this file after
                    authenticating via Microsoft Entra ID.
                  </p>
                </div>
              </div>

              <div className="link-copy-box">
                <input
                  type="text"
                  readOnly
                  value={getFullShareUrl()}
                  className="input link-input"
                  onClick={(e) => (e.target as HTMLInputElement).select()}
                />
                <button
                  type="button"
                  className="btn btn-primary copy-btn"
                  onClick={handleCopyLink}
                >
                  {copied ? (
                    <>
                      <CheckIcon size={16} />
                      <span>Copied!</span>
                    </>
                  ) : (
                    <>
                      <CopyIcon size={16} />
                      <span>Copy</span>
                    </>
                  )}
                </button>
              </div>

              <div className="share-meta-grid">
                <div className="share-meta-item">
                  <span className="meta-label">Recipient</span>
                  <span className="meta-val">{shareResult.recipient_email}</span>
                </div>
                <div className="share-meta-item">
                  <span className="meta-label">Quota</span>
                  <span className="meta-val">{shareResult.max_downloads} download(s)</span>
                </div>
                <div className="share-meta-item">
                  <span className="meta-label">Expires</span>
                  <span className="meta-val">
                    {new Date(shareResult.expires_at).toLocaleString()}
                  </span>
                </div>
                <div className="share-meta-item">
                  <span className="meta-label">Token Prefix</span>
                  <span className="meta-val font-mono">{shareResult.token_prefix}***</span>
                </div>
              </div>

              <p className="notice-text">
                <strong>Important:</strong> The 256-bit bearer token in this link is generated
                cryptographically and returned <em>only once</em>. The server stores only its SHA-256
                digest. If you close this dialog without copying the link, you will need to create a
                new share.
              </p>

              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary w-full"
                  onClick={handleClose}
                >
                  Done
                </button>
              </div>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="share-form">
              <div className="form-group">
                <label htmlFor="recipient-email" className="form-label">
                  Recipient Microsoft Entra Email
                </label>
                <input
                  id="recipient-email"
                  type="email"
                  className="input"
                  placeholder="colleague@organization.com"
                  value={recipientEmail}
                  onChange={(e) => setRecipientEmail(e.target.value)}
                  disabled={isSubmitting}
                  required
                />
                <span className="form-hint">
                  Strictly recipient-bound: Entra ID account email must match during download.
                </span>
              </div>

              <div className="form-group">
                <label className="form-label">Access Duration</label>
                <div className="pill-group">
                  {(['1h', '24h', '7d', '30d', 'custom'] as const).map((opt) => (
                    <button
                      key={opt}
                      type="button"
                      className={`pill-btn ${expiryOption === opt ? 'pill-btn-active' : ''}`}
                      onClick={() => setExpiryOption(opt)}
                      disabled={isSubmitting}
                    >
                      {opt === '1h' && '1 Hour'}
                      {opt === '24h' && '24 Hours'}
                      {opt === '7d' && '7 Days'}
                      {opt === '30d' && '30 Days'}
                      {opt === 'custom' && 'Custom Date'}
                    </button>
                  ))}
                </div>

                {expiryOption === 'custom' && (
                  <div className="custom-date-wrap">
                    <input
                      type="datetime-local"
                      className="input"
                      value={customExpiryDate}
                      onChange={(e) => setCustomExpiryDate(e.target.value)}
                      min={new Date().toISOString().slice(0, 16)}
                      disabled={isSubmitting}
                      required
                    />
                  </div>
                )}
              </div>

              <div className="form-group">
                <label htmlFor="max-downloads" className="form-label">
                  Download Limit Quota
                </label>
                <div className="quota-input-wrap">
                  <input
                    id="max-downloads"
                    type="number"
                    className="input"
                    min={1}
                    max={MAX_DOWNLOADS_CAP}
                    value={maxDownloads}
                    onChange={(e) => setMaxDownloads(parseInt(e.target.value, 10) || 1)}
                    disabled={isSubmitting}
                    required
                  />
                  <span className="quota-desc">maximum downloads permitted</span>
                </div>
                <span className="form-hint">
                  The link automatically flips to EXHAUSTED once this limit is reached.
                </span>
              </div>

              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={handleClose}
                  disabled={isSubmitting}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={isSubmitting}
                >
                  {isSubmitting ? (
                    <>
                      <span className="btn-spinner" />
                      <span>Creating Grant...</span>
                    </>
                  ) : (
                    'Generate Share Link'
                  )}
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
