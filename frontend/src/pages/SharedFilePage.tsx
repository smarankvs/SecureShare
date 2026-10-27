import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { downloadSharedFile, triggerFileDownload } from '../api/apiClient.ts';
import { useAuth } from '../auth/useAuth.ts';
import {
  CheckIcon,
  DownloadIcon,
  FileIcon,
  MicrosoftIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
} from '../components/Icons.tsx';
import { Navbar } from '../components/Navbar.tsx';
import type { ShareDownloadResponse } from '../types/index.ts';

export function SharedFilePage() {
  const { token } = useParams<{ token: string }>();
  const { isAuthenticated, user, login, isLoading: authLoading } = useAuth();

  const [isDownloading, setIsDownloading] = useState<boolean>(false);
  const [downloadSuccess, setDownloadSuccess] = useState<ShareDownloadResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const isValidToken = Boolean(token && token.trim().length >= 16);

  const handleSignIn = async () => {
    // Preserve current URL (/share/:token) so user returns here after Entra ID login
    await login(window.location.pathname);
  };

  const handleDownload = async () => {
    if (!token || !isAuthenticated || isDownloading) return;

    setIsDownloading(true);
    setErrorMessage(null);

    try {
      // 1. Submit token in POST body to evaluate the 4 policy gates atomically
      const shareData = await downloadSharedFile(token);

      // 2. Fetch and trigger browser file save
      await triggerFileDownload(shareData.download_url, shareData.file_name);

      setDownloadSuccess(shareData);
    } catch (err: unknown) {
      const errorObj = err as { statusCode?: number; message?: string };
      if (errorObj.statusCode === 404) {
        setErrorMessage(
          'This share link is either invalid, expired, revoked, quota-exhausted, or addressed to a different recipient email.'
        );
      } else if (errorObj.statusCode === 401) {
        setErrorMessage('Your session has expired. Please sign in again to verify your identity.');
      } else {
        setErrorMessage(
          errorObj.message ||
            'Unable to download file. Please verify network connectivity and backend status.'
        );
      }
    } finally {
      setIsDownloading(false);
    }
  };

  return (
    <div className="shared-page-layout">
      <Navbar />

      <main className="shared-page-main">
        <div className="shared-page-container">
          <div className="shared-file-card">
            <div className="shared-card-header">
              <div className="shared-icon-badge">
                <FileIcon size={32} />
              </div>
              <h1 className="shared-title">Protected Document Transfer</h1>
              <p className="shared-subtitle">
                A document has been securely shared with you via SecureShare.
              </p>
            </div>

            {!isValidToken ? (
              <div className="alert alert-error">
                <ShieldAlertIcon size={20} />
                <div>
                  <strong>Invalid Share Link</strong>
                  <p className="alert-sub">
                    The link appears incomplete or malformed. Please request a new share link from
                    the document owner.
                  </p>
                </div>
              </div>
            ) : (
              <div className="shared-content">
                {/* Gatekeeper Security Notice */}
                <div className="security-notice-box">
                  <div className="notice-icon">
                    <ShieldCheckIcon size={20} />
                  </div>
                  <div className="notice-content">
                    <span className="notice-title">Zero-Trust Access Control Enforced</span>
                    <p className="notice-body">
                      This link requires recipient identity verification. Access is only granted if
                      your authenticated Microsoft Entra ID email matches the designated recipient.
                    </p>
                  </div>
                </div>

                {errorMessage && (
                  <div className="alert alert-error" role="alert">
                    <ShieldAlertIcon size={20} />
                    <span>{errorMessage}</span>
                  </div>
                )}

                {downloadSuccess ? (
                  <div className="download-complete-box">
                    <div className="success-badge-wrap">
                      <CheckIcon size={24} className="text-emerald" />
                    </div>
                    <h2 className="download-complete-title">Download Initiated!</h2>
                    <p className="download-filename">{downloadSuccess.file_name}</p>
                    <div className="download-stats-grid">
                      <div className="stat-pill">
                        <span className="pill-label">Size:</span>
                        <span className="pill-val">
                          {(downloadSuccess.size / (1024 * 1024)).toFixed(2)} MB
                        </span>
                      </div>
                      <div className="stat-pill">
                        <span className="pill-label">Remaining downloads:</span>
                        <span className="pill-val">{downloadSuccess.remaining_downloads}</span>
                      </div>
                    </div>
                    <button
                      type="button"
                      className="btn btn-secondary mt-4"
                      onClick={handleDownload}
                      disabled={isDownloading || downloadSuccess.remaining_downloads <= 0}
                    >
                      {downloadSuccess.remaining_downloads > 0
                        ? 'Download Again'
                        : 'Download Limit Reached'}
                    </button>
                  </div>
                ) : !isAuthenticated ? (
                  <div className="auth-required-box">
                    <p className="auth-prompt-text">
                      Please sign in with your authorized Microsoft Entra ID account to verify your
                      recipient identity and unlock the download.
                    </p>
                    <button
                      type="button"
                      className="btn btn-entra w-full"
                      onClick={handleSignIn}
                      disabled={authLoading}
                    >
                      {authLoading ? (
                        <>
                          <span className="btn-spinner" />
                          <span>Checking authentication...</span>
                        </>
                      ) : (
                        <>
                          <MicrosoftIcon size={20} />
                          <span>Sign in to Unlock Document</span>
                        </>
                      )}
                    </button>
                  </div>
                ) : (
                  <div className="authenticated-download-box">
                    <div className="recipient-verified-banner">
                      <span className="verified-label">Authenticated as:</span>
                      <strong className="verified-email">{user?.email}</strong>
                    </div>

                    <button
                      type="button"
                      className="btn btn-primary btn-lg w-full"
                      onClick={handleDownload}
                      disabled={isDownloading}
                    >
                      {isDownloading ? (
                        <>
                          <span className="btn-spinner" />
                          <span>Verifying 4-Gates &amp; Generating SAS...</span>
                        </>
                      ) : (
                        <>
                          <DownloadIcon size={20} />
                          <span>Download Secured Document</span>
                        </>
                      )}
                    </button>
                    <p className="download-quota-hint">
                      This action will evaluate status, expiration, download quota, and recipient
                      binding atomically.
                    </p>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
