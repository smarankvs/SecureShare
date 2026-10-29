import { useCallback, useEffect, useState } from 'react';
import {
  deleteFile,
  downloadSharedWithMeFile,
  getFileDetails,
  getFiles,
  getSharedWithMe,
  triggerFileDownload,
} from '../api/apiClient.ts';
import { useAuth } from '../auth/useAuth.ts';
import { FileTable } from '../components/FileTable.tsx';
import {
  FileIcon,
  RefreshIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  UploadCloudIcon,
  UsersIcon,
} from '../components/Icons.tsx';
import { Navbar } from '../components/Navbar.tsx';
import { ShareModal } from '../components/ShareModal.tsx';
import { SharedWithMeTable } from '../components/SharedWithMeTable.tsx';
import { UploadModal } from '../components/UploadModal.tsx';
import type { FileItem, SharedWithMeItem } from '../types/index.ts';

export function DashboardPage() {
  const { user } = useAuth();

  // My uploaded files state
  const [files, setFiles] = useState<FileItem[]>([]);
  const [totalFiles, setTotalFiles] = useState<number>(0);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Shared with me state
  const [sharedDocs, setSharedDocs] = useState<SharedWithMeItem[]>([]);
  const [totalShared, setTotalShared] = useState<number>(0);
  const [isSharedLoading, setIsSharedLoading] = useState<boolean>(true);
  const [downloadingShareId, setDownloadingShareId] = useState<string | null>(null);

  // Modals state
  const [isUploadOpen, setIsUploadOpen] = useState<boolean>(false);
  const [shareTargetFile, setShareTargetFile] = useState<FileItem | null>(null);

  // Operation feedback
  const [actionNotice, setActionNotice] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const fetchFiles = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await getFiles(0, 100);
      setFiles(response.files);
      setTotalFiles(response.total);
    } catch (err: unknown) {
      const errorObj = err as Error;
      setError(errorObj.message || 'Unable to load documents from backend.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  const fetchSharedDocs = useCallback(async () => {
    setIsSharedLoading(true);
    try {
      const response = await getSharedWithMe(0, 100);
      setSharedDocs(response.documents);
      setTotalShared(response.total);
    } catch {
      // Non-blocking for dashboard
      setSharedDocs([]);
      setTotalShared(0);
    } finally {
      setIsSharedLoading(false);
    }
  }, []);

  const refreshAll = useCallback(async () => {
    await Promise.all([fetchFiles(), fetchSharedDocs()]);
  }, [fetchFiles, fetchSharedDocs]);

  useEffect(() => {
    let mounted = true;
    Promise.all([getFiles(0, 100), getSharedWithMe(0, 100)])
      .then(([filesRes, sharedRes]) => {
        if (mounted) {
          setFiles(filesRes.files);
          setTotalFiles(filesRes.total);
          setSharedDocs(sharedRes.documents);
          setTotalShared(sharedRes.total);
          setIsLoading(false);
          setIsSharedLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (mounted) {
          const errorObj = err as Error;
          setError(errorObj.message || 'Unable to load documents from backend.');
          setIsLoading(false);
          setIsSharedLoading(false);
        }
      });
    return () => {
      mounted = false;
    };
  }, []);

  const handleDownload = async (file: FileItem) => {
    try {
      setActionNotice({ type: 'success', message: `Preparing secure download for ${file.original_name}...` });
      // Fetch fresh short-lived SAS download URL from file details endpoint
      const details = await getFileDetails(file.id);
      await triggerFileDownload(details.download_url, details.original_name);
      setActionNotice({ type: 'success', message: `Downloaded ${file.original_name}` });
      setTimeout(() => setActionNotice(null), 3000);
    } catch (err: unknown) {
      const errorObj = err as Error;
      setActionNotice({
        type: 'error',
        message: errorObj.message || `Failed to download ${file.original_name}`,
      });
      setTimeout(() => setActionNotice(null), 5000);
    }
  };

  const handleSharedDownload = async (item: SharedWithMeItem) => {
    try {
      setDownloadingShareId(item.share_id);
      setActionNotice({
        type: 'success',
        message: `Evaluating zero-trust policy gates and generating download for ${item.file_name}...`,
      });
      const res = await downloadSharedWithMeFile(item.share_id);
      await triggerFileDownload(res.download_url, res.file_name);
      setActionNotice({
        type: 'success',
        message: `Successfully downloaded ${res.file_name}`,
      });
      setTimeout(() => setActionNotice(null), 4000);
      fetchSharedDocs();
    } catch (err: unknown) {
      const errorObj = err as Error;
      setActionNotice({
        type: 'error',
        message: errorObj.message || `Failed to download ${item.file_name}`,
      });
      setTimeout(() => setActionNotice(null), 5000);
    } finally {
      setDownloadingShareId(null);
    }
  };

  const handleDelete = async (file: FileItem) => {
    const confirmed = window.confirm(
      `Are you sure you want to permanently delete "${file.original_name}"? This will delete the encrypted blob from storage and revoke all active share links.`
    );
    if (!confirmed) return;

    try {
      await deleteFile(file.id);
      setActionNotice({ type: 'success', message: `Permanently deleted ${file.original_name}` });
      setTimeout(() => setActionNotice(null), 3000);
      fetchFiles();
    } catch (err: unknown) {
      const errorObj = err as Error;
      setActionNotice({
        type: 'error',
        message: errorObj.message || `Failed to delete ${file.original_name}`,
      });
      setTimeout(() => setActionNotice(null), 5000);
    }
  };

  // Compute total bytes for quick stats
  const totalBytes = files.reduce((acc, f) => acc + (f.size || 0), 0);
  const totalMB = (totalBytes / (1024 * 1024)).toFixed(1);

  return (
    <div className="dashboard-layout">
      <Navbar />

      <main className="dashboard-main">
        <div className="dashboard-container">
          {/* Header Banner */}
          <div className="dashboard-header">
            <div>
              <h1 className="dashboard-title">Document Security Center</h1>
              <p className="dashboard-subtitle">
                Welcome, <strong>{user?.name}</strong>. Manage your encrypted documents and access
                grants with zero-trust local verification.
              </p>
            </div>

            <div className="dashboard-actions">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={refreshAll}
                disabled={isLoading || isSharedLoading}
                title="Refresh document lists"
              >
                <RefreshIcon size={16} />
                <span>Refresh</span>
              </button>

              <button
                type="button"
                className="btn btn-primary"
                onClick={() => setIsUploadOpen(true)}
              >
                <UploadCloudIcon size={18} />
                <span>Upload Document</span>
              </button>
            </div>
          </div>

          {/* Quick Stats Grid */}
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-icon-wrap stat-icon-blue">
                <FileIcon size={20} />
              </div>
              <div className="stat-info">
                <span className="stat-label">My Documents</span>
                <span className="stat-val">{totalFiles}</span>
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-icon-wrap stat-icon-emerald">
                <UsersIcon size={20} />
              </div>
              <div className="stat-info">
                <span className="stat-label">Shared With Me</span>
                <span className="stat-val">{totalShared}</span>
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-icon-wrap stat-icon-indigo">
                <UploadCloudIcon size={20} />
              </div>
              <div className="stat-info">
                <span className="stat-label">Storage Used</span>
                <span className="stat-val">{totalMB} MB</span>
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-icon-wrap stat-icon-emerald">
                <ShieldCheckIcon size={20} />
              </div>
              <div className="stat-info">
                <span className="stat-label">Security Pipeline</span>
                <span className="stat-val">Active (Argon2id &amp; ClamAV)</span>
              </div>
            </div>
          </div>

          {/* Action Notification */}
          {actionNotice && (
            <div
              className={`alert ${actionNotice.type === 'success' ? 'alert-success' : 'alert-error'}`}
              role="status"
            >
              {actionNotice.type === 'success' ? (
                <ShieldCheckIcon size={18} />
              ) : (
                <ShieldAlertIcon size={18} />
              )}
              <span>{actionNotice.message}</span>
            </div>
          )}

          {/* Error State with Retry */}
          {error && (
            <div className="alert alert-error" role="alert">
              <ShieldAlertIcon size={20} />
              <div className="alert-content-wrap">
                <span>{error}</span>
                <button
                  type="button"
                  className="btn btn-sm btn-secondary retry-btn"
                  onClick={refreshAll}
                >
                  Retry
                </button>
              </div>
            </div>
          )}

          {/* My Uploaded Files Management Table */}
          <div className="table-card">
            <div className="table-card-header">
              <h2 className="table-card-title">My Encrypted Documents</h2>
              <span className="table-count-badge">{totalFiles} items</span>
            </div>

            <FileTable
              files={files}
              isLoading={isLoading}
              onShare={(file) => setShareTargetFile(file)}
              onDownload={handleDownload}
              onDelete={handleDelete}
            />
          </div>

          {/* Shared With Me Section */}
          <div className="table-card" style={{ marginTop: '2rem' }}>
            <div className="table-card-header">
              <div>
                <h2 className="table-card-title">Shared With Me</h2>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                  Documents securely shared with your account by other users. Download directly without opening an external email link.
                </p>
              </div>
              <span className="table-count-badge">{totalShared} shared</span>
            </div>

            <SharedWithMeTable
              items={sharedDocs}
              isLoading={isSharedLoading}
              onDownload={handleSharedDownload}
              downloadingId={downloadingShareId}
            />
          </div>
        </div>
      </main>

      {/* Upload Modal */}
      <UploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onSuccess={() => {
          fetchFiles();
        }}
      />

      {/* Share Modal */}
      <ShareModal
        isOpen={Boolean(shareTargetFile)}
        file={shareTargetFile}
        onClose={() => setShareTargetFile(null)}
        onSuccess={() => {
          // Keep dialog open to allow copying share link
        }}
      />
    </div>
  );
}
