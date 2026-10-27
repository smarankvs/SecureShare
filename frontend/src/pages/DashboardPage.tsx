import { useCallback, useEffect, useState } from 'react';
import { deleteFile, getFileDetails, getFiles, triggerFileDownload } from '../api/apiClient.ts';
import { useAuth } from '../auth/useAuth.ts';
import { FileTable } from '../components/FileTable.tsx';
import {
  FileIcon,
  RefreshIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  UploadCloudIcon,
} from '../components/Icons.tsx';
import { Navbar } from '../components/Navbar.tsx';
import { ShareModal } from '../components/ShareModal.tsx';
import { UploadModal } from '../components/UploadModal.tsx';
import type { FileItem } from '../types/index.ts';

export function DashboardPage() {
  const { user } = useAuth();

  const [files, setFiles] = useState<FileItem[]>([]);
  const [totalFiles, setTotalFiles] = useState<number>(0);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

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

  useEffect(() => {
    let mounted = true;
    getFiles(0, 100)
      .then((response) => {
        if (mounted) {
          setFiles(response.files);
          setTotalFiles(response.total);
          setIsLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (mounted) {
          const errorObj = err as Error;
          setError(errorObj.message || 'Unable to load documents from backend.');
          setIsLoading(false);
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
                grants with Microsoft Entra ID verification.
              </p>
            </div>

            <div className="dashboard-actions">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={fetchFiles}
                disabled={isLoading}
                title="Refresh document list"
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
                <span className="stat-label">Total Documents</span>
                <span className="stat-val">{totalFiles}</span>
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
                <span className="stat-val">Active (ClamAV &amp; Magic Bytes)</span>
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
                  onClick={fetchFiles}
                >
                  Retry
                </button>
              </div>
            </div>
          )}

          {/* File Management Table */}
          <div className="table-card">
            <div className="table-card-header">
              <h2 className="table-card-title">Encrypted Documents</h2>
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
