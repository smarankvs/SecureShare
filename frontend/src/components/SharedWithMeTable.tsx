import React from 'react';
import type { SharedWithMeItem } from '../types/index.ts';
import {
  DownloadIcon,
  FileIcon,
  FileImageIcon,
  FilePdfIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  UsersIcon,
} from './Icons.tsx';

interface SharedWithMeTableProps {
  items: SharedWithMeItem[];
  isLoading: boolean;
  onDownload: (item: SharedWithMeItem) => void;
  downloadingId?: string | null;
}

function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

function formatDate(dateStr: string): string {
  try {
    const d = new Date(dateStr);
    return new Intl.DateTimeFormat('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }).format(d);
  } catch {
    return dateStr;
  }
}

function getFileIcon(contentType: string, fileName: string): React.ReactElement {
  const lowerName = fileName.toLowerCase();
  if (contentType.includes('pdf') || lowerName.endsWith('.pdf')) {
    return <FilePdfIcon className="file-icon-pdf" size={20} />;
  }
  if (
    contentType.startsWith('image/') ||
    lowerName.endsWith('.png') ||
    lowerName.endsWith('.jpg') ||
    lowerName.endsWith('.jpeg')
  ) {
    return <FileImageIcon className="file-icon-image" size={20} />;
  }
  return <FileIcon className="file-icon-default" size={20} />;
}

export function SharedWithMeTable({
  items,
  isLoading,
  onDownload,
  downloadingId,
}: SharedWithMeTableProps) {
  if (isLoading) {
    return (
      <div className="table-loading-container">
        <div className="loading-spinner-ring" />
        <p>Loading documents shared with you...</p>
      </div>
    );
  }

  if (items.length === 0) {
    return (
      <div className="empty-table-state">
        <div className="empty-icon-wrap">
          <UsersIcon size={48} className="empty-icon" />
        </div>
        <h3 className="empty-title">No documents shared with you yet</h3>
        <p className="empty-desc">
          When another SecureShare user shares an encrypted document with your registered email,
          it will automatically appear here for direct zero-trust download.
        </p>
      </div>
    );
  }

  return (
    <div className="file-table-wrapper">
      <table className="file-table">
        <thead>
          <tr>
            <th>Document</th>
            <th>Shared By</th>
            <th>Size</th>
            <th>Date Shared</th>
            <th>Expires</th>
            <th>Quota Left</th>
            <th className="text-right">Action</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => {
            const isCurrentlyDownloading = downloadingId === item.share_id;
            const isExpired = item.status === 'EXPIRED';
            const isAvailable = item.can_download && item.remaining_downloads > 0 && !isExpired;

            return (
              <tr key={item.share_id} className={!isAvailable ? 'row-blocked' : ''}>
                <td className="cell-filename">
                  <div className="filename-container">
                    {getFileIcon(item.content_type, item.file_name)}
                    <div className="filename-text-wrap">
                      <span className="filename-text" title={item.file_name}>
                        {item.file_name}
                      </span>
                      <span className="hash-subtext">
                        {item.content_type.split('/')[1] || item.content_type}
                      </span>
                    </div>
                  </div>
                </td>
                <td className="cell-sender">
                  <div style={{ display: 'flex', flexDirection: 'column' }}>
                    <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                      {item.sender_name}
                    </span>
                    <span
                      style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}
                      title={item.sender_email}
                    >
                      {item.sender_email}
                    </span>
                  </div>
                </td>
                <td className="cell-size">{formatFileSize(item.size)}</td>
                <td className="cell-date">{formatDate(item.shared_at)}</td>
                <td className="cell-expires">
                  {isExpired ? (
                    <span className="badge badge-error">Expired</span>
                  ) : (
                    <span>{formatDate(item.expires_at)}</span>
                  )}
                </td>
                <td className="cell-quota">
                  <span
                    className={`badge ${
                      item.remaining_downloads > 0 ? 'badge-clean' : 'badge-error'
                    }`}
                  >
                    {item.remaining_downloads > 0 ? (
                      <>
                        <ShieldCheckIcon size={12} />
                        <span>{item.remaining_downloads} / {item.max_downloads} left</span>
                      </>
                    ) : (
                      <>
                        <ShieldAlertIcon size={12} />
                        <span>Exhausted</span>
                      </>
                    )}
                  </span>
                </td>
                <td className="cell-actions text-right">
                  <button
                    type="button"
                    className="btn btn-primary btn-sm"
                    onClick={() => onDownload(item)}
                    disabled={!isAvailable || isCurrentlyDownloading}
                    title={
                      !isAvailable
                        ? 'Download quota reached or share expired'
                        : 'Download secured document'
                    }
                  >
                    {isCurrentlyDownloading ? (
                      <>
                        <span className="btn-spinner" />
                        <span>Downloading...</span>
                      </>
                    ) : (
                      <>
                        <DownloadIcon size={14} />
                        <span>Download</span>
                      </>
                    )}
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
