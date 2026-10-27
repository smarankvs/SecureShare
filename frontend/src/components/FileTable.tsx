import React from 'react';
import type { FileItem, ScanStatus } from '../types/index.ts';
import {
  DownloadIcon,
  FileIcon,
  FileImageIcon,
  FilePdfIcon,
  ShareIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  TrashIcon,
} from './Icons.tsx';

interface FileTableProps {
  files: FileItem[];
  isLoading: boolean;
  onShare: (file: FileItem) => void;
  onDownload: (file: FileItem) => void;
  onDelete: (file: FileItem) => void;
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

function renderScanStatusBadge(scanStatus?: ScanStatus | string) {
  const statusUpper = (scanStatus || '').toUpperCase();

  switch (statusUpper) {
    case 'CLEAN':
      return (
        <span className="badge badge-clean" title="Passed ClamAV heuristic & malware inspection">
          <ShieldCheckIcon size={14} />
          <span>Clean</span>
        </span>
      );
    case 'PENDING':
      return (
        <span className="badge badge-pending" title="Malware scan in progress">
          <span className="badge-pulse" />
          <span>Scanning...</span>
        </span>
      );
    case 'INFECTED':
      return (
        <span className="badge badge-infected" title="Threat detected: File blocked by quarantine">
          <ShieldAlertIcon size={14} />
          <span>Blocked</span>
        </span>
      );
    case 'ERROR':
      return (
        <span className="badge badge-error" title="Antivirus scan engine failed">
          <ShieldAlertIcon size={14} />
          <span>Scan Failed</span>
        </span>
      );
    default:
      // Default fallback for verified uploaded files
      return (
        <span className="badge badge-clean" title="Verified secure in cloud storage">
          <ShieldCheckIcon size={14} />
          <span>Clean</span>
        </span>
      );
  }
}

export function FileTable({
  files,
  isLoading,
  onShare,
  onDownload,
  onDelete,
}: FileTableProps) {
  if (isLoading) {
    return (
      <div className="table-loading-container">
        <div className="loading-spinner-ring" />
        <p>Loading encrypted documents...</p>
      </div>
    );
  }

  if (files.length === 0) {
    return (
      <div className="empty-table-state">
        <div className="empty-icon-wrap">
          <FileIcon size={48} className="empty-icon" />
        </div>
        <h3 className="empty-title">No documents yet</h3>
        <p className="empty-desc">
          Upload your sensitive documents (PDF, PNG, JPG, DOCX up to 25MB). All files undergo
          antivirus inspection and are secured in private Azure storage.
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
            <th>Type</th>
            <th>Size</th>
            <th>Uploaded</th>
            <th>Scan Status</th>
            <th className="text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          {files.map((file) => {
            const isBlocked = (file.scan_status || '').toUpperCase() === 'INFECTED';
            return (
              <tr key={file.id} className={isBlocked ? 'row-blocked' : ''}>
                <td className="cell-filename">
                  <div className="filename-container">
                    {getFileIcon(file.content_type, file.original_name)}
                    <div className="filename-text-wrap">
                      <span className="filename-text" title={file.original_name}>
                        {file.original_name}
                      </span>
                      {file.sha256_hash && (
                        <span
                          className="hash-subtext"
                          title={`SHA-256: ${file.sha256_hash}`}
                        >
                          SHA: {file.sha256_hash.slice(0, 8)}...{file.sha256_hash.slice(-6)}
                        </span>
                      )}
                    </div>
                  </div>
                </td>
                <td className="cell-type">
                  <span className="type-pill">{file.content_type.split('/')[1] || file.content_type}</span>
                </td>
                <td className="cell-size">{formatFileSize(file.size)}</td>
                <td className="cell-date">{formatDate(file.upload_time)}</td>
                <td className="cell-status">{renderScanStatusBadge(file.scan_status)}</td>
                <td className="cell-actions text-right">
                  <div className="action-buttons-group">
                    <button
                      type="button"
                      className="btn-icon"
                      onClick={() => onShare(file)}
                      disabled={isBlocked}
                      title={isBlocked ? 'Cannot share infected file' : 'Create secure share link'}
                    >
                      <ShareIcon size={16} />
                      <span className="sr-only">Share</span>
                    </button>

                    <button
                      type="button"
                      className="btn-icon"
                      onClick={() => onDownload(file)}
                      disabled={isBlocked}
                      title={isBlocked ? 'Cannot download blocked file' : 'Download document'}
                    >
                      <DownloadIcon size={16} />
                      <span className="sr-only">Download</span>
                    </button>

                    <button
                      type="button"
                      className="btn-icon btn-icon-danger"
                      onClick={() => onDelete(file)}
                      title="Delete permanently"
                    >
                      <TrashIcon size={16} />
                      <span className="sr-only">Delete</span>
                    </button>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
