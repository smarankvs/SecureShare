import React from 'react';
import type { FileItem, ShareResponse } from '../types/index.ts';
import {
  BanIcon,
  FileIcon,
  FileImageIcon,
  FilePdfIcon,
  ShareIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
} from './Icons.tsx';

interface SharedByMeTableProps {
  shares: ShareResponse[];
  files: FileItem[];
  isLoading: boolean;
  onRevoke: (share: ShareResponse) => Promise<void>;
  revokingId?: string | null;
}

function formatDate(dateStr?: string | null): string {
  if (!dateStr) return '—';
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

function getFileIcon(fileName: string): React.ReactElement {
  const lowerName = fileName.toLowerCase();
  if (lowerName.endsWith('.pdf')) {
    return <FilePdfIcon className="file-icon-pdf" size={20} />;
  }
  if (
    lowerName.endsWith('.png') ||
    lowerName.endsWith('.jpg') ||
    lowerName.endsWith('.jpeg')
  ) {
    return <FileImageIcon className="file-icon-image" size={20} />;
  }
  return <FileIcon className="file-icon-default" size={20} />;
}

export function SharedByMeTable({
  shares,
  files,
  isLoading,
  onRevoke,
  revokingId,
}: SharedByMeTableProps) {
  if (isLoading) {
    return (
      <div className="table-loading-container">
        <div className="loading-spinner-ring" />
        <p>Loading your active access grants...</p>
      </div>
    );
  }

  if (shares.length === 0) {
    return (
      <div className="empty-table-state">
        <div className="empty-icon-wrap">
          <ShareIcon size={48} className="empty-icon" />
        </div>
        <h3 className="empty-title">No outgoing share grants</h3>
        <p className="empty-desc">
          You have not shared any documents yet. Click "Share" on any file in your document list to
          create a recipient-bound, time-limited access grant.
        </p>
      </div>
    );
  }

  const handleRevokeClick = (share: ShareResponse) => {
    const docName =
      share.file_name ||
      files.find((f) => f.id === share.file_id)?.original_name ||
      'this document';

    const confirmed = window.confirm(
      `Are you sure you want to revoke access for ${share.recipient_email} to "${docName}"?\n\nThe recipient will immediately lose all permissions to view or download this document. The original file will not be affected.`
    );

    if (confirmed) {
      onRevoke(share);
    }
  };

  return (
    <div className="file-table-wrapper">
      <table className="file-table">
        <thead>
          <tr>
            <th>Document</th>
            <th>Recipient</th>
            <th>Status</th>
            <th>Downloads</th>
            <th>Date Shared</th>
            <th>Expires</th>
            <th className="text-right">Action</th>
          </tr>
        </thead>
        <tbody>
          {shares.map((share) => {
            const isCurrentlyRevoking = revokingId === share.id;
            const docName =
              share.file_name ||
              files.find((f) => f.id === share.file_id)?.original_name ||
              `Document (${share.file_id.slice(0, 8)})`;
            const isRevoked = share.status === 'REVOKED';
            const isExhausted = share.status === 'EXHAUSTED';
            const isExpired = share.status === 'EXPIRED';
            const isActive = share.status === 'ACTIVE';

            return (
              <tr key={share.id} className={isRevoked ? 'row-blocked' : ''}>
                <td className="cell-filename">
                  <div className="filename-container">
                    {getFileIcon(docName)}
                    <div className="filename-text-wrap">
                      <span className="filename-text" title={docName}>
                        {docName}
                      </span>
                      <span className="hash-subtext">
                        Prefix: {share.token_prefix}***
                      </span>
                    </div>
                  </div>
                </td>
                <td className="cell-recipient">
                  <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>
                    {share.recipient_email}
                  </span>
                </td>
                <td className="cell-status">
                  {isActive && (
                    <span className="badge badge-clean">
                      <ShieldCheckIcon size={12} />
                      <span>Active</span>
                    </span>
                  )}
                  {isRevoked && (
                    <span className="badge badge-infected">
                      <BanIcon size={12} />
                      <span>Revoked</span>
                    </span>
                  )}
                  {isExhausted && (
                    <span className="badge badge-error">
                      <ShieldAlertIcon size={12} />
                      <span>Exhausted</span>
                    </span>
                  )}
                  {isExpired && (
                    <span className="badge badge-error">
                      <span>Expired</span>
                    </span>
                  )}
                </td>
                <td className="cell-downloads">
                  <span style={{ fontSize: '0.8125rem' }}>
                    {share.download_count} / {share.max_downloads}
                  </span>
                </td>
                <td className="cell-date">{formatDate(share.created_at)}</td>
                <td className="cell-expires">{formatDate(share.expires_at)}</td>
                <td className="cell-actions text-right">
                  {isRevoked ? (
                    <span
                      style={{
                        fontSize: '0.75rem',
                        color: 'var(--text-muted)',
                        fontStyle: 'italic',
                      }}
                    >
                      Revoked
                    </span>
                  ) : (
                    <button
                      type="button"
                      className="btn btn-danger btn-sm"
                      onClick={() => handleRevokeClick(share)}
                      disabled={isCurrentlyRevoking}
                      title={`Revoke access for ${share.recipient_email}`}
                    >
                      {isCurrentlyRevoking ? (
                        <>
                          <span className="btn-spinner" />
                          <span>Revoking...</span>
                        </>
                      ) : (
                        <>
                          <BanIcon size={14} />
                          <span>Revoke Access</span>
                        </>
                      )}
                    </button>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
