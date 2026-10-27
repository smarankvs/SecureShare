import React, { useCallback, useEffect, useRef, useState } from 'react';
import { uploadFile } from '../api/apiClient.ts';
import {
  CloseIcon,
  FileIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  UploadCloudIcon,
} from './Icons.tsx';

interface UploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

const MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024; // 25 Megabytes
const ALLOWED_EXTENSIONS = ['.pdf', '.png', '.jpg', '.jpeg', '.docx'];
const ALLOWED_MIME_TYPES = [
  'application/pdf',
  'image/png',
  'image/jpeg',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
];

export function UploadModal({ isOpen, onClose, onSuccess }: UploadModalProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [isUploading, setIsUploading] = useState<boolean>(false);
  const [uploadProgress, setUploadProgress] = useState<number>(0);
  const [apiError, setApiError] = useState<string | null>(null);
  const [isSuccess, setIsSuccess] = useState<boolean>(false);
  const [isDragOver, setIsDragOver] = useState<boolean>(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const resetState = useCallback(() => {
    setSelectedFile(null);
    setValidationError(null);
    setIsUploading(false);
    setUploadProgress(0);
    setApiError(null);
    setIsSuccess(false);
    setIsDragOver(false);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  }, []);

  const handleClose = useCallback(() => {
    if (isUploading) return;
    resetState();
    onClose();
  }, [isUploading, resetState, onClose]);

  // Handle ESC key to close modal
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen && !isUploading) {
        handleClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, isUploading, handleClose]);

  const validateFile = (file: File): string | null => {
    if (!file) return 'No file selected.';

    if (file.size === 0) {
      return 'File is empty (0 bytes). Please select a valid document.';
    }

    if (file.size > MAX_FILE_SIZE_BYTES) {
      const sizeMB = (file.size / (1024 * 1024)).toFixed(1);
      return `File size (${sizeMB} MB) exceeds the maximum limit of 25 MB.`;
    }

    const lowerName = file.name.toLowerCase();
    const hasValidExt = ALLOWED_EXTENSIONS.some((ext) => lowerName.endsWith(ext));

    if (!hasValidExt) {
      return `Invalid file extension. Allowed extensions are: ${ALLOWED_EXTENSIONS.join(', ')}`;
    }

    if (file.type && !ALLOWED_MIME_TYPES.includes(file.type)) {
      return `Invalid file MIME type (${file.type}). Allowed types: PDF, PNG, JPEG, DOCX.`;
    }

    return null;
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    setValidationError(null);
    setApiError(null);

    if (!file) {
      setSelectedFile(null);
      return;
    }

    const error = validateFile(file);
    if (error) {
      setValidationError(error);
      setSelectedFile(null);
    } else {
      setSelectedFile(file);
    }
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(false);
    setValidationError(null);
    setApiError(null);

    const file = e.dataTransfer.files?.[0];
    if (!file) return;

    const error = validateFile(file);
    if (error) {
      setValidationError(error);
      setSelectedFile(null);
    } else {
      setSelectedFile(file);
    }
  };

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(false);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile || isUploading) return;

    const error = validateFile(selectedFile);
    if (error) {
      setValidationError(error);
      return;
    }

    setIsUploading(true);
    setUploadProgress(0);
    setApiError(null);

    try {
      await uploadFile(selectedFile, (progress) => {
        setUploadProgress(progress);
      });
      setIsSuccess(true);
      setTimeout(() => {
        onSuccess();
        handleClose();
      }, 1200);
    } catch (err: unknown) {
      const error = err as Error;
      setApiError(error.message || 'Upload failed. Please check backend status and file content.');
      setIsUploading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-backdrop" onClick={handleClose} role="dialog" aria-modal="true">
      <div
        className="modal-card"
        onClick={(e) => e.stopPropagation()}
        aria-labelledby="upload-modal-title"
      >
        <div className="modal-header">
          <div className="modal-title-group">
            <div className="modal-icon-badge">
              <UploadCloudIcon size={20} />
            </div>
            <h2 id="upload-modal-title" className="modal-title">
              Upload Document
            </h2>
          </div>
          <button
            type="button"
            className="btn-icon"
            onClick={handleClose}
            disabled={isUploading}
            aria-label="Close modal"
          >
            <CloseIcon size={18} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="modal-body">
          {validationError && (
            <div className="alert alert-error" role="alert">
              <ShieldAlertIcon size={18} />
              <span>{validationError}</span>
            </div>
          )}

          {apiError && (
            <div className="alert alert-error" role="alert">
              <ShieldAlertIcon size={18} />
              <span>{apiError}</span>
            </div>
          )}

          {isSuccess && (
            <div className="alert alert-success" role="status">
              <ShieldCheckIcon size={18} />
              <span>Upload complete! Document scanned and encrypted.</span>
            </div>
          )}

          {!selectedFile ? (
            <div
              className={`dropzone ${isDragOver ? 'dropzone-active' : ''}`}
              onDrop={handleDrop}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onClick={() => fileInputRef.current?.click()}
            >
              <input
                ref={fileInputRef}
                type="file"
                className="sr-only"
                onChange={handleFileChange}
                accept=".pdf,.png,.jpg,.jpeg,.docx"
              />
              <UploadCloudIcon size={40} className="dropzone-icon" />
              <p className="dropzone-title">Click to browse or drag file here</p>
              <p className="dropzone-hint">
                Supported: PDF, PNG, JPG, DOCX &bull; Maximum 25 MB
              </p>
            </div>
          ) : (
            <div className="selected-file-card">
              <div className="selected-file-info">
                <FileIcon size={24} className="selected-file-icon" />
                <div className="selected-file-meta">
                  <span className="selected-file-name" title={selectedFile.name}>
                    {selectedFile.name}
                  </span>
                  <span className="selected-file-size">
                    {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB &bull; {selectedFile.type || 'document'}
                  </span>
                </div>
              </div>
              {!isUploading && !isSuccess && (
                <button
                  type="button"
                  className="btn-icon"
                  onClick={() => {
                    setSelectedFile(null);
                    if (fileInputRef.current) fileInputRef.current.value = '';
                  }}
                  title="Remove selected file"
                >
                  <CloseIcon size={16} />
                </button>
              )}
            </div>
          )}

          {isUploading && (
            <div className="progress-container">
              <div className="progress-header">
                <span className="progress-label">
                  {uploadProgress < 100 ? 'Streaming to quarantine pipeline...' : 'Scanning for threats...'}
                </span>
                <span className="progress-percent">{uploadProgress}%</span>
              </div>
              <div className="progress-bar-bg">
                <div
                  className="progress-bar-fill"
                  style={{ width: `${uploadProgress}%` }}
                />
              </div>
            </div>
          )}

          <div className="modal-footer">
            <button
              type="button"
              className="btn btn-secondary"
              onClick={handleClose}
              disabled={isUploading}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={!selectedFile || isUploading || isSuccess}
            >
              {isUploading ? (
                <>
                  <span className="btn-spinner" />
                  <span>Processing...</span>
                </>
              ) : (
                'Upload & Protect'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
