/**
 * Data contracts and TypeScript interfaces for SecureShare Frontend.
 * Perfectly aligned with FastAPI backend schemas (Member 2 & 3).
 */

export type ScanStatus = 'PENDING' | 'CLEAN' | 'INFECTED' | 'ERROR';

export type ShareStatus = 'ACTIVE' | 'REVOKED' | 'EXHAUSTED' | 'EXPIRED';

export interface UserProfile {
  id: string;
  name: string;
  email: string;
  username?: string | null;
  is_active: boolean;
  created_at?: string;
  auth_source?: string;
}

export interface FileItem {
  id: string;
  blob_name: string;
  original_name: string;
  content_type: string;
  size: number;
  upload_time: string;
  blob_url?: string;
  download_url?: string;
  sha256_hash?: string | null;
  scan_status?: ScanStatus;
}

export interface FileListResponse {
  total: number;
  files: FileItem[];
}

export interface FileDetailResponse {
  id: string;
  blob_name: string;
  original_name: string;
  content_type: string;
  size: number;
  upload_time: string;
  download_url: string;
  sha256_hash?: string | null;
}

export interface FileUploadResponse {
  id: string;
  blob_name: string;
  original_name: string;
  content_type: string;
  size: number;
  upload_time: string;
  blob_url: string;
  sha256_hash?: string | null;
}

export interface ShareCreateRequest {
  file_id: string;
  recipient_email: string;
  expires_at: string; // ISO 8601 UTC
  max_downloads: number; // 1 to 100
}

export interface ShareCreatedResponse {
  share_id: string;
  file_id: string;
  recipient_email: string;
  token: string;
  token_prefix: string;
  share_url: string;
  expires_at: string;
  max_downloads: number;
  status: ShareStatus;
}

export interface ShareResponse {
  id: string;
  file_id: string;
  file_name?: string | null;
  recipient_email: string;
  token_prefix: string;
  status: ShareStatus;
  expires_at: string;
  max_downloads: number;
  download_count: number;
  created_at: string;
  last_downloaded_at?: string | null;
  revoked_at?: string | null;
  revoked_by?: string | null;
}

export interface ShareListResponse {
  total: number;
  shares: ShareResponse[];
}

export interface ShareRevokeResponse {
  id: string;
  status: ShareStatus;
  revoked_at?: string | null;
  revoked_by?: string | null;
}

export interface ShareDownloadRequest {
  token: string;
}

export interface ShareDownloadResponse {
  share_id: string;
  file_name: string;
  content_type: string;
  size: number;
  sha256_hash?: string | null;
  download_url: string;
  expires_in_seconds: number;
  remaining_downloads: number;
}

export interface ApiErrorDetail {
  loc?: (string | number)[];
  msg?: string;
  type?: string;
  input?: unknown;
}

export interface ApiErrorPayload {
  code: string;
  message: string;
  status_code: number;
  details?: ApiErrorDetail[] | string | null;
}

export interface ApiErrorResponse {
  error: ApiErrorPayload;
}

export interface LoginRequest {
  identifier?: string;
  email?: string;
  password: string;
}

export interface RegisterRequest {
  name: string;
  email: string;
  password: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface UserResponse {
  id: string;
  name: string;
  email: string;
  username?: string | null;
  is_active: boolean;
  created_at: string;
}

export interface UserProfileUpdate {
  name: string;
}

export interface SharedWithMeItem {
  share_id: string;
  file_id: string;
  file_name: string;
  size: number;
  content_type: string;
  sender_name: string;
  sender_email: string;
  shared_at: string;
  expires_at: string;
  status: string;
  max_downloads: number;
  download_count: number;
  remaining_downloads: number;
  can_download: boolean;
}

export interface SharedWithMeResponse {
  total: number;
  documents: SharedWithMeItem[];
}
