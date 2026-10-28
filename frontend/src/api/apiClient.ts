import axios, {
  type AxiosError,
  type AxiosInstance,
  type InternalAxiosRequestConfig,
} from 'axios';
import { API_BASE_URL } from '../auth/authConfig.ts';
import type {
  ApiErrorResponse,
  FileDetailResponse,
  FileListResponse,
  FileUploadResponse,
  LoginRequest,
  RegisterRequest,
  ShareCreateRequest,
  ShareCreatedResponse,
  ShareDownloadResponse,
  ShareListResponse,
  ShareRevokeResponse,
  TokenResponse,
  UserProfile,
  UserResponse,
} from '../types/index.ts';

const TOKEN_STORAGE_KEY = 'secureshare_access_token';

/**
 * Retrieve the current session JWT access token from tab sessionStorage.
 */
export function getStoredAccessToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_STORAGE_KEY);
  } catch {
    return null;
  }
}

/**
 * Persist or clear the session JWT access token.
 */
export function setStoredAccessToken(token: string | null): void {
  try {
    if (token) {
      sessionStorage.setItem(TOKEN_STORAGE_KEY, token);
    } else {
      sessionStorage.removeItem(TOKEN_STORAGE_KEY);
    }
  } catch (e) {
    console.error('Failed to update session token', e);
  }
}

/**
 * Custom application API error wrapping backend error payloads.
 */
export class ApiError extends Error {
  public statusCode: number;
  public errorCode: string;
  public details?: unknown;

  constructor(message: string, statusCode: number, errorCode: string = 'API_ERROR', details?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.statusCode = statusCode;
    this.errorCode = errorCode;
    this.details = details;
  }
}

/**
 * Determine if a target URL belongs to our trusted API backend.
 * Avoids leaking bearer tokens to arbitrary 3rd party endpoints.
 */
function isTrustedBackendUrl(url?: string): boolean {
  if (!url) return false;
  if (url.startsWith('/') || url.startsWith('./')) return true;
  try {
    const parsedTarget = new URL(url, window.location.origin);
    const parsedBase = new URL(API_BASE_URL, window.location.origin);
    return parsedTarget.origin === parsedBase.origin;
  } catch {
    return false;
  }
}

/**
 * Configured Axios client instance.
 */
export const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    Accept: 'application/json',
  },
});

/**
 * Bearer Token Request Interceptor.
 * Attaches local JWT access token from session storage to trusted requests.
 */
apiClient.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const fullUrl = config.url?.startsWith('http')
      ? config.url
      : `${config.baseURL || ''}${config.url || ''}`;

    if (!isTrustedBackendUrl(fullUrl)) {
      return config;
    }

    const token = getStoredAccessToken();
    if (token) {
      config.headers.set('Authorization', `Bearer ${token}`);
    }

    return config;
  },
  (error) => Promise.reject(error)
);

/**
 * Centralized Response Interceptor for Error Normalization.
 */
apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError<ApiErrorResponse>) => {
    if (error.response) {
      const { status, data } = error.response;
      const backendError = data?.error;
      const message =
        backendError?.message ||
        (typeof data === 'object' && data !== null && 'detail' in data
          ? String((data as { detail: unknown }).detail)
          : null) ||
        error.message ||
        'Server request failed';

      const errorCode = backendError?.code || `HTTP_${status}`;
      const details = backendError?.details;

      switch (status) {
        case 400:
          return Promise.reject(new ApiError(message || 'Bad request', 400, errorCode, details));
        case 401:
          return Promise.reject(
            new ApiError(
              message || 'Authentication required or session expired. Please sign in again.',
              401,
              errorCode,
              details
            )
          );
        case 403:
          return Promise.reject(
            new ApiError(
              message || 'You do not have permission to access or perform this operation.',
              403,
              errorCode,
              details
            )
          );
        case 404:
          return Promise.reject(
            new ApiError(
              message || 'The requested resource or share link was not found.',
              404,
              errorCode,
              details
            )
          );
        case 413:
          return Promise.reject(
            new ApiError(
              message || 'File size exceeds maximum allowed upload limit of 25MB.',
              413,
              errorCode,
              details
            )
          );
        case 415:
          return Promise.reject(
            new ApiError(
              message || 'File type not allowed. Please upload PDF, PNG, JPG, or DOCX files.',
              415,
              errorCode,
              details
            )
          );
        case 422:
          return Promise.reject(
            new ApiError(
              message || 'Validation error. Please verify the submitted data.',
              422,
              errorCode,
              details
            )
          );
        case 429:
          return Promise.reject(
            new ApiError(
              message || 'Too many requests. Please wait a moment and try again.',
              429,
              errorCode,
              details
            )
          );
        default:
          if (status >= 500) {
            return Promise.reject(
              new ApiError(
                'A backend server error occurred. Please try again later.',
                status,
                errorCode,
                details
              )
            );
          }
          return Promise.reject(new ApiError(message, status, errorCode, details));
      }
    } else if (error.request) {
      return Promise.reject(
        new ApiError(
          'Network connection error. Please verify the SecureShare backend is running on ' +
            API_BASE_URL,
          0,
          'NETWORK_ERROR'
        )
      );
    }

    return Promise.reject(new ApiError(error.message, 0, 'CLIENT_ERROR'));
  }
);

// ==============================================================================
// Typed API Methods
// ==============================================================================

/**
 * Authenticate with email and password and receive JWT tokens.
 */
export async function loginUser(payload: LoginRequest): Promise<TokenResponse> {
  const response = await apiClient.post<TokenResponse>('/api/v1/auth/login', payload);
  if (response.data.access_token) {
    setStoredAccessToken(response.data.access_token);
  }
  return response.data;
}

/**
 * Register a new user account with email and password.
 */
export async function registerUser(payload: RegisterRequest): Promise<UserResponse> {
  const response = await apiClient.post<UserResponse>('/api/v1/auth/register', payload);
  return response.data;
}

/**
 * Terminate user session.
 */
export async function logoutUser(): Promise<void> {
  try {
    await apiClient.post('/api/v1/auth/logout');
  } catch {
    // Best-effort logout notification
  } finally {
    setStoredAccessToken(null);
  }
}

/**
 * Fetch current user profile.
 */
export async function getCurrentUser(): Promise<UserProfile> {
  const response = await apiClient.get<UserProfile>('/api/v1/users/me');
  return response.data;
}

/**
 * Fetch files owned by authenticated user.
 */
export async function getFiles(skip: number = 0, limit: number = 50): Promise<FileListResponse> {
  const response = await apiClient.get<FileListResponse>('/api/v1/files', {
    params: { skip, limit },
  });
  return response.data;
}

/**
 * Fetch specific file details and SAS URL.
 */
export async function getFileDetails(fileId: string): Promise<FileDetailResponse> {
  const response = await apiClient.get<FileDetailResponse>(`/api/v1/files/${fileId}`);
  return response.data;
}

/**
 * Upload a document or image to the secure storage pipeline.
 */
export async function uploadFile(
  file: File,
  onUploadProgress?: (progress: number) => void
): Promise<FileUploadResponse> {
  const formData = new FormData();
  formData.append('file', file);

  const response = await apiClient.post<FileUploadResponse>('/api/v1/upload', formData, {
    // Note: Do not set Content-Type header manually to allow browser to calculate boundary correctly
    onUploadProgress: (progressEvent) => {
      if (onUploadProgress && progressEvent.total) {
        const percent = Math.round((progressEvent.loaded * 100) / progressEvent.total);
        onUploadProgress(percent);
      }
    },
  });

  return response.data;
}

/**
 * Permanently delete a file.
 */
export async function deleteFile(fileId: string): Promise<{ message: string }> {
  const response = await apiClient.delete<{ message: string }>(`/api/v1/files/${fileId}`);
  return response.data;
}

/**
 * Create a new recipient-bound share grant (POST /api/v1/shares).
 */
export async function createShare(payload: ShareCreateRequest): Promise<ShareCreatedResponse> {
  const response = await apiClient.post<ShareCreatedResponse>('/api/v1/shares', payload);
  return response.data;
}

/**
 * List shares created by the caller.
 */
export async function listShares(fileId?: string): Promise<ShareListResponse> {
  const response = await apiClient.get<ShareListResponse>('/api/v1/shares', {
    params: fileId ? { file_id: fileId } : {},
  });
  return response.data;
}

/**
 * Revoke an active share grant.
 */
export async function revokeShare(shareId: string): Promise<ShareRevokeResponse> {
  const response = await apiClient.post<ShareRevokeResponse>(`/api/v1/shares/${shareId}/revoke`);
  return response.data;
}

/**
 * Gatekeeper shared-file download (POST /api/v1/shares/download).
 * The token is sent in the JSON request body.
 */
export async function downloadSharedFile(token: string): Promise<ShareDownloadResponse> {
  const response = await apiClient.post<ShareDownloadResponse>('/api/v1/shares/download', {
    token,
  });
  return response.data;
}

/**
 * Download file binary blob using either short-lived SAS URL or backend streaming endpoint,
 * and trigger a native browser file save dialog.
 */
export async function triggerFileDownload(downloadUrl: string, fileName: string): Promise<void> {
  // If downloadUrl is a relative path to our backend (e.g. /api/v1/files/download/...),
  // fetch it with our authenticated axios client so bearer token is attached!
  const isRelative = downloadUrl.startsWith('/');
  const isSameOriginBackend = isTrustedBackendUrl(downloadUrl);

  if (isRelative || isSameOriginBackend) {
    const response = await apiClient.get<Blob>(downloadUrl, {
      responseType: 'blob',
    });
    const contentType = response.headers['content-type'];
    const blob = new Blob([response.data], {
      type: typeof contentType === 'string' ? contentType : 'application/octet-stream',
    });
    const blobUrl = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = blobUrl;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(blobUrl);
  } else {
    // For direct Azure Blob SAS URL, create a temporary link or fetch blob
    try {
      const resp = await fetch(downloadUrl);
      if (!resp.ok) {
        throw new Error(`Direct download failed with status ${resp.status}`);
      }
      const blob = await resp.blob();
      const blobUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = blobUrl;
      link.download = fileName;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(blobUrl);
    } catch {
      // Fallback: direct window navigation
      const link = document.createElement('a');
      link.href = downloadUrl;
      link.download = fileName;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    }
  }
}
