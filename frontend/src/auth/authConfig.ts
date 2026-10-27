import {
  LogLevel,
  type Configuration,
  type PopupRequest,
  type RedirectRequest,
  type SilentRequest,
} from '@azure/msal-browser';

/**
 * Microsoft Entra ID (formerly Azure AD) Configuration for SecureShare SPA.
 * Values are injected through Vite environment variables (prefixed with VITE_).
 */
export const ENTRA_CLIENT_ID: string = import.meta.env.VITE_ENTRA_CLIENT_ID || '';
export const ENTRA_TENANT_ID: string = import.meta.env.VITE_ENTRA_TENANT_ID || 'common';
export const ENTRA_REDIRECT_URI: string =
  import.meta.env.VITE_ENTRA_REDIRECT_URI || window.location.origin;
export const ENTRA_POST_LOGOUT_REDIRECT_URI: string =
  import.meta.env.VITE_ENTRA_POST_LOGOUT_REDIRECT_URI || `${window.location.origin}/login`;

// Backend exposed scope for authorization, e.g. "api://<backend-client-id>/access_as_user"
export const ENTRA_API_SCOPE: string =
  import.meta.env.VITE_ENTRA_API_SCOPE ||
  (ENTRA_CLIENT_ID ? `api://${ENTRA_CLIENT_ID}/access_as_user` : '');

export const API_BASE_URL: string =
  import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

export const isEntraConfigured = Boolean(
  ENTRA_CLIENT_ID &&
  ENTRA_TENANT_ID &&
  ENTRA_CLIENT_ID !== '00000000-0000-0000-0000-000000000000' &&
  !ENTRA_CLIENT_ID.startsWith('your-')
);

export const msalConfig: Configuration = {
  auth: {
    clientId: ENTRA_CLIENT_ID || '00000000-0000-0000-0000-000000000000',
    authority: `https://login.microsoftonline.com/${ENTRA_TENANT_ID || 'common'}`,
    redirectUri: ENTRA_REDIRECT_URI,
    postLogoutRedirectUri: ENTRA_POST_LOGOUT_REDIRECT_URI,
  },
  cache: {
    cacheLocation: 'sessionStorage',
  },
  system: {
    loggerOptions: {
      loggerCallback: (level: LogLevel, message: string, containsPii: boolean) => {
        if (containsPii) {
          return;
        }
        switch (level) {
          case LogLevel.Error:
            console.error('[SecureShare MSAL Error]:', message);
            return;
          case LogLevel.Warning:
            console.warn('[SecureShare MSAL Warning]:', message);
            return;
          default:
            return;
        }
      },
      logLevel: LogLevel.Warning,
    },
  },
};

/**
 * Scopes requested during user login.
 * Basic profile, OpenID, email, and optional backend API scope.
 */
export const loginRequest: RedirectRequest | PopupRequest = {
  scopes: [
    'openid',
    'profile',
    'email',
    ...(ENTRA_API_SCOPE ? [ENTRA_API_SCOPE] : []),
  ],
};

/**
 * Scopes for silent token acquisition passed to the custom FastAPI backend.
 */
export const tokenRequest: SilentRequest = {
  scopes: ENTRA_API_SCOPE ? [ENTRA_API_SCOPE] : ['openid', 'profile', 'email'],
};
