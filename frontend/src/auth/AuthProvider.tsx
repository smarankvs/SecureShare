import React, {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from 'react';
import {
  MsalProvider,
  useAccount,
  useIsAuthenticated,
  useMsal,
} from '@azure/msal-react';
import {
  InteractionRequiredAuthError,
} from '@azure/msal-browser';
import {
  isEntraConfigured,
  loginRequest,
  tokenRequest,
} from './authConfig.ts';
import {
  initializeMsal,
  msalInstance,
} from './msalInstance.ts';
import { AuthContext, type AuthContextType, type AuthUser } from './AuthContext.ts';

const REDIRECT_STORAGE_KEY = 'secureshare_intended_path';

interface AuthProviderInnerProps {
  children: React.ReactNode;
}

function AuthProviderInner({ children }: AuthProviderInnerProps) {
  const { instance, accounts, inProgress } = useMsal();
  const rawIsAuthenticated = useIsAuthenticated();
  const activeAccount = useAccount(accounts[0] || null);

  const [authError, setAuthError] = useState<string | null>(null);

  // Sync active account if not set
  useEffect(() => {
    if (!instance.getActiveAccount() && accounts.length > 0 && accounts[0]) {
      instance.setActiveAccount(accounts[0]);
    }
  }, [accounts, instance]);

  const currentAccount = instance.getActiveAccount() || activeAccount || (accounts.length > 0 ? accounts[0] : null);

  const user: AuthUser | null = useMemo(() => {
    if (!currentAccount) {
      return null;
    }
    const idTokenClaims = currentAccount.idTokenClaims as Record<string, unknown> | undefined;
    const email =
      (idTokenClaims?.email as string) ||
      (idTokenClaims?.preferred_username as string) ||
      currentAccount.username ||
      '';
    const name = currentAccount.name || (idTokenClaims?.name as string) || email.split('@')[0] || 'User';
    const oid = (idTokenClaims?.oid as string) || '';

    return {
      name,
      email,
      username: currentAccount.username,
      oid,
      homeAccountId: currentAccount.homeAccountId,
    };
  }, [currentAccount]);

  const isAuthenticated = rawIsAuthenticated && Boolean(currentAccount);

  const clearError = useCallback(() => {
    setAuthError(null);
  }, []);

  const login = useCallback(
    async (redirectPath?: string) => {
      setAuthError(null);
      if (redirectPath) {
        sessionStorage.setItem(REDIRECT_STORAGE_KEY, redirectPath);
      }

      if (!isEntraConfigured) {
        setAuthError(
          'Microsoft Entra ID is not yet configured. Please set VITE_ENTRA_CLIENT_ID and VITE_ENTRA_TENANT_ID in frontend/.env.'
        );
        return;
      }

      try {
        // Try popup login first for a seamless SPA experience, fallback to redirect
        const response = await instance.loginPopup(loginRequest);
        if (response.account) {
          instance.setActiveAccount(response.account);
        }

        const storedRedirect = sessionStorage.getItem(REDIRECT_STORAGE_KEY);
        if (storedRedirect) {
          sessionStorage.removeItem(REDIRECT_STORAGE_KEY);
          window.location.href = storedRedirect;
        }
      } catch (popupError: unknown) {
        // If popup was blocked or failed, fallback to redirect
        const err = popupError as { errorCode?: string; message?: string };
        if (
          err.errorCode === 'popup_window_error' ||
          err.errorCode === 'empty_window_error' ||
          err.errorCode === 'user_cancelled'
        ) {
          try {
            await instance.loginRedirect(loginRequest);
          } catch (redirectError: unknown) {
            const redirectErr = redirectError as Error;
            setAuthError(redirectErr.message || 'Login redirect failed');
          }
        } else {
          setAuthError(err.message || 'Failed to authenticate with Microsoft Entra ID');
        }
      }
    },
    [instance]
  );

  const logout = useCallback(async () => {
    setAuthError(null);
    sessionStorage.removeItem(REDIRECT_STORAGE_KEY);
    try {
      await instance.logoutRedirect({
        account: instance.getActiveAccount(),
        postLogoutRedirectUri: `${window.location.origin}/login`,
      });
    } catch (err: unknown) {
      const error = err as Error;
      setAuthError(error.message || 'Logout failed');
    }
  }, [instance]);

  const getAccessToken = useCallback(async (): Promise<string | null> => {
    const account = instance.getActiveAccount() || (accounts.length > 0 ? accounts[0] : null);
    if (!account) {
      return null;
    }

    try {
      const result = await instance.acquireTokenSilent({
        ...tokenRequest,
        account,
      });
      return result.accessToken;
    } catch (silentError) {
      if (silentError instanceof InteractionRequiredAuthError) {
        try {
          const result = await instance.acquireTokenPopup({
            ...tokenRequest,
            account,
          });
          return result.accessToken;
        } catch (interactiveError: unknown) {
          const err = interactiveError as Error;
          setAuthError(err.message || 'Failed to refresh authentication token');
          return null;
        }
      }
      console.warn('[SecureShare] Silent token acquisition warning:', silentError);
      return null;
    }
  }, [instance, accounts]);

  // Handle post-redirect destination restoration after MSAL handles redirect
  useEffect(() => {
    if (isAuthenticated && inProgress === 'none') {
      const storedRedirect = sessionStorage.getItem(REDIRECT_STORAGE_KEY);
      if (storedRedirect) {
        sessionStorage.removeItem(REDIRECT_STORAGE_KEY);
        if (window.location.pathname !== storedRedirect) {
          window.location.href = storedRedirect;
        }
      }
    }
  }, [isAuthenticated, inProgress]);

  const isLoading = inProgress !== 'none';

  const contextValue = useMemo<AuthContextType>(
    () => ({
      isAuthenticated,
      user,
      account: currentAccount ?? null,
      isLoading,
      error: authError,
      isEntraConfigured,
      login,
      logout,
      getAccessToken,
      clearError,
    }),
    [
      isAuthenticated,
      user,
      currentAccount,
      isLoading,
      authError,
      login,
      logout,
      getAccessToken,
      clearError,
    ]
  );

  return <AuthContext.Provider value={contextValue}>{children}</AuthContext.Provider>;
}

export interface AuthProviderProps {
  children: React.ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [msalReady, setMsalReady] = useState(false);

  useEffect(() => {
    let mounted = true;
    initializeMsal()
      .then(() => {
        if (mounted) {
          setMsalReady(true);
        }
      })
      .catch((err) => {
        console.error('[SecureShare] MSAL bootstrap error:', err);
        if (mounted) {
          setMsalReady(true);
        }
      });
    return () => {
      mounted = false;
    };
  }, []);

  if (!msalReady) {
    return (
      <div className="auth-bootstrap-loading">
        <div className="loading-spinner-ring" />
        <p>Initializing Secure Identity Services...</p>
      </div>
    );
  }

  return (
    <MsalProvider instance={msalInstance}>
      <AuthProviderInner>{children}</AuthProviderInner>
    </MsalProvider>
  );
}
