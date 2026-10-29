import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { AuthContext, type AuthContextType, type AuthUser } from './AuthContext.ts';
import {
  getCurrentUser,
  getStoredAccessToken,
  loginUser,
  logoutUser,
  registerUser,
  setStoredAccessToken,
} from '../api/apiClient.ts';

const REDIRECT_STORAGE_KEY = 'secureshare_intended_path';

interface AuthProviderProps {
  children: React.ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(() => Boolean(getStoredAccessToken()));
  const [error, setError] = useState<string | null>(null);

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  const getAccessToken = useCallback(() => {
    return getStoredAccessToken();
  }, []);

  // Hydrate user profile on initial load if session token exists
  useEffect(() => {
    let mounted = true;
    const token = getStoredAccessToken();
    if (!token) {
      return;
    }

    getCurrentUser()
      .then((profile) => {
        if (mounted) {
          setUser({
            id: profile.id,
            name: profile.name,
            email: profile.email,
            username: profile.email,
          });
          setIsLoading(false);
        }
      })
      .catch(() => {
        if (mounted) {
          setStoredAccessToken(null);
          setUser(null);
          setIsLoading(false);
        }
      });

    return () => {
      mounted = false;
    };
  }, []);

  const login = useCallback(
    async (email: string, password: string, redirectPath?: string) => {
      setError(null);
      setIsLoading(true);
      try {
        const tokenRes = await loginUser({ email, password });
        setStoredAccessToken(tokenRes.access_token);

        // Fetch user profile
        const profile = await getCurrentUser();
        setUser({
          id: profile.id,
          name: profile.name,
          email: profile.email,
          username: profile.email,
        });

        const target =
          redirectPath || sessionStorage.getItem(REDIRECT_STORAGE_KEY) || '/';
        sessionStorage.removeItem(REDIRECT_STORAGE_KEY);
        window.location.href = target;
      } catch (err: unknown) {
        const errObj = err as Error;
        setError(errObj.message || 'Login failed. Please verify your credentials.');
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    []
  );

  const register = useCallback(
    async (name: string, email: string, password: string, redirectPath?: string) => {
      setError(null);
      setIsLoading(true);
      try {
        await registerUser({ name, email, password });
        // Automatically log in newly registered user
        await login(email, password, redirectPath);
      } catch (err: unknown) {
        const errObj = err as Error;
        setError(errObj.message || 'Registration failed. Please check input requirements.');
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [login]
  );

  const logout = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      await logoutUser();
    } finally {
      setStoredAccessToken(null);
      setUser(null);
      sessionStorage.removeItem(REDIRECT_STORAGE_KEY);
      setIsLoading(false);
      window.location.href = '/login';
    }
  }, []);

  const updateUser = useCallback((updatedFields: Partial<AuthUser>) => {
    setUser((prev) => (prev ? { ...prev, ...updatedFields } : null));
  }, []);

  const contextValue = useMemo<AuthContextType>(
    () => ({
      isAuthenticated: Boolean(user && getStoredAccessToken()),
      user,
      isLoading,
      error,
      login,
      register,
      logout,
      getAccessToken,
      clearError,
      updateUser,
    }),
    [user, isLoading, error, login, register, logout, getAccessToken, clearError, updateUser]
  );

  return <AuthContext.Provider value={contextValue}>{children}</AuthContext.Provider>;
}
