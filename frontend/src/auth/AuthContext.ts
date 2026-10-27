import { createContext } from 'react';
import type { AccountInfo } from '@azure/msal-browser';

export interface AuthUser {
  name: string;
  email: string;
  username: string;
  oid?: string;
  homeAccountId?: string;
}

export interface AuthContextType {
  isAuthenticated: boolean;
  user: AuthUser | null;
  account: AccountInfo | null;
  isLoading: boolean;
  error: string | null;
  isEntraConfigured: boolean;
  login: (redirectPath?: string) => Promise<void>;
  logout: () => Promise<void>;
  getAccessToken: () => Promise<string | null>;
  clearError: () => void;
}

export const AuthContext = createContext<AuthContextType | undefined>(undefined);
