import { createContext } from 'react';

export interface AuthUser {
  id?: string;
  name: string;
  email: string;
  username?: string;
  role?: string;
}

export interface AuthContextType {
  isAuthenticated: boolean;
  user: AuthUser | null;
  isLoading: boolean;
  error: string | null;
  login: (email: string, password: string, redirectPath?: string) => Promise<void>;
  register: (name: string, email: string, password: string, redirectPath?: string) => Promise<void>;
  logout: () => Promise<void>;
  getAccessToken: () => string | null;
  clearError: () => void;
}

export const AuthContext = createContext<AuthContextType | undefined>(undefined);
