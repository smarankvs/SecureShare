import {
  EventType,
  PublicClientApplication,
  type AccountInfo,
  type AuthenticationResult,
} from '@azure/msal-browser';
import { msalConfig } from './authConfig.ts';

/**
 * Singleton PublicClientApplication instance for the entire application.
 * Never instantiate multiple PublicClientApplications in the same runtime.
 */
export const msalInstance = new PublicClientApplication(msalConfig);

let isInitialized = false;
let initPromise: Promise<PublicClientApplication> | null = null;

/**
 * Asynchronously initialize MSAL and handle any redirect responses from Entra ID.
 * Returns the initialized singleton instance.
 */
export async function initializeMsal(): Promise<PublicClientApplication> {
  if (isInitialized) {
    return msalInstance;
  }

  if (initPromise) {
    return initPromise;
  }

  initPromise = (async () => {
    try {
      await msalInstance.initialize();

      // Listen for authentication events to automatically update the active account
      msalInstance.addEventCallback((event) => {
        if (
          (event.eventType === EventType.LOGIN_SUCCESS ||
            event.eventType === EventType.ACQUIRE_TOKEN_SUCCESS) &&
          event.payload
        ) {
          const authResult = event.payload as AuthenticationResult;
          if (authResult.account) {
            msalInstance.setActiveAccount(authResult.account);
          }
        }

        if (event.eventType === EventType.LOGOUT_SUCCESS) {
          msalInstance.setActiveAccount(null);
        }
      });

      // Handle redirect promise from Entra ID redirect flow
      const response = await msalInstance.handleRedirectPromise();
      if (response?.account) {
        msalInstance.setActiveAccount(response.account);
      } else {
        const currentActive = msalInstance.getActiveAccount();
        if (!currentActive) {
          const accounts = msalInstance.getAllAccounts();
          if (accounts.length > 0 && accounts[0]) {
            msalInstance.setActiveAccount(accounts[0]);
          }
        }
      }

      isInitialized = true;
      return msalInstance;
    } catch (error) {
      console.error('[SecureShare] MSAL Initialization or Redirect Handling Error:', error);
      isInitialized = true; // Mark as initialized to prevent blocking app render
      return msalInstance;
    }
  })();

  return initPromise;
}

/**
 * Helper to retrieve currently active account.
 */
export function getActiveAccount(): AccountInfo | null {
  return msalInstance.getActiveAccount();
}
