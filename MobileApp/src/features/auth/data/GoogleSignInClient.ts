import {
  GoogleSignin,
  isCancelledResponse,
  isErrorWithCode,
  statusCodes,
} from '@react-native-google-signin/google-signin';

/** Outcome of the native Google account picker. */
export type GoogleSignInResult =
  | { type: 'success'; idToken: string }
  | { type: 'cancelled' };

export class GoogleSignInError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GoogleSignInError';
  }
}

/** Abstraction over the native SDK, so UI/session code stays testable and the SDK can be swapped. */
export interface GoogleSignInClient {
  readonly isConfigured: boolean;
  signIn(): Promise<GoogleSignInResult>;
  signOut(): Promise<void>;
}

/**
 * Native Google Sign-In. Only the ID token is used; it is sent to OUR backend, which verifies it.
 * We never request Google API scopes or offline access, so no Google access/refresh tokens exist in the app.
 */
export class NativeGoogleSignInClient implements GoogleSignInClient {
  readonly isConfigured: boolean;

  constructor(webClientId: string) {
    this.isConfigured = webClientId.length > 0;
    if (this.isConfigured) {
      GoogleSignin.configure({ webClientId, offlineAccess: false });
    }
  }

  async signIn(): Promise<GoogleSignInResult> {
    if (!this.isConfigured) {
      throw new GoogleSignInError('Google sign-in is not configured.');
    }
    try {
      await GoogleSignin.hasPlayServices({ showPlayServicesUpdateDialog: true });
      const response = await GoogleSignin.signIn();
      if (isCancelledResponse(response)) {
        return { type: 'cancelled' };
      }
      const idToken = response.data.idToken;
      if (!idToken) {
        throw new GoogleSignInError('Google did not return an ID token. Check the web client id.');
      }
      return { type: 'success', idToken };
    } catch (error) {
      if (error instanceof GoogleSignInError) {
        throw error;
      }
      if (isErrorWithCode(error)) {
        if (error.code === statusCodes.SIGN_IN_CANCELLED) {
          return { type: 'cancelled' };
        }
        if (error.code === statusCodes.IN_PROGRESS) {
          return { type: 'cancelled' };
        }
        if (error.code === statusCodes.PLAY_SERVICES_NOT_AVAILABLE) {
          throw new GoogleSignInError('Google Play Services is not available on this device.');
        }
      }
      throw new GoogleSignInError('Google sign-in failed. Please try again.');
    }
  }

  async signOut(): Promise<void> {
    if (this.isConfigured) {
      await GoogleSignin.signOut();
    }
  }
}
