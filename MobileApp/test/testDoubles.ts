import { ApiError } from '../src/core/http/errors';
import type { AuthRepository } from '../src/features/auth/data/AuthRepository';
import type { GoogleSignInClient, GoogleSignInResult } from '../src/features/auth/data/GoogleSignInClient';
import type { AuthTokens } from '../src/features/auth/domain/types';

export const tokens = (n = 1, expiresIn = 900): AuthTokens => ({
  tokenType: 'Bearer',
  accessToken: `access-${n}`,
  expiresIn,
  refreshToken: `refresh-${n}`,
  refreshExpiresIn: 2_592_000,
});

/** Fake backend: accepts OTP "123456" and the Google ID token "valid-google-id-token". */
export class FakeAuthRepository implements AuthRepository {
  requestOtp = jest.fn(async (_email: string) => ({ expiresInSeconds: 600, resendAfterSeconds: 30 }));
  verifyOtp = jest.fn(async (_email: string, code: string) => {
    if (code !== '123456') {
      throw new ApiError(401, 'OTP_INVALID', 'The code is invalid or has expired.');
    }
    return tokens(1);
  });
  signInWithGoogle = jest.fn(async (idToken: string) => {
    if (idToken !== 'valid-google-id-token') {
      throw new ApiError(401, 'INVALID_EXTERNAL_TOKEN', 'Sign-in failed.');
    }
    return tokens(1);
  });
  refresh = jest.fn(async (_refreshToken: string) => tokens(2));
  logout = jest.fn(async (_refreshToken: string) => undefined);
}

export class FakeGoogleSignInClient implements GoogleSignInClient {
  isConfigured = true;
  nextResult: GoogleSignInResult = { type: 'success', idToken: 'valid-google-id-token' };
  signIn = jest.fn(async () => this.nextResult);
  signOut = jest.fn(async () => undefined);
}
