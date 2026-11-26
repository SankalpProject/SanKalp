/** Wire contracts of the auth API (mirror the Java DTOs). */
export interface OtpRequested {
  expiresInSeconds: number;
  resendAfterSeconds: number;
}

export interface AuthTokens {
  tokenType: 'Bearer';
  accessToken: string;
  /** Seconds until the access token expires. */
  expiresIn: number;
  refreshToken: string;
  refreshExpiresIn: number;
}

export type SessionStatus = 'restoring' | 'signedOut' | 'signedIn';
