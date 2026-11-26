import type { HttpClient } from '../../../core/http/HttpClient';
import type { AuthTokens, OtpRequested } from '../domain/types';

/** Auth data source contract. UI and session logic depend on this, not on HTTP details. */
export interface AuthRepository {
  requestOtp(email: string): Promise<OtpRequested>;
  verifyOtp(email: string, code: string): Promise<AuthTokens>;
  signInWithGoogle(idToken: string): Promise<AuthTokens>;
  refresh(refreshToken: string): Promise<AuthTokens>;
  logout(refreshToken: string): Promise<void>;
}

export class HttpAuthRepository implements AuthRepository {
  constructor(private readonly http: HttpClient) {}

  requestOtp(email: string) {
    return this.http.request<OtpRequested>({
      method: 'POST',
      path: '/api/v1/auth/otp/request',
      body: { email },
    });
  }

  verifyOtp(email: string, code: string) {
    return this.http.request<AuthTokens>({
      method: 'POST',
      path: '/api/v1/auth/otp/verify',
      body: { email, code },
    });
  }

  signInWithGoogle(idToken: string) {
    return this.http.request<AuthTokens>({
      method: 'POST',
      path: '/api/v1/auth/google',
      body: { idToken },
    });
  }

  refresh(refreshToken: string) {
    return this.http.request<AuthTokens>({
      method: 'POST',
      path: '/api/v1/auth/token/refresh',
      body: { refreshToken },
    });
  }

  logout(refreshToken: string) {
    return this.http.request<void>({
      method: 'POST',
      path: '/api/v1/auth/logout',
      body: { refreshToken },
    });
  }
}
