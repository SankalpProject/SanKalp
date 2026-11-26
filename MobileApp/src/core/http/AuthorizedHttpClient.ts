import { ApiError } from './errors';
import type { HttpClient, HttpRequest } from './HttpClient';

/** What the HTTP layer needs from the session (Interface Segregation: nothing more). */
export interface AccessTokenProvider {
  getAccessToken(): Promise<string>;
  /** Forces a token refresh (e.g. the server rejected the current one). */
  refreshAccessToken(): Promise<string>;
}

/**
 * Decorator that adds `Authorization: Bearer …` and transparently retries once after refreshing
 * when the server answers 401 (e.g. the access token was revoked or the clock drifted).
 */
export class AuthorizedHttpClient implements HttpClient {
  constructor(
    private readonly inner: HttpClient,
    private readonly tokens: AccessTokenProvider,
  ) {}

  async request<T>(request: HttpRequest): Promise<T> {
    const token = await this.tokens.getAccessToken();
    try {
      return await this.inner.request<T>(withBearer(request, token));
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        const fresh = await this.tokens.refreshAccessToken();
        return this.inner.request<T>(withBearer(request, fresh));
      }
      throw error;
    }
  }
}

function withBearer(request: HttpRequest, token: string): HttpRequest {
  return { ...request, headers: { ...request.headers, Authorization: `Bearer ${token}` } };
}
