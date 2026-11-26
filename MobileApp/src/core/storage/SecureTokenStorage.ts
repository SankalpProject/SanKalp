/**
 * Persists the refresh token in hardware-backed secure storage.
 * The access token is never persisted: it lives in memory only.
 */
export interface SecureTokenStorage {
  getRefreshToken(): Promise<string | null>;
  setRefreshToken(token: string): Promise<void>;
  clear(): Promise<void>;
}

/** For tests and as a fallback; loses the session on app restart. */
export class InMemoryTokenStorage implements SecureTokenStorage {
  private token: string | null = null;

  async getRefreshToken() {
    return this.token;
  }

  async setRefreshToken(token: string) {
    this.token = token;
  }

  async clear() {
    this.token = null;
  }
}
