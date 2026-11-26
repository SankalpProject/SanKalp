import type { AccessTokenProvider } from '../../../core/http/AuthorizedHttpClient';
import { ApiError, NetworkError } from '../../../core/http/errors';
import type { SecureTokenStorage } from '../../../core/storage/SecureTokenStorage';
import type { AuthRepository } from '../data/AuthRepository';
import type { AuthTokens, SessionStatus } from '../domain/types';

export class SessionExpiredError extends Error {
  constructor() {
    super('Session expired');
    this.name = 'SessionExpiredError';
  }
}

/** Refresh a little early so a token never expires mid-request. */
const EXPIRY_SKEW_MS = 30_000;

/**
 * Single source of truth for the user's session (framework-agnostic; React binds to it via subscribe()).
 *
 * - Access token: memory only. Refresh token: Keychain/Keystore.
 * - Refresh is single-flight: concurrent callers share one request. This matters because the server
 *   rotates refresh tokens and treats a reused token as theft (revoking the session).
 */
export class SessionManager implements AccessTokenProvider {
  private status: SessionStatus = 'restoring';
  private accessToken: string | null = null;
  private accessTokenExpiresAt = 0;
  private refreshInFlight: Promise<string> | null = null;
  private readonly listeners = new Set<() => void>();

  constructor(
    private readonly authRepository: AuthRepository,
    private readonly storage: SecureTokenStorage,
    private readonly now: () => number = Date.now,
  ) {}

  // ----- observable state (useSyncExternalStore-compatible) -----

  getStatus = (): SessionStatus => this.status;

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  // ----- lifecycle -----

  /** Called once at app start: resumes the session if a refresh token is stored. */
  async restore(): Promise<void> {
    const refreshToken = await this.storage.getRefreshToken();
    if (!refreshToken) {
      this.setStatus('signedOut');
      return;
    }
    try {
      await this.refreshAccessToken();
      this.setStatus('signedIn');
    } catch (error) {
      if (error instanceof NetworkError) {
        // Offline: keep the stored session; the next API call will refresh.
        this.setStatus('signedIn');
      } else {
        this.setStatus('signedOut');
      }
    }
  }

  async signIn(tokens: AuthTokens): Promise<void> {
    await this.applyTokens(tokens);
    this.setStatus('signedIn');
  }

  /** Clears local state first, so sign-out always succeeds on the device, then revokes server-side. */
  async signOut(): Promise<void> {
    const refreshToken = await this.storage.getRefreshToken();
    await this.clearLocal();
    if (refreshToken) {
      this.authRepository.logout(refreshToken).catch(() => {
        /* best effort: the token will also expire on its own */
      });
    }
  }

  // ----- AccessTokenProvider -----

  async getAccessToken(): Promise<string> {
    if (this.accessToken && this.now() < this.accessTokenExpiresAt - EXPIRY_SKEW_MS) {
      return this.accessToken;
    }
    return this.refreshAccessToken();
  }

  refreshAccessToken(): Promise<string> {
    if (!this.refreshInFlight) {
      this.refreshInFlight = this.performRefresh().finally(() => {
        this.refreshInFlight = null;
      });
    }
    return this.refreshInFlight;
  }

  // ----- internals -----

  private async performRefresh(): Promise<string> {
    const refreshToken = await this.storage.getRefreshToken();
    if (!refreshToken) {
      await this.clearLocal();
      throw new SessionExpiredError();
    }
    try {
      const tokens = await this.authRepository.refresh(refreshToken);
      await this.applyTokens(tokens);
      return tokens.accessToken;
    } catch (error) {
      if (error instanceof ApiError && (error.status === 401 || error.status === 400)) {
        await this.clearLocal();
        throw new SessionExpiredError();
      }
      throw error;
    }
  }

  private async applyTokens(tokens: AuthTokens): Promise<void> {
    await this.storage.setRefreshToken(tokens.refreshToken);
    this.accessToken = tokens.accessToken;
    this.accessTokenExpiresAt = this.now() + tokens.expiresIn * 1000;
  }

  private async clearLocal(): Promise<void> {
    this.accessToken = null;
    this.accessTokenExpiresAt = 0;
    try {
      await this.storage.clear();
    } finally {
      this.setStatus('signedOut');
    }
  }

  private setStatus(status: SessionStatus) {
    if (this.status !== status) {
      this.status = status;
      this.listeners.forEach(listener => listener());
    }
  }
}
