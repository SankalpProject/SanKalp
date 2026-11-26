import { ApiError, NetworkError } from '../src/core/http/errors';
import { InMemoryTokenStorage } from '../src/core/storage/SecureTokenStorage';
import { SessionExpiredError, SessionManager } from '../src/features/auth/session/SessionManager';
import { FakeAuthRepository, tokens } from '../test/testDoubles';

describe('SessionManager', () => {
  let repo: FakeAuthRepository;
  let storage: InMemoryTokenStorage;
  let now: number;
  let session: SessionManager;

  beforeEach(() => {
    repo = new FakeAuthRepository();
    storage = new InMemoryTokenStorage();
    now = 1_000_000;
    session = new SessionManager(repo, storage, () => now);
  });

  it('starts signed out when no refresh token is stored', async () => {
    await session.restore();
    expect(session.getStatus()).toBe('signedOut');
    expect(repo.refresh).not.toHaveBeenCalled();
  });

  it('signIn persists only the refresh token and serves the access token from memory', async () => {
    await session.signIn(tokens(1));
    expect(session.getStatus()).toBe('signedIn');
    expect(await storage.getRefreshToken()).toBe('refresh-1');
    expect(await session.getAccessToken()).toBe('access-1');
    expect(repo.refresh).not.toHaveBeenCalled();
  });

  it('refreshes an expiring access token and rotates the stored refresh token', async () => {
    await session.signIn(tokens(1, 60));
    now += 45_000; // inside the 30s skew window
    expect(await session.getAccessToken()).toBe('access-2');
    expect(repo.refresh).toHaveBeenCalledWith('refresh-1');
    expect(await storage.getRefreshToken()).toBe('refresh-2');
  });

  it('makes concurrent refreshes share a single request (avoids refresh-token reuse)', async () => {
    await storage.setRefreshToken('refresh-1');
    const results = await Promise.all([
      session.refreshAccessToken(),
      session.refreshAccessToken(),
      session.refreshAccessToken(),
    ]);
    expect(results).toEqual(['access-2', 'access-2', 'access-2']);
    expect(repo.refresh).toHaveBeenCalledTimes(1);
  });

  it('signs out and wipes storage when the server rejects the refresh token', async () => {
    await session.signIn(tokens(1));
    repo.refresh.mockRejectedValueOnce(new ApiError(401, 'INVALID_REFRESH_TOKEN', 'expired'));
    await expect(session.refreshAccessToken()).rejects.toBeInstanceOf(SessionExpiredError);
    expect(session.getStatus()).toBe('signedOut');
    expect(await storage.getRefreshToken()).toBeNull();
  });

  it('keeps the session when offline at startup', async () => {
    await storage.setRefreshToken('refresh-1');
    repo.refresh.mockRejectedValueOnce(new NetworkError());
    await session.restore();
    expect(session.getStatus()).toBe('signedIn');
    expect(await storage.getRefreshToken()).toBe('refresh-1');
  });

  it('signOut clears locally even if the server call fails, and revokes server-side', async () => {
    await session.signIn(tokens(1));
    repo.logout.mockRejectedValueOnce(new NetworkError());
    await session.signOut();
    expect(session.getStatus()).toBe('signedOut');
    expect(await storage.getRefreshToken()).toBeNull();
    expect(repo.logout).toHaveBeenCalledWith('refresh-1');
  });
});
