import React, { createContext, PropsWithChildren, useContext, useSyncExternalStore } from 'react';
import { env } from '../config/env';
import { AuthorizedHttpClient } from '../core/http/AuthorizedHttpClient';
import { FetchHttpClient } from '../core/http/FetchHttpClient';
import { KeychainTokenStorage } from '../core/storage/KeychainTokenStorage';
import { AuthRepository, HttpAuthRepository } from '../features/auth/data/AuthRepository';
import { GoogleSignInClient, NativeGoogleSignInClient } from '../features/auth/data/GoogleSignInClient';
import { SessionManager } from '../features/auth/session/SessionManager';
import { HomeRepository, HttpHomeRepository } from '../features/home/data/HomeRepository';

/** Everything the UI may depend on — all as interfaces/abstractions. */
export interface Dependencies {
  authRepository: AuthRepository;
  googleSignIn: GoogleSignInClient;
  homeRepository: HomeRepository;
  session: SessionManager;
  /** Ends our session (server + device) and clears the Google account selection. */
  signOut: () => Promise<void>;
}

/**
 * Composition root: the only place that wires concrete implementations together.
 * Tests pass their own Dependencies with fakes.
 */
export function createDependencies(): Dependencies {
  const http = new FetchHttpClient(env.apiBaseUrl, env.requestTimeoutMs);
  const authRepository = new HttpAuthRepository(http);
  const session = new SessionManager(authRepository, new KeychainTokenStorage());
  const authorizedHttp = new AuthorizedHttpClient(http, session);
  const googleSignIn = new NativeGoogleSignInClient(env.googleWebClientId);
  return {
    authRepository,
    googleSignIn,
    session,
    homeRepository: new HttpHomeRepository(authorizedHttp),
    signOut: createSignOut(session, googleSignIn),
  };
}

export function createSignOut(session: SessionManager, googleSignIn: GoogleSignInClient) {
  return async () => {
    await session.signOut();
    await googleSignIn.signOut().catch(() => undefined); // best effort
  };
}

const DependenciesContext = createContext<Dependencies | null>(null);

export function DependenciesProvider({ value, children }: PropsWithChildren<{ value: Dependencies }>) {
  return <DependenciesContext.Provider value={value}>{children}</DependenciesContext.Provider>;
}

export function useDependencies(): Dependencies {
  const deps = useContext(DependenciesContext);
  if (!deps) {
    throw new Error('useDependencies must be used inside <DependenciesProvider>');
  }
  return deps;
}

export function useSessionStatus() {
  const { session } = useDependencies();
  return useSyncExternalStore(session.subscribe, session.getStatus);
}
