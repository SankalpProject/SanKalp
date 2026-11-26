import { useCallback, useRef, useState } from 'react';
import { useDependencies } from '../../../app/dependencies';
import { GoogleSignInError } from '../data/GoogleSignInClient';
import { toUserMessage } from '../domain/errorMessages';

/**
 * Google button logic: native account picker → ID token → our backend verifies it → our session.
 */
export function useGoogleSignIn() {
  const { googleSignIn, authRepository, session } = useDependencies();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);

  const signIn = useCallback(async () => {
    if (inFlight.current) {
      return;
    }
    inFlight.current = true;
    setLoading(true);
    setError(null);
    try {
      const result = await googleSignIn.signIn();
      if (result.type === 'cancelled') {
        return; // user closed the picker: not an error
      }
      const tokens = await authRepository.signInWithGoogle(result.idToken);
      await session.signIn(tokens); // RootNavigator reacts to the session change
    } catch (e) {
      setError(e instanceof GoogleSignInError ? e.message : toUserMessage(e));
      googleSignIn.signOut().catch(() => undefined); // let the user pick another account next time
    } finally {
      inFlight.current = false;
      setLoading(false);
    }
  }, [authRepository, googleSignIn, session]);

  return { available: googleSignIn.isConfigured, signIn, loading, error };
}
