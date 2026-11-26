import { useCallback, useEffect, useState } from 'react';

/**
 * Seconds remaining until a deadline. Based on an absolute end time, so it stays correct
 * even if the app was in the background (timers pause there).
 */
export function useCountdown(initialSeconds: number) {
  const [endsAt, setEndsAt] = useState(() => Date.now() + initialSeconds * 1000);
  const [remaining, setRemaining] = useState(initialSeconds);

  useEffect(() => {
    const tick = () => setRemaining(Math.max(0, Math.ceil((endsAt - Date.now()) / 1000)));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [endsAt]);

  const restart = useCallback((seconds: number) => setEndsAt(Date.now() + seconds * 1000), []);

  return { remaining, restart };
}
