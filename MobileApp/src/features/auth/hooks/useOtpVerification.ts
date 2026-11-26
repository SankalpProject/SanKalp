import { useCallback, useRef, useState } from 'react';
import { useDependencies } from '../../../app/dependencies';
import { env } from '../../../config/env';
import { ApiError } from '../../../core/http/errors';
import { toUserMessage } from '../domain/errorMessages';
import { digitsOnly, isValidOtp } from '../domain/validation';
import { useCountdown } from './useCountdown';

export function useOtpVerification(email: string, initialResendAfterSeconds: number) {
  const { authRepository, session } = useDependencies();
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [resending, setResending] = useState(false);
  const inFlight = useRef(false);
  const { remaining: resendIn, restart } = useCountdown(initialResendAfterSeconds);

  const verify = useCallback(
    async (value: string) => {
      if (inFlight.current || !isValidOtp(value, env.otpLength)) {
        return;
      }
      inFlight.current = true;
      setVerifying(true);
      setError(null);
      setInfo(null);
      try {
        const tokens = await authRepository.verifyOtp(email, value);
        await session.signIn(tokens); // RootNavigator reacts to the session change
      } catch (e) {
        setError(toUserMessage(e));
        setCode('');
      } finally {
        inFlight.current = false;
        setVerifying(false);
      }
    },
    [authRepository, email, session],
  );

  const onChangeCode = useCallback(
    (text: string) => {
      const value = digitsOnly(text, env.otpLength);
      setCode(value);
      setError(null);
      if (value.length === env.otpLength) {
        verify(value); // auto-submit when complete (also works with SMS autofill)
      }
    },
    [verify],
  );

  const resend = useCallback(async () => {
    if (resendIn > 0 || resending) {
      return;
    }
    setResending(true);
    setError(null);
    setInfo(null);
    try {
      const result = await authRepository.requestOtp(email);
      restart(result.resendAfterSeconds);
      setCode('');
      setInfo('A new code has been sent.');
    } catch (e) {
      if (e instanceof ApiError && e.retryAfterSeconds) {
        restart(e.retryAfterSeconds);
      }
      setError(toUserMessage(e));
    } finally {
      setResending(false);
    }
  }, [authRepository, email, resendIn, resending, restart]);

  return {
    code,
    onChangeCode,
    submit: () => verify(code),
    canSubmit: isValidOtp(code, env.otpLength),
    verifying,
    resending,
    resendIn,
    resend,
    error,
    info,
    otpLength: env.otpLength,
  };
}
