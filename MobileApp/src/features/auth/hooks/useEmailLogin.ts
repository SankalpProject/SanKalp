import { useCallback, useRef, useState } from 'react';
import { useDependencies } from '../../../app/dependencies';
import { ApiError } from '../../../core/http/errors';
import { toUserMessage } from '../domain/errorMessages';
import { isValidEmail, normalizeEmail } from '../domain/validation';

export interface OtpSentEvent {
  email: string;
  resendAfterSeconds: number;
}

/** Presentation logic for the email step, kept out of the view (testable, reusable). */
export function useEmailLogin(onOtpSent: (event: OtpSentEvent) => void) {
  const { authRepository } = useDependencies();
  const [rawEmail, setRawEmail] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const inFlight = useRef(false); // guards against double taps before re-render

  const email = normalizeEmail(rawEmail);
  const canSubmit = isValidEmail(email);

  const onChangeEmail = useCallback((text: string) => {
    setRawEmail(text.slice(0, 254));
    setError(null);
  }, []);

  const submit = useCallback(async () => {
    if (inFlight.current) {
      return;
    }
    if (!canSubmit) {
      setError('Enter a valid email address.');
      return;
    }
    inFlight.current = true;
    setSubmitting(true);
    setError(null);
    try {
      const result = await authRepository.requestOtp(email);
      onOtpSent({ email, resendAfterSeconds: result.resendAfterSeconds });
    } catch (e) {
      if (e instanceof ApiError && e.code === 'OTP_RESEND_TOO_SOON') {
        // A code was already sent moments ago: let the user enter it.
        onOtpSent({ email, resendAfterSeconds: e.retryAfterSeconds ?? 30 });
      } else {
        setError(toUserMessage(e));
      }
    } finally {
      inFlight.current = false;
      setSubmitting(false);
    }
  }, [authRepository, canSubmit, email, onOtpSent]);

  return { email: rawEmail, onChangeEmail, canSubmit, submitting, error, submit };
}
