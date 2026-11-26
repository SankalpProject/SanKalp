import { ApiError, NetworkError } from '../../../core/http/errors';

/** Maps any error to a safe, user-facing message. Raw server/library errors are never shown. */
export function toUserMessage(error: unknown): string {
  if (error instanceof NetworkError) {
    return error.message;
  }
  if (error instanceof ApiError) {
    switch (error.code) {
      case 'INVALID_EMAIL':
      case 'VALIDATION_FAILED':
        return 'Please check the details and try again.';
      case 'INVALID_EXTERNAL_TOKEN':
        return 'Google sign-in failed. Please try again.';
      case 'EXTERNAL_EMAIL_NOT_VERIFIED':
        return 'Your Google account email is not verified.';
      case 'OTP_INVALID':
        return 'Incorrect or expired code.';
      case 'OTP_ATTEMPTS_EXCEEDED':
        return 'Too many incorrect attempts. Please request a new code.';
      case 'OTP_RESEND_TOO_SOON':
      case 'RATE_LIMITED':
        return error.retryAfterSeconds
          ? `Too many requests. Try again in ${formatWait(error.retryAfterSeconds)}.`
          : 'Too many requests. Please try again later.';
      default:
        return 'Something went wrong. Please try again.';
    }
  }
  return 'Something went wrong. Please try again.';
}

function formatWait(seconds: number): string {
  if (seconds < 60) {
    return `${seconds}s`;
  }
  return `${Math.ceil(seconds / 60)} min`;
}
