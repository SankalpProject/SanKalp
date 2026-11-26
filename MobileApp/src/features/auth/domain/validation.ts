const EMAIL = /^[^\s@]{1,64}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

/** Keeps only digits and caps the length, so the input can never contain anything else. */
export function digitsOnly(value: string, maxLength: number): string {
  return value.replace(/\D/g, '').slice(0, maxLength);
}

export function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

/** Client-side check for fast feedback only. The server validates again (never trust the client). */
export function isValidEmail(email: string): boolean {
  return email.length <= 254 && EMAIL.test(email);
}

export function isValidOtp(code: string, length: number): boolean {
  return code.length === length && /^\d+$/.test(code);
}

/** "satyam@gmail.com" -> "sa***@gmail.com" for display. */
export function maskEmail(email: string): string {
  const at = email.indexOf('@');
  if (at < 1) {
    return email;
  }
  return `${email.slice(0, Math.min(2, at))}***${email.slice(at)}`;
}
