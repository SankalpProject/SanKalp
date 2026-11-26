import { Platform } from 'react-native';

/**
 * Environment configuration.
 * Dev: Android emulator reaches the host machine via 10.0.2.2, iOS simulator via localhost.
 * Release builds MUST use HTTPS; we fail fast instead of silently sending tokens in clear text.
 */
const DEV_API_BASE_URL =
  Platform.OS === 'android' ? 'http://10.0.2.2:8080' : 'http://localhost:8080';

const PROD_API_BASE_URL = 'https://api.myapp.example';

export const env = {
  apiBaseUrl: __DEV__ ? DEV_API_BASE_URL : PROD_API_BASE_URL,
  requestTimeoutMs: 15_000,
  otpLength: 6,
  /**
   * Google Cloud Console → APIs & Services → Credentials → OAuth client of type "Web application".
   * Not a secret (it ships in the app). Must match AUTH_GOOGLE_CLIENT_IDS on the backend.
   * Leave empty to hide the Google button.
   */
  googleWebClientId: '710862510496-gds83jculudgds3c1rilbfeg4f2l6i2g.apps.googleusercontent.com',
} as const;

if (!__DEV__ && !env.apiBaseUrl.startsWith('https://')) {
  throw new Error('Release builds must use an HTTPS API base URL');
}
