import * as Keychain from 'react-native-keychain';
import type { SecureTokenStorage } from './SecureTokenStorage';

const SERVICE = 'com.myapp.auth.refresh-token';

/**
 * iOS Keychain / Android Keystore-backed storage.
 * NEVER store tokens in AsyncStorage: it is unencrypted plain text on disk.
 * `WHEN_UNLOCKED_THIS_DEVICE_ONLY` keeps the token out of backups and off other devices.
 */
export class KeychainTokenStorage implements SecureTokenStorage {
  async getRefreshToken(): Promise<string | null> {
    try {
      const credentials = await Keychain.getGenericPassword({ service: SERVICE });
      return credentials ? credentials.password : null;
    } catch {
      return null;
    }
  }

  async setRefreshToken(token: string): Promise<void> {
    await Keychain.setGenericPassword('refresh_token', token, {
      service: SERVICE,
      accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    });
  }

  async clear(): Promise<void> {
    await Keychain.resetGenericPassword({ service: SERVICE });
  }
}
