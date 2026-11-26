import React, { useEffect } from 'react';
import { ActivityIndicator, StyleSheet, View } from 'react-native';
import { AuthFlow } from '../features/auth/AuthFlow';
import { HomeScreen } from '../features/home/HomeScreen';
import { colors } from '../shared/ui/theme';
import { useDependencies, useSessionStatus } from './dependencies';

/**
 * Auth gate: the session state decides which tree is mounted, so protected screens
 * can never render without a session (and are unmounted immediately on logout/expiry).
 */
export function RootNavigator() {
  const { session } = useDependencies();
  const status = useSessionStatus();

  useEffect(() => {
    session.restore();
  }, [session]);

  switch (status) {
    case 'restoring':
      return (
        <View style={styles.splash}>
          <ActivityIndicator size="large" color={colors.primary} />
        </View>
      );
    case 'signedIn':
      return <HomeScreen />;
    case 'signedOut':
      return <AuthFlow />;
  }
}

const styles = StyleSheet.create({
  splash: { flex: 1, alignItems: 'center', justifyContent: 'center', backgroundColor: colors.background },
});
