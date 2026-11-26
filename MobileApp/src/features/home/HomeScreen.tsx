import React, { useEffect, useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';
import { useDependencies } from '../../app/dependencies';
import { PrimaryButton } from '../../shared/ui/PrimaryButton';
import { Screen } from '../../shared/ui/Screen';
import { colors, spacing } from '../../shared/ui/theme';

/** Shown after login. The greeting is fetched from a protected endpoint to prove the session works. */
export function HomeScreen() {
  const { homeRepository, signOut } = useDependencies();
  const [verified, setVerified] = useState<boolean | null>(null);

  useEffect(() => {
    let active = true;
    homeRepository
      .getGreeting()
      .then(() => active && setVerified(true))
      .catch(() => active && setVerified(false));
    return () => {
      active = false;
    };
  }, [homeRepository]);

  return (
    <Screen>
      <View style={styles.center}>
        <Text testID="hello-world" style={styles.hello}>
          Hello World
        </Text>
        {verified === true ? <Text style={styles.caption}>Signed in securely</Text> : null}
        {verified === false ? <Text style={styles.caption}>Couldn't reach the server</Text> : null}
      </View>
      <PrimaryButton testID="logout-button" title="Log out" onPress={signOut} />
    </Screen>
  );
}

const styles = StyleSheet.create({
  center: { flex: 1, alignItems: 'center', justifyContent: 'center', gap: spacing.sm },
  hello: { fontSize: 36, fontWeight: '700', color: colors.text },
  caption: { fontSize: 14, color: colors.textMuted },
});
