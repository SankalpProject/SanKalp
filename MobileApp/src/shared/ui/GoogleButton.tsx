import React from 'react';
import { ActivityIndicator, Pressable, StyleSheet, Text, View } from 'react-native';
import { colors, radius, spacing } from './theme';

interface Props {
  onPress: () => void;
  loading?: boolean;
  disabled?: boolean;
  testID?: string;
}

/** "Continue with Google" button styled per Google's branding guidelines (white, neutral border). */
export function GoogleButton({ onPress, loading, disabled, testID }: Props) {
  const isDisabled = disabled || loading;
  return (
    <Pressable
      testID={testID}
      accessibilityRole="button"
      accessibilityLabel="Continue with Google"
      accessibilityState={{ disabled: !!isDisabled, busy: !!loading }}
      onPress={onPress}
      disabled={isDisabled}
      style={({ pressed }) => [styles.button, pressed && styles.pressed, isDisabled && styles.disabled]}>
      {loading ? (
        <ActivityIndicator color={colors.text} />
      ) : (
        <View style={styles.row}>
          <Text style={styles.logo}>G</Text>
          <Text style={styles.label}>Continue with Google</Text>
        </View>
      )}
    </Pressable>
  );
}

const styles = StyleSheet.create({
  button: {
    minHeight: 50,
    borderRadius: radius.md,
    borderWidth: 1,
    borderColor: colors.border,
    backgroundColor: '#FFFFFF',
    alignItems: 'center',
    justifyContent: 'center',
    paddingHorizontal: spacing.md,
  },
  row: { flexDirection: 'row', alignItems: 'center', gap: spacing.sm },
  logo: { fontSize: 18, fontWeight: '700', color: '#4285F4' },
  label: { fontSize: 16, fontWeight: '600', color: colors.text },
  pressed: { backgroundColor: colors.surface },
  disabled: { opacity: 0.6 },
});
