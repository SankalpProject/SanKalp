import React from 'react';
import { ActivityIndicator, Pressable, StyleSheet, Text } from 'react-native';
import { colors, radius, spacing } from './theme';

interface Props {
  title: string;
  onPress: () => void;
  disabled?: boolean;
  loading?: boolean;
  variant?: 'solid' | 'text';
  testID?: string;
}

export function PrimaryButton({ title, onPress, disabled, loading, variant = 'solid', testID }: Props) {
  const isDisabled = disabled || loading;
  const solid = variant === 'solid';
  return (
    <Pressable
      testID={testID}
      accessibilityRole="button"
      accessibilityState={{ disabled: !!isDisabled, busy: !!loading }}
      onPress={onPress}
      disabled={isDisabled}
      style={({ pressed }) => [
        styles.base,
        solid && styles.solid,
        solid && isDisabled && styles.solidDisabled,
        pressed && !isDisabled && styles.pressed,
      ]}>
      {loading ? (
        <ActivityIndicator color={solid ? '#fff' : colors.primary} />
      ) : (
        <Text style={[styles.label, solid ? styles.solidLabel : styles.textLabel, !solid && isDisabled && styles.textDisabled]}>
          {title}
        </Text>
      )}
    </Pressable>
  );
}

const styles = StyleSheet.create({
  base: {
    minHeight: 50,
    borderRadius: radius.md,
    alignItems: 'center',
    justifyContent: 'center',
    paddingHorizontal: spacing.md,
  },
  solid: { backgroundColor: colors.primary },
  solidDisabled: { backgroundColor: colors.primaryDisabled },
  pressed: { opacity: 0.85 },
  label: { fontSize: 16, fontWeight: '600' },
  solidLabel: { color: '#fff' },
  textLabel: { color: colors.primary },
  textDisabled: { color: colors.textMuted },
});
