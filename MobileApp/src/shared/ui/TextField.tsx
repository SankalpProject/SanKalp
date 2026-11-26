import React, { useState } from 'react';
import { StyleSheet, Text, TextInput, TextInputProps, View } from 'react-native';
import { colors, radius, spacing } from './theme';

interface Props extends TextInputProps {
  label: string;
  error?: string | null;
  prefix?: string;
}

export function TextField({ label, error, prefix, style, ...inputProps }: Props) {
  const [focused, setFocused] = useState(false);
  return (
    <View style={styles.container}>
      <Text style={styles.label}>{label}</Text>
      <View style={[styles.inputRow, focused && styles.focused, !!error && styles.errorBorder]}>
        {prefix ? <Text style={styles.prefix}>{prefix}</Text> : null}
        <TextInput
          accessibilityLabel={label}
          placeholderTextColor={colors.textMuted}
          autoCorrect={false}
          autoCapitalize="none"
          {...inputProps}
          onFocus={e => {
            setFocused(true);
            inputProps.onFocus?.(e);
          }}
          onBlur={e => {
            setFocused(false);
            inputProps.onBlur?.(e);
          }}
          style={[styles.input, style]}
        />
      </View>
      {error ? (
        <Text accessibilityLiveRegion="polite" style={styles.errorText}>
          {error}
        </Text>
      ) : null}
    </View>
  );
}

const styles = StyleSheet.create({
  container: { gap: spacing.xs },
  label: { fontSize: 14, fontWeight: '500', color: colors.text },
  inputRow: {
    flexDirection: 'row',
    alignItems: 'center',
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: radius.md,
    paddingHorizontal: spacing.md,
    backgroundColor: colors.surface,
  },
  focused: { borderColor: colors.borderFocused },
  errorBorder: { borderColor: colors.error },
  prefix: { fontSize: 18, color: colors.text, marginRight: spacing.sm },
  input: { flex: 1, fontSize: 18, paddingVertical: 12, color: colors.text },
  errorText: { color: colors.error, fontSize: 13 },
});
