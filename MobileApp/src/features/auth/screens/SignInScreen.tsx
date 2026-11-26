import React from 'react';
import { StyleSheet, Text, View } from 'react-native';
import { GoogleButton } from '../../../shared/ui/GoogleButton';
import { PrimaryButton } from '../../../shared/ui/PrimaryButton';
import { Screen } from '../../../shared/ui/Screen';
import { TextField } from '../../../shared/ui/TextField';
import { colors, spacing } from '../../../shared/ui/theme';
import { OtpSentEvent, useEmailLogin } from '../hooks/useEmailLogin';
import { useGoogleSignIn } from '../hooks/useGoogleSignIn';

interface Props {
  onOtpSent: (event: OtpSentEvent) => void;
}

/** View only: behaviour lives in useEmailLogin / useGoogleSignIn (Single Responsibility). */
export function SignInScreen({ onOtpSent }: Props) {
  const emailLogin = useEmailLogin(onOtpSent);
  const google = useGoogleSignIn();
  const busy = emailLogin.submitting || google.loading;

  return (
    <Screen>
      <View style={styles.header}>
        <Text style={styles.title}>Welcome</Text>
        <Text style={styles.subtitle}>Sign in or create an account.</Text>
      </View>

      {google.available ? (
        <>
          <GoogleButton testID="google-button" onPress={google.signIn} loading={google.loading} disabled={busy} />
          {google.error ? <Text style={styles.error}>{google.error}</Text> : null}
          <View style={styles.dividerRow}>
            <View style={styles.line} />
            <Text style={styles.dividerText}>or</Text>
            <View style={styles.line} />
          </View>
        </>
      ) : null}

      <TextField
        testID="email-input"
        label="Email"
        value={emailLogin.email}
        onChangeText={emailLogin.onChangeEmail}
        placeholder="you@example.com"
        keyboardType="email-address"
        textContentType="emailAddress"
        autoComplete="email"
        autoCapitalize="none"
        maxLength={254}
        returnKeyType="send"
        onSubmitEditing={emailLogin.submit}
        editable={!busy}
        error={emailLogin.error}
      />

      <PrimaryButton
        testID="send-otp-button"
        title="Email me a code"
        onPress={emailLogin.submit}
        disabled={!emailLogin.canSubmit || google.loading}
        loading={emailLogin.submitting}
      />
    </Screen>
  );
}

const styles = StyleSheet.create({
  header: { gap: spacing.sm },
  title: { fontSize: 28, fontWeight: '700', color: colors.text },
  subtitle: { fontSize: 15, color: colors.textMuted, lineHeight: 21 },
  error: { color: colors.error, fontSize: 13 },
  dividerRow: { flexDirection: 'row', alignItems: 'center', gap: spacing.sm },
  line: { flex: 1, height: StyleSheet.hairlineWidth, backgroundColor: colors.border },
  dividerText: { color: colors.textMuted, fontSize: 13 },
});
