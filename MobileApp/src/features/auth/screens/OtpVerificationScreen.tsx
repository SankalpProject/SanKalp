import React, { useEffect } from 'react';
import { BackHandler, StyleSheet, Text, View } from 'react-native';
import { PrimaryButton } from '../../../shared/ui/PrimaryButton';
import { Screen } from '../../../shared/ui/Screen';
import { TextField } from '../../../shared/ui/TextField';
import { colors, spacing } from '../../../shared/ui/theme';
import { maskEmail } from '../domain/validation';
import { useOtpVerification } from '../hooks/useOtpVerification';

interface Props {
  email: string;
  resendAfterSeconds: number;
  onChangeEmail: () => void;
}

export function OtpVerificationScreen({ email, resendAfterSeconds, onChangeEmail }: Props) {
  const vm = useOtpVerification(email, resendAfterSeconds);

  // Android hardware back returns to the sign-in step instead of closing the app.
  useEffect(() => {
    const sub = BackHandler.addEventListener('hardwareBackPress', () => {
      onChangeEmail();
      return true;
    });
    return () => sub.remove();
  }, [onChangeEmail]);

  return (
    <Screen>
      <View style={styles.header}>
        <Text style={styles.title}>Check your email</Text>
        <Text style={styles.subtitle}>
          Enter the {vm.otpLength}-digit code sent to <Text style={styles.highlight}>{maskEmail(email)}</Text>
        </Text>
      </View>

      <TextField
        testID="otp-input"
        label="Verification code"
        value={vm.code}
        onChangeText={vm.onChangeCode}
        placeholder={'•'.repeat(vm.otpLength)}
        keyboardType="number-pad"
        textContentType="oneTimeCode" // iOS: suggests codes from Mail/Messages
        autoComplete="one-time-code"
        importantForAutofill="yes"
        maxLength={vm.otpLength}
        editable={!vm.verifying}
        error={vm.error}
        style={styles.otpInput}
        autoFocus
      />
      {vm.info ? <Text style={styles.info}>{vm.info}</Text> : null}
      <Text style={styles.info}>Didn't get it? Check your spam or promotions folder.</Text>

      <PrimaryButton
        testID="verify-otp-button"
        title="Verify & continue"
        onPress={vm.submit}
        disabled={!vm.canSubmit}
        loading={vm.verifying}
      />

      <View style={styles.row}>
        <PrimaryButton
          variant="text"
          title={vm.resendIn > 0 ? `Resend code in ${vm.resendIn}s` : 'Resend code'}
          onPress={vm.resend}
          disabled={vm.resendIn > 0}
          loading={vm.resending}
        />
        <PrimaryButton variant="text" title="Change email" onPress={onChangeEmail} disabled={vm.verifying} />
      </View>
    </Screen>
  );
}

const styles = StyleSheet.create({
  header: { gap: spacing.sm },
  title: { fontSize: 28, fontWeight: '700', color: colors.text },
  subtitle: { fontSize: 15, color: colors.textMuted, lineHeight: 21 },
  highlight: { color: colors.text, fontWeight: '600' },
  otpInput: { letterSpacing: 8, fontSize: 22 },
  info: { color: colors.textMuted, fontSize: 13 },
  row: { flexDirection: 'row', justifyContent: 'space-between' },
});
