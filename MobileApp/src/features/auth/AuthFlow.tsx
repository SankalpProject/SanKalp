import React, { useCallback, useState } from 'react';
import type { OtpSentEvent } from './hooks/useEmailLogin';
import { OtpVerificationScreen } from './screens/OtpVerificationScreen';
import { SignInScreen } from './screens/SignInScreen';

type Step = { name: 'signIn' } | ({ name: 'otp' } & OtpSentEvent);

/** Sign-in: Google (one step) or email -> OTP (two steps). */
export function AuthFlow() {
  const [step, setStep] = useState<Step>({ name: 'signIn' });

  const onOtpSent = useCallback((event: OtpSentEvent) => setStep({ name: 'otp', ...event }), []);
  const backToSignIn = useCallback(() => setStep({ name: 'signIn' }), []);

  if (step.name === 'otp') {
    return (
      <OtpVerificationScreen
        email={step.email}
        resendAfterSeconds={step.resendAfterSeconds}
        onChangeEmail={backToSignIn}
      />
    );
  }
  return <SignInScreen onOtpSent={onOtpSent} />;
}
