/**
 * @format
 */

import React from 'react';
import ReactTestRenderer from 'react-test-renderer';
import App from '../App';
import { createSignOut, Dependencies } from '../src/app/dependencies';
import { InMemoryTokenStorage } from '../src/core/storage/SecureTokenStorage';
import { SessionManager } from '../src/features/auth/session/SessionManager';
import { FakeAuthRepository, FakeGoogleSignInClient } from '../test/testDoubles';

function createTestDependencies() {
  const authRepository = new FakeAuthRepository();
  const googleSignIn = new FakeGoogleSignInClient();
  const session = new SessionManager(authRepository, new InMemoryTokenStorage());
  const deps: Dependencies = {
    authRepository,
    googleSignIn,
    session,
    homeRepository: { getGreeting: jest.fn(async () => ({ message: 'Hello World' })) },
    signOut: createSignOut(session, googleSignIn),
  };
  return { deps, authRepository, googleSignIn };
}

type Tree = ReactTestRenderer.ReactTestRenderer;

const byTestId = (tree: Tree, id: string) => tree.root.findAll(node => node.props.testID === id)[0];
const hasText = (tree: Tree, text: string) => JSON.stringify(tree.toJSON()).includes(text);

async function render(deps: Dependencies): Promise<Tree> {
  let tree!: Tree;
  await ReactTestRenderer.act(async () => {
    tree = ReactTestRenderer.create(<App dependencies={deps} />);
  });
  return tree;
}

async function interact(fn: () => void) {
  await ReactTestRenderer.act(async () => fn());
}

test('email -> OTP -> Hello World -> logout', async () => {
  const { deps, authRepository, googleSignIn } = createTestDependencies();
  const tree = await render(deps);

  // Step 1: email is trimmed and lower-cased before sending
  await interact(() => byTestId(tree, 'email-input').props.onChangeText('  Satyam@Example.com '));
  await interact(() => byTestId(tree, 'send-otp-button').props.onPress());
  expect(authRepository.requestOtp).toHaveBeenCalledWith('satyam@example.com');
  expect(hasText(tree, 'sa***@example.com')).toBe(true);

  // Step 2: wrong code shows an error and stays on the OTP screen
  await interact(() => byTestId(tree, 'otp-input').props.onChangeText('000000'));
  expect(hasText(tree, 'Incorrect or expired code.')).toBe(true);

  // Correct code auto-submits and signs in
  await interact(() => byTestId(tree, 'otp-input').props.onChangeText('123456'));
  expect(byTestId(tree, 'hello-world')).toBeDefined();
  expect(hasText(tree, 'Hello World')).toBe(true);

  // Logout returns to sign-in and also clears the Google account selection
  await interact(() => byTestId(tree, 'logout-button').props.onPress());
  expect(byTestId(tree, 'email-input')).toBeDefined();
  expect(authRepository.logout).toHaveBeenCalledWith('refresh-1');
  expect(googleSignIn.signOut).toHaveBeenCalled();

  await ReactTestRenderer.act(async () => tree.unmount());
}, 20_000);

test('invalid email is not sent to the server', async () => {
  const { deps, authRepository } = createTestDependencies();
  const tree = await render(deps);

  await interact(() => byTestId(tree, 'email-input').props.onChangeText('not-an-email'));
  expect(byTestId(tree, 'send-otp-button').props.disabled).toBe(true);
  expect(authRepository.requestOtp).not.toHaveBeenCalled();

  await ReactTestRenderer.act(async () => tree.unmount());
}, 20_000);

test('Continue with Google -> Hello World', async () => {
  const { deps, authRepository } = createTestDependencies();
  const tree = await render(deps);

  await interact(() => byTestId(tree, 'google-button').props.onPress());
  expect(authRepository.signInWithGoogle).toHaveBeenCalledWith('valid-google-id-token');
  expect(hasText(tree, 'Hello World')).toBe(true);

  await ReactTestRenderer.act(async () => tree.unmount());
}, 20_000);

test('cancelling the Google picker is silent; a rejected token shows an error', async () => {
  const { deps, authRepository, googleSignIn } = createTestDependencies();
  const tree = await render(deps);

  googleSignIn.nextResult = { type: 'cancelled' };
  await interact(() => byTestId(tree, 'google-button').props.onPress());
  expect(authRepository.signInWithGoogle).not.toHaveBeenCalled();
  expect(hasText(tree, 'failed')).toBe(false);

  googleSignIn.nextResult = { type: 'success', idToken: 'forged' };
  await interact(() => byTestId(tree, 'google-button').props.onPress());
  expect(hasText(tree, 'Google sign-in failed. Please try again.')).toBe(true);
  expect(byTestId(tree, 'email-input')).toBeDefined(); // still signed out

  await ReactTestRenderer.act(async () => tree.unmount());
}, 20_000);

test('Google button is hidden when no client id is configured', async () => {
  const { deps, googleSignIn } = createTestDependencies();
  googleSignIn.isConfigured = false;
  const tree = await render(deps);
  expect(byTestId(tree, 'google-button')).toBeUndefined();
  expect(byTestId(tree, 'email-input')).toBeDefined();
  await ReactTestRenderer.act(async () => tree.unmount());
}, 20_000);
