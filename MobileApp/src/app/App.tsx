import React, { useState } from 'react';
import { StatusBar } from 'react-native';
import { initialWindowMetrics, SafeAreaProvider } from 'react-native-safe-area-context';
import { createDependencies, Dependencies, DependenciesProvider } from './dependencies';
import { RootNavigator } from './RootNavigator';

interface Props {
  /** Injected in tests; production builds the real graph once. */
  dependencies?: Dependencies;
}

export default function App({ dependencies }: Props) {
  const [deps] = useState(() => dependencies ?? createDependencies());
  return (
    <SafeAreaProvider initialMetrics={initialWindowMetrics}>
      <StatusBar barStyle="dark-content" />
      <DependenciesProvider value={deps}>
        <RootNavigator />
      </DependenciesProvider>
    </SafeAreaProvider>
  );
}
