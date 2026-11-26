module.exports = {
  preset: '@react-native/jest-preset',
  setupFiles: [
    '<rootDir>/jest.setup.js',
    '<rootDir>/node_modules/@react-native-google-signin/google-signin/jest/build/jest/setup.js',
  ],
  // Libraries that ship untranspiled ES modules must be transformed by Babel.
  transformIgnorePatterns: [
    'node_modules/(?!((jest-)?react-native|@react-native(-community)?|@react-native-google-signin)/)',
  ],
};
