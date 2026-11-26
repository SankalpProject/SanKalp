# SanKalp mobile app (React Native)

Sign in with **Google** or an **email OTP**, then see **Hello World** from the protected API.

## Run
```bash
npm install
npm start          # Metro (keep it running; code changes hot-reload)
npm run android    # build + install (needed again only after native changes)
npm test           # 12 tests
```
The backend (`../Backend/auth-service`) must be running. The Android emulator reaches it at `10.0.2.2:8080`.

## Configuration
`src/config/env.ts`:
- `googleWebClientId`: Google OAuth **Web** client id (public, not a secret). Empty = Google button hidden.
- `PROD_API_BASE_URL`: HTTPS URL of the deployed backend (release builds refuse plain HTTP).

Android package: `com.sankalp.app`. Google Cloud's Android OAuth client must use this package and the SHA-1 of the signing key:
```bash
keytool -list -v -keystore android/app/debug.keystore -alias androiddebugkey -storepass android
```
`android/app/debug.keystore` is a **debug-only** key (standard password `android`) and is committed on purpose so the team shares one debug SHA-1. Release keys must **never** be committed; they are git-ignored.

## Structure
```
src/
  app/        App root, auth gate, dependency wiring
  config/     environment config
  core/       HTTP client (auth + refresh), secure token storage
  features/   auth (email OTP, Google, session), home
  shared/ui/  reusable components
```
