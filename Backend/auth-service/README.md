# auth-service

Spring Boot authentication API: **email OTP** + **Google Sign-In**, short-lived RS256 JWT access tokens, rotating refresh tokens.
Hexagonal architecture (domain → application ports → adapters).

## Run
```bash
mvn spring-boot:run          # dev profile, http://localhost:8080
mvn test                     # 35 tests
```
No Tomcat install needed: it is embedded. Or run `AuthServiceApplication` from IntelliJ/Eclipse (working directory: this folder).

## Configuration

**Local (dev profile):** copy `secrets.example.properties` to `secrets.properties` (git-ignored) and fill it in once:
- `auth.otp.sender=smtp` + `spring.mail.*`: send OTP emails (e.g. Gmail app password). Without it, codes are logged to the console.
- `auth.google.client-ids`: Google OAuth *Web* client id. Without it, Google sign-in is disabled.

**Production:** do not use the file. Set environment variables / secrets in your hosting platform:

| Variable | Purpose |
|---|---|
| `SPRING_PROFILES_ACTIVE` | e.g. `prod` (anything except `dev`) |
| `AUTH_HASH_PEPPER` | ≥ 32 random chars, HMAC key for OTP/refresh-token hashes |
| `AUTH_JWT_PUBLICKEY`, `AUTH_JWT_PRIVATEKEY` | `file:` paths to PEM keys |
| `AUTH_OTP_SENDER`, `AUTH_OTP_MAIL_FROM` | `smtp` and the from-address |
| `SPRING_MAIL_HOST`, `SPRING_MAIL_USERNAME`, `SPRING_MAIL_PASSWORD` | SMTP provider |
| `AUTH_GOOGLE_CLIENT_IDS` | Google Web client id(s) |

## API
| Method | Path | Auth |
|---|---|---|
| POST | `/api/v1/auth/otp/request` `{email}` | public |
| POST | `/api/v1/auth/otp/verify` `{email, code}` | public |
| POST | `/api/v1/auth/google` `{idToken}` | public |
| POST | `/api/v1/auth/token/refresh` `{refreshToken}` | public |
| POST | `/api/v1/auth/logout` `{refreshToken}` | public |
| GET | `/api/v1/home` | Bearer JWT |
| GET | `/actuator/health` | public |

> Storage is in-memory (dev). Users and sessions reset on restart. Add Redis/PostgreSQL adapters before production.
