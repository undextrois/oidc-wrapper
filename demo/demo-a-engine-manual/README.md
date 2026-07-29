# Demo A — Engine, manual wiring, no Javalin

Proves `KeycloakOidcEngine` works standalone against any HTTP stack — here,
the JDK's built-in `com.sun.net.httpserver.HttpServer`. Cookies are parsed
and written by hand (see `HttpUtil.java`) instead of relying on a framework's
cookie API. This is the reference for how your non-Javalin backends should
integrate.

## Prerequisites

1. Keycloak dev environment running (see `../keycloak-dev/README.md`):
   ```bash
   cd ../keycloak-dev && docker compose up
   ```
2. The `oidc-wrapper` library installed to your local Maven repo:
   ```bash
   cd ../oidc-wrapper && mvn install
   ```

## Run

```bash
mvn compile exec:java
```

Visit `http://localhost:7000`. Click **Log in**, authenticate as
`testuser` / `password123` on the Keycloak login page, and you should land
back on the demo page showing `Logged in as: <subject>`. Click **Log out**
to confirm you're returned to Keycloak's logout flow and back.

## What to actually check here (not just "does it look right")

- **Cookies**: open dev tools → Application → Cookies. After callback, you
  should see `SESSION` as `HttpOnly`, `SameSite=Lax`, with a `Max-Age`
  roughly matching the realm's refresh token lifespan — and `OIDC_PENDING`
  should be gone (deleted on successful callback).
- **State/nonce rejection**: hit `/auth/callback?code=x&state=wrong` directly
  in the browser after a real login flow started (or just with a stale
  cookie) — should get a 400 "Login failed: State mismatch", not a silent
  login.
- **Session persistence**: stop the server (`Ctrl+C`), restart it, refresh
  the page without logging in again — you should still be authenticated,
  since the session lives in `./data/demo-a-sessions.db`, not in memory.
- **`/auth/me` directly**: `curl -i --cookie "SESSION=<value from browser>" http://localhost:7000/auth/me`
  should return the JSON claims; with no cookie or a garbage value, a 401.

## Config

All via environment variables (see `DemoAServer.main`), with defaults that
match `keycloak-dev`'s realm export — no setup needed to just run it. Override
any of `KEYCLOAK_BASE_URL`, `KEYCLOAK_REALM`, `CLIENT_ID`, `CLIENT_SECRET`,
`REDIRECT_URI`, `POST_LOGOUT_REDIRECT_URI`, `SQLITE_PATH`,
`ENCRYPTION_KEY_BASE64`, `APP_PORT` as needed.

The bundled `ENCRYPTION_KEY_BASE64` default is a fixed demo key — fine for
throwaway local testing, but generate your own (`openssl rand -base64 32`)
for anything that isn't this demo.
