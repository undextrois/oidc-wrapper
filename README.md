# oidc-wrapper

Drop-in Keycloak OIDC integration via the BFF pattern: the backend owns the
entire OIDC relationship (Authorization Code + PKCE, ID token validation,
refresh, logout). The browser only ever holds an `httpOnly` session cookie —
never a token. This is what makes it work identically across SPA and
server-rendered frontends: they all just have a cookie.

## Architecture

```
KeycloakOidcEngine   <- framework-agnostic core, zero Javalin dependency
SessionStore         <- pluggable interface
SqliteSessionStore   <- default implementation (WAL mode, encrypted columns)
JavalinOidcPlugin    <- thin adapter for Javalin (default / JAVALIN_AUTO mode)
```

## Quick start (Javalin, default mode)

```java
byte[] key = new byte[32];
new SecureRandom().nextBytes(key); // generate once, store in your secrets manager, reuse across restarts

OidcConfig config = OidcConfig.builder()
    .keycloakBaseUrl("https://auth.kdysystems.com")
    .realm("kdy")
    .clientId("dashboard-app")
    .clientSecret(System.getenv("KEYCLOAK_CLIENT_SECRET")) // omit for public clients
    .redirectUri("https://dashboard.kdysystems.com/auth/callback")
    .postLogoutRedirectUri("https://dashboard.kdysystems.com/")
    .sqliteDbPath("./data/sessions.db")
    .encryptionKeyBase64(Base64.getEncoder().encodeToString(key))
    .build();

SessionStore store = new SqliteSessionStore(config.sqliteDbPath);
JavalinOidcPlugin oidc = new JavalinOidcPlugin(config, store);

Javalin app = Javalin.create();
oidc.install(app); // registers /auth/login, /auth/callback, /auth/logout, /auth/me

app.before("/dashboard/*", oidc::requireAuth); // protect specific routes
app.start(7000);

// Periodically (e.g. via your own scheduled task), sweep expired sessions:
oidc.engine().sweepExpiredSessions();
```

Frontend side (any framework — this is the whole contract):

- Redirect to `/auth/login` to start login (optional `?redirect=/somewhere` to control post-login destination)
- Call `GET /auth/me` to check auth state — `401` means not logged in, redirect to `/auth/login`
- Redirect to `/auth/logout` to log out

No JS SDK, no token handling, no framework-specific code needed on the frontend.

## Non-Javalin backends (MANUAL mode)

Don't use `JavalinOidcPlugin`. Use `KeycloakOidcEngine` directly — its public
methods are the contract every backend implements against:

```java
KeycloakOidcEngine engine = new KeycloakOidcEngine(config, store);

// your framework's /auth/login route:
var authReq = engine.startLogin(redirectParam);
// -> set authReq.pendingAuthCookieValue as an httpOnly, Secure, SameSite=Lax cookie
//    named config.pendingAuthCookieName, maxAge = config.pendingAuthMaxAgeSeconds
// -> redirect to authReq.redirectUrl

// your framework's /auth/callback route:
var result = engine.handleCallback(code, state, pendingAuthCookieFromRequest);
// -> set result.sessionId as an httpOnly, Secure, SameSite=Lax cookie
//    named config.sessionCookieName, maxAge = result.refreshExpiresAt - now
// -> remove the pending-auth cookie
// -> redirect to result.postLoginRedirect

// any route needing auth state:
Optional<UserSession> user = engine.resolveSession(sessionIdFromCookie);

// your framework's /auth/logout route:
String keycloakLogoutUrl = engine.logout(sessionIdFromCookie);
// -> clear the session cookie
// -> redirect to keycloakLogoutUrl
```

Cookie attributes matter — replicate exactly what's noted above in whatever
framework you're using, especially `SameSite=Lax` (not `Strict`; the callback
from Keycloak is a top-level cross-site GET and `Strict` cookies won't be
sent on it) and `httpOnly` + `Secure` (requires HTTPS everywhere, including dev).

## Security properties this gives you

- Authorization Code + PKCE (S256) only — no implicit flow
- Full ID token validation: signature via JWKS (auto-refreshes on rotation), `iss`, `aud`/`azp`, `exp`/`iat` with clock skew tolerance, `nonce`
- `state` checked with constant-time comparison; pending-auth payload is itself encrypted (AES-256-GCM), so it can't be forged or read client-side
- Tokens never reach the browser — no XSS token-theft surface
- Tokens encrypted at rest in SQLite (AES-256-GCM)
- Transparent access-token refresh with a configurable buffer before expiry
- Refresh failure (e.g. rotation/reuse detected by Keycloak) is treated as session-end, not a hard error
- Revoke-by-subject and expiry sweep available via indexed SQL (`revokeAllSessionsForSubject`, `sweepExpiredSessions`)

## Known constraint

`SqliteSessionStore` assumes all backends sharing session state run on the
same host or a shared local volume. If a non-Javalin backend ends up on a
separate machine from where the SQLite file lives, don't reach for it over
NFS — that's the point to swap in a `SessionStore` implementation backed by
Postgres or Redis instead. The interface is the same either way.
