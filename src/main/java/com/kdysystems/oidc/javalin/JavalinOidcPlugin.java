package com.kdysystems.oidc.javalin;

import com.kdysystems.oidc.KeycloakOidcEngine;
import com.kdysystems.oidc.OidcConfig;
import com.kdysystems.oidc.SessionStore;
import com.kdysystems.oidc.UserSession;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.Cookie;
import io.javalin.http.SameSite;

import java.util.Optional;

/**
 * Default (JAVALIN_AUTO mode) integration. Registers:
 *   GET  /auth/login     -> redirect to Keycloak
 *   GET  /auth/callback  -> exchange code, establish session cookie, redirect into app
 *   GET  /auth/logout    -> clear session, redirect to Keycloak end-session
 *   GET  /auth/me        -> 200 + claims JSON if authenticated, 401 otherwise
 *
 * Plus a `before` filter that resolves the session cookie into ctx.attribute("user").
 *
 * Non-Javalin backends: don't use this class. Call KeycloakOidcEngine directly
 * from your own routes — its public methods (startLogin/handleCallback/
 * resolveSession/logout) are the contract; wire cookies up however your
 * framework does it.
 */
public final class JavalinOidcPlugin {

    private final KeycloakOidcEngine engine;
    private final OidcConfig config;

    public JavalinOidcPlugin(OidcConfig config, SessionStore store) {
        this.config = config;
        this.engine = new KeycloakOidcEngine(config, store);
    }

    public KeycloakOidcEngine engine() {
        return engine;
    }

    public void install(Javalin app) {
        app.get("/auth/login", this::login);
        app.get("/auth/callback", this::callback);
        app.get("/auth/logout", this::logout);
        app.get("/auth/me", this::me);
        app.before(this::resolveUser);
    }

    private void login(Context ctx) {
        String redirectAfter = ctx.queryParam("redirect");
        KeycloakOidcEngine.AuthorizationRequest req = engine.startLogin(redirectAfter);

        ctx.cookie(pendingAuthCookie(req.pendingAuthCookieValue));
        ctx.redirect(req.redirectUrl);
    }

    private void callback(Context ctx) {
        String code = ctx.queryParam("code");
        String state = ctx.queryParam("state");
        String pendingCookie = ctx.cookie(config.pendingAuthCookieName);

        KeycloakOidcEngine.CallbackResult result = engine.handleCallback(code, state, pendingCookie);

        ctx.cookie(sessionCookie(result.sessionId, result.refreshExpiresAt));
        ctx.removeCookie(config.pendingAuthCookieName);
        ctx.redirect(result.postLoginRedirect);
    }

    private void logout(Context ctx) {
        String sessionId = ctx.cookie(config.sessionCookieName);
        String logoutUrl = engine.logout(sessionId);
        ctx.removeCookie(config.sessionCookieName);
        ctx.redirect(logoutUrl);
    }

    private void me(Context ctx) {
        Object user = ctx.attribute("user");
        if (user == null) {
            ctx.status(401).json(java.util.Map.of("authenticated", false));
        } else {
            ctx.json(java.util.Map.of("authenticated", true, "claims", ((UserSession) user).claims()));
        }
    }

    private void resolveUser(Context ctx) {
        String sessionId = ctx.cookie(config.sessionCookieName);
        Optional<UserSession> session = engine.resolveSession(sessionId);
        ctx.attribute("user", session.orElse(null));
    }

    private Cookie sessionCookie(String value, long expiresAtEpochSeconds) {
        long now = java.time.Instant.now().getEpochSecond();
        int maxAgeSeconds = (int) Math.max(0, expiresAtEpochSeconds - now);
        Cookie cookie = new Cookie(config.sessionCookieName, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(true); // requires HTTPS; run behind TLS even in dev (e.g. mkcert) so this can stay true everywhere
        cookie.setPath("/");
        cookie.setSameSite(SameSite.LAX); // Lax, not Strict — the callback redirect from Keycloak is a top-level cross-site GET
        cookie.setMaxAge(maxAgeSeconds);
        return cookie;
    }

    private Cookie pendingAuthCookie(String value) {
        Cookie cookie = new Cookie(config.pendingAuthCookieName, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setSameSite(SameSite.LAX);
        cookie.setMaxAge(config.pendingAuthMaxAgeSeconds);
        return cookie;
    }

    /** Convenience for protecting individual routes: app.before("/dashboard/*", plugin::requireAuth) */
    public void requireAuth(Context ctx) {
        if (ctx.attribute("user") == null) {
            ctx.status(401).result("Unauthorized");
            ctx.skipRemainingHandlers();
        }
    }
}
