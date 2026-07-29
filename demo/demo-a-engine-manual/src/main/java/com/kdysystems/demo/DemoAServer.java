package com.kdysystems.demo;

import com.kdysystems.oidc.KeycloakOidcEngine;
import com.kdysystems.oidc.OidcConfig;
import com.kdysystems.oidc.OidcException;
import com.kdysystems.oidc.SessionStore;
import com.kdysystems.oidc.SqliteSessionStore;
import com.kdysystems.oidc.UserSession;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

/**
 * Demo A: proves KeycloakOidcEngine works against literally any HTTP stack.
 * No Javalin, no framework — just the JDK's HttpServer and hand-wired
 * cookies. If Demo B (JavalinOidcPlugin) ever behaves differently from
 * this, the bug is in the adapter, not the engine.
 *
 * Config comes from environment variables (see README in this folder).
 */
public final class DemoAServer {

    private static final String SESSION_COOKIE = "SESSION";
    private static final String PENDING_COOKIE = "OIDC_PENDING";

    private final KeycloakOidcEngine engine;

    public DemoAServer(KeycloakOidcEngine engine) {
        this.engine = engine;
    }

    public static void main(String[] args) throws IOException {
        OidcConfig config = OidcConfig.builder()
                .keycloakBaseUrl(env("KEYCLOAK_BASE_URL", "http://localhost:8081"))
                .realm(env("KEYCLOAK_REALM", "kdy-demo"))
                .clientId(env("CLIENT_ID", "demo-client"))
                .clientSecret(env("CLIENT_SECRET", "demo-client-secret-change-me"))
                .redirectUri(env("REDIRECT_URI", "http://localhost:7000/auth/callback"))
                .postLogoutRedirectUri(env("POST_LOGOUT_REDIRECT_URI", "http://localhost:7000/"))
                .sqliteDbPath(env("SQLITE_PATH", "./data/demo-a-sessions.db"))
                // DEMO KEY ONLY. Generate your own with `openssl rand -base64 32`
                // and never commit a real one. This exists so the demo runs with zero setup.
                .encryptionKeyBase64(env("ENCRYPTION_KEY_BASE64", "3F6M9lXk2p5Q8rT1vY4zB7cE0gH3jK6nP9sU2wZ5aC8="))
                .sessionCookieName(SESSION_COOKIE)
                .pendingAuthCookieName(PENDING_COOKIE)
                .build();

        new java.io.File("./data").mkdirs();
        SessionStore store = new SqliteSessionStore(config.sqliteDbPath);
        KeycloakOidcEngine engine = new KeycloakOidcEngine(config, store);

        int port = Integer.parseInt(env("APP_PORT", "7000"));
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        DemoAServer demo = new DemoAServer(engine);

        server.createContext("/", wrap(demo::serveIndex));
        server.createContext("/auth/login", wrap(demo::login));
        server.createContext("/auth/callback", wrap(demo::callback));
        server.createContext("/auth/logout", wrap(demo::logout));
        server.createContext("/auth/me", wrap(demo::me));

        server.start();
        System.out.println("Demo A running at http://localhost:" + port);
    }

    /**
     * DIAGNOSTIC WRAPPER — not something to carry into real code.
     *
     * The JDK's HttpServer does NOT print handler exceptions to stdout/stderr
     * by default (it only logs at FINE level via java.util.logging, which is
     * off by default) — an uncaught exception just silently drops the
     * connection, which is what "This page isn't working / didn't send any
     * data" looks like in a browser. This wrapper catches everything, prints
     * the full stack trace to the console so it's actually visible, and
     * returns it in the response body too so it shows up in the browser.
     */
    private static HttpHandler wrap(HttpHandler inner) {
        return ex -> {
            try {
                inner.handle(ex);
            } catch (Throwable t) {
                t.printStackTrace(System.err);
                ByteArrayOutputStream buf = new ByteArrayOutputStream();
                t.printStackTrace(new PrintStream(buf, true, StandardCharsets.UTF_8));
                byte[] bytes = buf.toByteArray();
                try {
                    ex.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
                    ex.sendResponseHeaders(500, bytes.length);
                    ex.getResponseBody().write(bytes);
                    ex.getResponseBody().close();
                } catch (IOException ignored) {
                    // response already committed or connection gone — the console trace is what matters
                }
            }
        };
    }

    private void serveIndex(HttpExchange ex) throws IOException {
        try (InputStream in = getClass().getResourceAsStream("/public/index.html")) {
            byte[] bytes = in.readAllBytes();
            ex.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
            ex.sendResponseHeaders(200, bytes.length);
            ex.getResponseBody().write(bytes);
            ex.getResponseBody().close();
        }
    }

    private void login(HttpExchange ex) throws IOException {
        Map<String, String> query = HttpUtil.parseQuery(ex.getRequestURI().getRawQuery());
        KeycloakOidcEngine.AuthorizationRequest req = engine.startLogin(query.get("redirect"));

        ex.getResponseHeaders().add("Set-Cookie", HttpUtil.buildSetCookie(PENDING_COOKIE, req.pendingAuthCookieValue, 600));
        ex.getResponseHeaders().add("Location", req.redirectUrl);
        ex.sendResponseHeaders(302, -1);
    }

    private void callback(HttpExchange ex) throws IOException {
        Map<String, String> query = HttpUtil.parseQuery(ex.getRequestURI().getRawQuery());
        Map<String, String> cookies = HttpUtil.parseCookies(ex.getRequestHeaders().get("Cookie"));

        try {
            KeycloakOidcEngine.CallbackResult result = engine.handleCallback(
                    query.get("code"), query.get("state"), cookies.get(PENDING_COOKIE));

            long now = java.time.Instant.now().getEpochSecond();
            int maxAge = (int) Math.max(0, result.refreshExpiresAt - now);

            ex.getResponseHeaders().add("Set-Cookie", HttpUtil.buildSetCookie(SESSION_COOKIE, result.sessionId, maxAge));
            ex.getResponseHeaders().add("Set-Cookie", HttpUtil.buildDeleteCookie(PENDING_COOKIE));
            ex.getResponseHeaders().add("Location", result.postLoginRedirect);
            ex.sendResponseHeaders(302, -1);
        } catch (OidcException e) {
            String body = "Login failed: " + e.getMessage();
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(400, bytes.length);
            ex.getResponseBody().write(bytes);
            ex.getResponseBody().close();
        }
    }

    private void logout(HttpExchange ex) throws IOException {
        Map<String, String> cookies = HttpUtil.parseCookies(ex.getRequestHeaders().get("Cookie"));
        String logoutUrl = engine.logout(cookies.get(SESSION_COOKIE));

        ex.getResponseHeaders().add("Set-Cookie", HttpUtil.buildDeleteCookie(SESSION_COOKIE));
        ex.getResponseHeaders().add("Location", logoutUrl);
        ex.sendResponseHeaders(302, -1);
    }

    private void me(HttpExchange ex) throws IOException {
        Map<String, String> cookies = HttpUtil.parseCookies(ex.getRequestHeaders().get("Cookie"));
        Optional<UserSession> session = engine.resolveSession(cookies.get(SESSION_COOKIE));

        String body;
        int status;
        if (session.isPresent()) {
            status = 200;
            body = "{\"authenticated\":true,\"subject\":\"" + escape(session.get().subject()) + "\"}";
        } else {
            status = 401;
            body = "{\"authenticated\":false}";
        }

        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length);
        ex.getResponseBody().write(bytes);
        ex.getResponseBody().close();
    }

    private String escape(String s) {
        return s.replace("\"", "\\\"");
    }

    private static String env(String name, String fallback) {
        String v = System.getenv(name);
        return (v != null && !v.isBlank()) ? v : fallback;
    }
}
