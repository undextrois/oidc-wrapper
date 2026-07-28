package com.kdysystems.oidc;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;

/**
 * Framework-agnostic OIDC core for a single Keycloak realm/client. No Javalin
 * dependency here — JavalinOidcPlugin (or any other framework's adapter) just
 * calls these methods and translates to/from its own request/response types.
 *
 * Flow implemented: Authorization Code + PKCE (S256) only. No implicit flow.
 */
public final class KeycloakOidcEngine {

    private final OidcConfig config;
    private final SessionStore store;
    private final CryptoUtil crypto;
    private final HttpClient http = HttpClient.newHttpClient();
    private final Gson gson = new Gson();
    private final SecureRandom random = new SecureRandom();

    private volatile DiscoveryDocument discovery;
    private static final long DISCOVERY_TTL_SECONDS = 3600;

    private DefaultJWTProcessor<SecurityContext> jwtProcessor;

    public KeycloakOidcEngine(OidcConfig config, SessionStore store) {
        this.config = config;
        this.store = store;
        this.crypto = new CryptoUtil(config.encryptionKey);
    }

    // ---------------------------------------------------------------
    // Discovery
    // ---------------------------------------------------------------

    private synchronized DiscoveryDocument discovery() {
        long now = Instant.now().getEpochSecond();
        if (discovery != null && (now - discovery.fetchedAt) < DISCOVERY_TTL_SECONDS) {
            return discovery;
        }
        try {
            String url = config.realmBaseUrl() + "/.well-known/openid-configuration";
            HttpRequest req = HttpRequest.newBuilder(URI.create(url)).GET().build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new OidcException("Discovery fetch failed: HTTP " + resp.statusCode());
            }
            Map<?, ?> body = gson.fromJson(resp.body(), Map.class);
            DiscoveryDocument d = new DiscoveryDocument();
            d.issuer = (String) body.get("issuer");
            d.authorizationEndpoint = (String) body.get("authorization_endpoint");
            d.tokenEndpoint = (String) body.get("token_endpoint");
            d.endSessionEndpoint = (String) body.get("end_session_endpoint");
            d.jwksUri = (String) body.get("jwks_uri");
            d.fetchedAt = now;

            // (Re)build the JWKS-backed JWT processor whenever discovery refreshes,
            // so key rotation on the Keycloak side is picked up automatically.
            JWKSource<SecurityContext> jwkSource = JWKSourceBuilder
                    .create(URI.create(d.jwksUri).toURL())
                    .build();
            DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
            processor.setJWSKeySelector(new JWSVerificationKeySelector<>(
                    com.nimbusds.jose.JWSAlgorithm.RS256, jwkSource));
            this.jwtProcessor = processor;

            this.discovery = d;
            return d;
        } catch (OidcException e) {
            throw e;
        } catch (Exception e) {
            throw new OidcException("Discovery failed", e);
        }
    }

    // ---------------------------------------------------------------
    // Login: step 1 — build the redirect + pending-auth cookie
    // ---------------------------------------------------------------

    public static final class AuthorizationRequest {
        public final String redirectUrl;
        public final String pendingAuthCookieValue;
        public AuthorizationRequest(String redirectUrl, String pendingAuthCookieValue) {
            this.redirectUrl = redirectUrl;
            this.pendingAuthCookieValue = pendingAuthCookieValue;
        }
    }

    public AuthorizationRequest startLogin(String postLoginRedirect) {
        DiscoveryDocument d = discovery();

        String state = randomToken();
        String nonce = randomToken();
        String codeVerifier = randomToken(); // 43-128 chars of unreserved chars; randomToken() satisfies this
        String codeChallenge = base64UrlSha256(codeVerifier);

        PendingAuth pending = new PendingAuth();
        pending.state = state;
        pending.nonce = nonce;
        pending.codeVerifier = codeVerifier;
        pending.postLoginRedirect = (postLoginRedirect != null) ? postLoginRedirect : "/";
        pending.createdAt = Instant.now().getEpochSecond();

        String pendingCookieValue = crypto.encrypt(gson.toJson(pending));

        String url = d.authorizationEndpoint
                + "?response_type=code"
                + "&client_id=" + enc(config.clientId)
                + "&redirect_uri=" + enc(config.redirectUri)
                + "&scope=" + enc(config.scopes)
                + "&state=" + enc(state)
                + "&nonce=" + enc(nonce)
                + "&code_challenge=" + enc(codeChallenge)
                + "&code_challenge_method=S256";

        return new AuthorizationRequest(url, pendingCookieValue);
    }

    // ---------------------------------------------------------------
    // Login: step 2 — handle the callback
    // ---------------------------------------------------------------

    public static final class CallbackResult {
        public final String sessionId;
        public final String postLoginRedirect;
        public final long refreshExpiresAt; // use as cookie max-age; falls back to access token life if no refresh token
        public CallbackResult(String sessionId, String postLoginRedirect, long refreshExpiresAt) {
            this.sessionId = sessionId;
            this.postLoginRedirect = postLoginRedirect;
            this.refreshExpiresAt = refreshExpiresAt;
        }
    }

    public CallbackResult handleCallback(String code, String stateParam, String pendingAuthCookieValue) {
        if (code == null || stateParam == null || pendingAuthCookieValue == null) {
            throw new OidcException("Missing code/state/pending-auth cookie on callback");
        }

        PendingAuth pending = gson.fromJson(crypto.decrypt(pendingAuthCookieValue), PendingAuth.class);

        long now = Instant.now().getEpochSecond();
        if (now - pending.createdAt > config.pendingAuthMaxAgeSeconds) {
            throw new OidcException("Login attempt expired — please try again");
        }
        if (!constantTimeEquals(pending.state, stateParam)) {
            throw new OidcException("State mismatch — possible CSRF, rejecting");
        }

        DiscoveryDocument d = discovery();
        Map<String, Object> tokenResponse = exchangeCode(d, code, pending.codeVerifier);

        String idTokenRaw = (String) tokenResponse.get("id_token");
        String accessToken = (String) tokenResponse.get("access_token");
        String refreshToken = (String) tokenResponse.get("refresh_token");
        Number expiresIn = (Number) tokenResponse.get("expires_in");
        Number refreshExpiresIn = (Number) tokenResponse.get("refresh_expires_in");

        JWTClaimsSet claims = validateIdToken(idTokenRaw, pending.nonce);

        String sub = claims.getSubject();
        Map<String, Object> claimsMap = claims.getClaims();

        SessionRecord record = new SessionRecord();
        record.sessionId = randomToken();
        record.sub = sub;
        record.userClaimsJsonEnc = crypto.encrypt(gson.toJson(claimsMap));
        record.accessTokenEnc = crypto.encrypt(accessToken);
        record.refreshTokenEnc = (refreshToken != null) ? crypto.encrypt(refreshToken) : null;
        record.idTokenEnc = crypto.encrypt(idTokenRaw);
        record.accessExpiresAt = now + (expiresIn != null ? expiresIn.longValue() : 300);
        record.refreshExpiresAt = (refreshToken != null && refreshExpiresIn != null)
                ? now + refreshExpiresIn.longValue() : null;
        record.createdAt = now;
        record.lastAccessedAt = now;

        store.create(record);

        long cookieMaxAge = (record.refreshExpiresAt != null) ? record.refreshExpiresAt : record.accessExpiresAt;
        return new CallbackResult(record.sessionId, pending.postLoginRedirect, cookieMaxAge);
    }

    private Map<String, Object> exchangeCode(DiscoveryDocument d, String code, String codeVerifier) {
        StringBuilder body = new StringBuilder();
        body.append("grant_type=authorization_code")
                .append("&code=").append(enc(code))
                .append("&redirect_uri=").append(enc(config.redirectUri))
                .append("&client_id=").append(enc(config.clientId))
                .append("&code_verifier=").append(enc(codeVerifier));
        if (config.clientSecret != null) {
            body.append("&client_secret=").append(enc(config.clientSecret));
        }
        return postForm(d.tokenEndpoint, body.toString());
    }

    private Map<String, Object> postForm(String url, String body) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new OidcException("Token endpoint returned HTTP " + resp.statusCode() + ": " + resp.body());
            }
            return gson.fromJson(resp.body(), Map.class);
        } catch (OidcException e) {
            throw e;
        } catch (Exception e) {
            throw new OidcException("Token endpoint call failed", e);
        }
    }

    private JWTClaimsSet validateIdToken(String idTokenRaw, String expectedNonce) {
        try {
            discovery(); // ensures jwtProcessor is built
            SignedJWT jwt = SignedJWT.parse(idTokenRaw);
            JWTClaimsSet claims = jwtProcessor.process(jwt, null); // verifies signature via JWKS

            DiscoveryDocument d = discovery;
            long now = Instant.now().getEpochSecond();

            if (!Objects.equals(claims.getIssuer(), d.issuer)) {
                throw new OidcException("ID token issuer mismatch");
            }
            List<String> aud = claims.getAudience();
            if (aud == null || !aud.contains(config.clientId)) {
                throw new OidcException("ID token audience mismatch");
            }
            if (aud.size() > 1) {
                Object azp = claims.getClaim("azp");
                if (!config.clientId.equals(azp)) {
                    throw new OidcException("ID token azp mismatch for multi-audience token");
                }
            }
            Date exp = claims.getExpirationTime();
            if (exp == null || exp.toInstant().getEpochSecond() + config.clockSkewSeconds < now) {
                throw new OidcException("ID token expired");
            }
            Date iat = claims.getIssueTime();
            if (iat != null && iat.toInstant().getEpochSecond() - config.clockSkewSeconds > now) {
                throw new OidcException("ID token issued in the future");
            }
            Object nonceClaim = claims.getClaim("nonce");
            if (!Objects.equals(expectedNonce, nonceClaim)) {
                throw new OidcException("ID token nonce mismatch — possible replay");
            }

            return claims;
        } catch (OidcException e) {
            throw e;
        } catch (Exception e) {
            throw new OidcException("ID token validation failed", e);
        }
    }

    // ---------------------------------------------------------------
    // Resolve an existing session (with transparent refresh)
    // ---------------------------------------------------------------

    public Optional<UserSession> resolveSession(String sessionId) {
        if (sessionId == null) return Optional.empty();
        Optional<SessionRecord> maybe = store.get(sessionId);
        if (maybe.isEmpty()) return Optional.empty();
        SessionRecord record = maybe.get();

        long now = Instant.now().getEpochSecond();

        // Fully expired (refresh token gone or expired, or no refresh token and access token expired)
        boolean noRefresh = record.refreshTokenEnc == null;
        boolean refreshExpired = record.refreshExpiresAt != null && record.refreshExpiresAt < now;
        if ((noRefresh && record.accessExpiresAt < now) || refreshExpired) {
            store.delete(sessionId);
            return Optional.empty();
        }

        // Access token near/at expiry but refresh token still valid — refresh transparently
        if (record.accessExpiresAt - config.refreshBufferSeconds <= now && !noRefresh) {
            try {
                record = refresh(record);
            } catch (OidcException e) {
                // Refresh token was likely already rotated/invalidated (e.g. reused after rotation).
                // Treat as session-ended rather than a hard error — caller sees "not authenticated".
                store.delete(sessionId);
                return Optional.empty();
            }
        }

        record.lastAccessedAt = now;
        store.update(record);

        Map<String, Object> claims = gson.fromJson(crypto.decrypt(record.userClaimsJsonEnc), Map.class);
        return Optional.of(new UserSession(record.sessionId, record.sub, claims, record.accessExpiresAt));
    }

    private SessionRecord refresh(SessionRecord record) {
        DiscoveryDocument d = discovery();
        String refreshToken = crypto.decrypt(record.refreshTokenEnc);

        StringBuilder body = new StringBuilder();
        body.append("grant_type=refresh_token")
                .append("&refresh_token=").append(enc(refreshToken))
                .append("&client_id=").append(enc(config.clientId));
        if (config.clientSecret != null) {
            body.append("&client_secret=").append(enc(config.clientSecret));
        }

        Map<String, Object> tokenResponse = postForm(d.tokenEndpoint, body.toString());

        String newAccessToken = (String) tokenResponse.get("access_token");
        String newRefreshToken = (String) tokenResponse.get("refresh_token"); // Keycloak may rotate it
        String newIdToken = (String) tokenResponse.get("id_token");
        Number expiresIn = (Number) tokenResponse.get("expires_in");
        Number refreshExpiresIn = (Number) tokenResponse.get("refresh_expires_in");

        long now = Instant.now().getEpochSecond();
        record.accessTokenEnc = crypto.encrypt(newAccessToken);
        if (newRefreshToken != null) record.refreshTokenEnc = crypto.encrypt(newRefreshToken);
        if (newIdToken != null) record.idTokenEnc = crypto.encrypt(newIdToken);
        record.accessExpiresAt = now + (expiresIn != null ? expiresIn.longValue() : 300);
        if (refreshExpiresIn != null) record.refreshExpiresAt = now + refreshExpiresIn.longValue();

        return record;
    }

    // ---------------------------------------------------------------
    // Access token retrieval for calling downstream APIs (explicit opt-in)
    // ---------------------------------------------------------------

    public Optional<String> getAccessToken(String sessionId) {
        // Ensures freshness first
        if (resolveSession(sessionId).isEmpty()) return Optional.empty();
        return store.get(sessionId).map(r -> crypto.decrypt(r.accessTokenEnc));
    }

    // ---------------------------------------------------------------
    // Logout
    // ---------------------------------------------------------------

    /** Deletes the session and returns the Keycloak end_session_endpoint URL to redirect the browser to. */
    public String logout(String sessionId) {
        DiscoveryDocument d = discovery();
        String idTokenHint = null;
        if (sessionId != null) {
            Optional<SessionRecord> maybe = store.get(sessionId);
            if (maybe.isPresent()) {
                idTokenHint = crypto.decrypt(maybe.get().idTokenEnc);
                store.delete(sessionId);
            }
        }
        StringBuilder url = new StringBuilder(d.endSessionEndpoint)
                .append("?post_logout_redirect_uri=").append(enc(config.postLogoutRedirectUri))
                .append("&client_id=").append(enc(config.clientId));
        if (idTokenHint != null) {
            url.append("&id_token_hint=").append(enc(idTokenHint));
        }
        return url.toString();
    }

    // ---------------------------------------------------------------
    // Maintenance
    // ---------------------------------------------------------------

    /** Call periodically (e.g. hourly) from your app's own scheduler — this library doesn't spin up its own thread. */
    public void sweepExpiredSessions() {
        store.deleteExpired(Instant.now().getEpochSecond());
    }

    public void revokeAllSessionsForSubject(String sub) {
        store.deleteAllForSubject(sub);
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private String randomToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String base64UrlSha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
