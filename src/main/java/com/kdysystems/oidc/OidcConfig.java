package com.kdysystems.oidc;

import java.util.Base64;

/**
 * All the knobs the engine needs. One config = one Keycloak realm/client.
 * If you need multiple realms/clients, instantiate multiple engines — don't
 * try to make one engine multi-tenant, it's not worth the complexity here.
 */
public final class OidcConfig {

    public enum Mode { JAVALIN_AUTO, MANUAL }

    public final String keycloakBaseUrl;      // e.g. https://auth.example.com
    public final String realm;                // e.g. "kdy"
    public final String clientId;
    public final String clientSecret;         // null for public clients
    public final String redirectUri;          // must match a Keycloak client redirect URI
    public final String postLogoutRedirectUri;
    public final String scopes;               // default "openid profile email"

    public final String sqliteDbPath;         // e.g. "./data/sessions.db"
    public final byte[] encryptionKey;         // 32 bytes, for AES-256-GCM on stored tokens

    public final Mode mode;
    public final String sessionCookieName;    // default "SESSION"
    public final String pendingAuthCookieName; // default "OIDC_PENDING"

    public final int refreshBufferSeconds;    // refresh access token this many seconds before expiry
    public final int clockSkewSeconds;        // tolerance when checking exp/iat on ID tokens
    public final int pendingAuthMaxAgeSeconds; // how long the login->callback round trip is allowed to take

    private OidcConfig(Builder b) {
        this.keycloakBaseUrl = require(b.keycloakBaseUrl, "keycloakBaseUrl");
        this.realm = require(b.realm, "realm");
        this.clientId = require(b.clientId, "clientId");
        this.clientSecret = b.clientSecret;
        this.redirectUri = require(b.redirectUri, "redirectUri");
        this.postLogoutRedirectUri = require(b.postLogoutRedirectUri, "postLogoutRedirectUri");
        this.scopes = b.scopes;
        this.sqliteDbPath = require(b.sqliteDbPath, "sqliteDbPath");
        this.encryptionKey = require(b.encryptionKey, "encryptionKey");
        if (this.encryptionKey.length != 32) {
            throw new IllegalArgumentException("encryptionKey must be exactly 32 bytes (AES-256)");
        }
        this.mode = b.mode;
        this.sessionCookieName = b.sessionCookieName;
        this.pendingAuthCookieName = b.pendingAuthCookieName;
        this.refreshBufferSeconds = b.refreshBufferSeconds;
        this.clockSkewSeconds = b.clockSkewSeconds;
        this.pendingAuthMaxAgeSeconds = b.pendingAuthMaxAgeSeconds;
    }

    private static <T> T require(T val, String name) {
        if (val == null) throw new IllegalArgumentException(name + " is required");
        return val;
    }

    /** Base URL for this realm's OIDC endpoints, e.g. .../realms/{realm} */
    public String realmBaseUrl() {
        return keycloakBaseUrl.replaceAll("/+$", "") + "/realms/" + realm;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String keycloakBaseUrl;
        private String realm;
        private String clientId;
        private String clientSecret;
        private String redirectUri;
        private String postLogoutRedirectUri;
        private String scopes = "openid profile email";
        private String sqliteDbPath;
        private byte[] encryptionKey;
        private Mode mode = Mode.JAVALIN_AUTO;
        private String sessionCookieName = "SESSION";
        private String pendingAuthCookieName = "OIDC_PENDING";
        private int refreshBufferSeconds = 60;
        private int clockSkewSeconds = 60;
        private int pendingAuthMaxAgeSeconds = 600; // 10 minutes

        public Builder keycloakBaseUrl(String v) { this.keycloakBaseUrl = v; return this; }
        public Builder realm(String v) { this.realm = v; return this; }
        public Builder clientId(String v) { this.clientId = v; return this; }
        public Builder clientSecret(String v) { this.clientSecret = v; return this; }
        public Builder redirectUri(String v) { this.redirectUri = v; return this; }
        public Builder postLogoutRedirectUri(String v) { this.postLogoutRedirectUri = v; return this; }
        public Builder scopes(String v) { this.scopes = v; return this; }
        public Builder sqliteDbPath(String v) { this.sqliteDbPath = v; return this; }
        public Builder encryptionKeyBase64(String base64) { this.encryptionKey = Base64.getDecoder().decode(base64); return this; }
        public Builder mode(Mode v) { this.mode = v; return this; }
        public Builder sessionCookieName(String v) { this.sessionCookieName = v; return this; }
        public Builder pendingAuthCookieName(String v) { this.pendingAuthCookieName = v; return this; }
        public Builder refreshBufferSeconds(int v) { this.refreshBufferSeconds = v; return this; }
        public Builder clockSkewSeconds(int v) { this.clockSkewSeconds = v; return this; }
        public Builder pendingAuthMaxAgeSeconds(int v) { this.pendingAuthMaxAgeSeconds = v; return this; }

        public OidcConfig build() { return new OidcConfig(this); }
    }
}
