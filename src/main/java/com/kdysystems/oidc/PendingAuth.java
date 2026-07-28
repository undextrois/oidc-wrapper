package com.kdysystems.oidc;

/**
 * Survives the redirect round-trip to Keycloak and back via a short-lived
 * encrypted cookie (never a server-side table — it's short-lived and
 * per-browser, a cookie is the right lifetime/shape for it).
 */
final class PendingAuth {
    String state;
    String nonce;
    String codeVerifier;
    String postLoginRedirect; // where to send the user after successful login
    long createdAt;           // epoch seconds, checked against pendingAuthMaxAgeSeconds
}
