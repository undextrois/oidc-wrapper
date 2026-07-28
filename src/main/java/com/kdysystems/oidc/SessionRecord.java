package com.kdysystems.oidc;

/**
 * Internal storage shape. Token fields are already encrypted (base64 ciphertext)
 * by the time they reach the store — the store never sees plaintext tokens.
 */
final class SessionRecord {
    String sessionId;
    String sub;
    String userClaimsJsonEnc;   // encrypted JSON of the claims map
    String accessTokenEnc;
    String refreshTokenEnc;     // may be null if Keycloak didn't issue one
    String idTokenEnc;
    long accessExpiresAt;       // epoch seconds
    Long refreshExpiresAt;      // epoch seconds, null if no refresh token
    long createdAt;
    long lastAccessedAt;
}
