package com.kdysystems.oidc;

import java.util.Collections;
import java.util.Map;

/**
 * What application code gets after a session resolves successfully.
 * Deliberately does not carry raw tokens — if a backend needs to call
 * a downstream API with the access token, use engine.getAccessToken(sessionId)
 * explicitly, so it's an intentional call site, not something that leaks
 * into logs via a toString() somewhere.
 */
public final class UserSession {
    private final String sessionId;
    private final String subject;
    private final Map<String, Object> claims;
    private final long accessExpiresAt;

    public UserSession(String sessionId, String subject, Map<String, Object> claims, long accessExpiresAt) {
        this.sessionId = sessionId;
        this.subject = subject;
        this.claims = Collections.unmodifiableMap(claims);
        this.accessExpiresAt = accessExpiresAt;
    }

    public String sessionId() { return sessionId; }
    public String subject() { return subject; }
    public Map<String, Object> claims() { return claims; }
    public long accessExpiresAt() { return accessExpiresAt; }

    @Override
    public String toString() {
        // Deliberately excludes claims (may contain email/PII) from default logging output
        return "UserSession{sessionId='" + sessionId + "', subject='" + subject + "'}";
    }
}
