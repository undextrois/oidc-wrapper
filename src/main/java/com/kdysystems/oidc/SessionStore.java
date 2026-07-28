package com.kdysystems.oidc;

import java.util.Optional;

/**
 * Storage seam. SqliteSessionStore is the default/reference implementation.
 * Swap in Postgres/Redis/etc later by implementing this — nothing else in
 * the engine needs to change.
 */
public interface SessionStore {

    void create(SessionRecord record);

    Optional<SessionRecord> get(String sessionId);

    void update(SessionRecord record);

    void delete(String sessionId);

    /** Delete all sessions whose refresh_expires_at (or access_expires_at if no refresh token) has passed. */
    void deleteExpired(long nowEpochSeconds);

    /** "Log this user out everywhere" — revoke by Keycloak subject. */
    void deleteAllForSubject(String sub);
}
