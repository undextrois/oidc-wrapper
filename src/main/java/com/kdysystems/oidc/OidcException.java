package com.kdysystems.oidc;

/** Thrown for any rejection in the auth flow: bad state, expired pending-auth, invalid ID token, failed exchange. */
public class OidcException extends RuntimeException {
    public OidcException(String message) { super(message); }
    public OidcException(String message, Throwable cause) { super(message, cause); }
}
