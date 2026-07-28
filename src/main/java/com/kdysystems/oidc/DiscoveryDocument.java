package com.kdysystems.oidc;

final class DiscoveryDocument {
    String issuer;
    String authorizationEndpoint;
    String tokenEndpoint;
    String endSessionEndpoint;
    String jwksUri;
    long fetchedAt; // epoch seconds, for cache TTL
}
