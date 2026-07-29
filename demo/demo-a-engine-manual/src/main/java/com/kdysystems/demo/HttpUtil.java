package com.kdysystems.demo;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Bare-bones cookie/query helpers. The point of Demo A is to prove
 * KeycloakOidcEngine works against literally any HTTP stack — so this
 * intentionally doesn't reach for a web framework, just the JDK's
 * com.sun.net.httpserver.HttpServer.
 */
final class HttpUtil {

    static Map<String, String> parseQuery(String rawQuery) {
        Map<String, String> params = new HashMap<>();
        if (rawQuery == null || rawQuery.isBlank()) return params;
        for (String pair : rawQuery.split("&")) {
            int eq = pair.indexOf('=');
            if (eq < 0) continue;
            String key = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
            String value = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            params.put(key, value);
        }
        return params;
    }

    static Map<String, String> parseCookies(List<String> cookieHeaders) {
        Map<String, String> cookies = new HashMap<>();
        if (cookieHeaders == null) return cookies;
        for (String header : cookieHeaders) {
            for (String part : header.split(";")) {
                int eq = part.indexOf('=');
                if (eq < 0) continue;
                String name = part.substring(0, eq).trim();
                String value = part.substring(eq + 1).trim();
                cookies.put(name, value);
            }
        }
        return cookies;
    }

    /**
     * NOTE: no `Secure` attribute here on purpose — this demo runs on plain
     * HTTP on localhost. Any real deployment (Demo B/C's Javalin plugin
     * included) must run behind HTTPS with Secure cookies; see
     * JavalinOidcPlugin for the production-shaped version.
     */
    static String buildSetCookie(String name, String value, int maxAgeSeconds) {
        // No URL-encoding here: standard base64 output (A-Z a-z 0-9 + / =) is
        // already legal inside a cookie value per RFC 6265, and parseCookies()
        // above reads values back raw — encoding here without a matching
        // decode there was the actual bug (percent-escapes never got undone,
        // so the decrypt step choked on a literal '%').
        return name + "=" + value + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + maxAgeSeconds;
    }

    static String buildDeleteCookie(String name) {
        return name + "=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";
    }
}
