package com.example.vulnerable;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.Arrays;
import java.util.List;

/**
 * CWE-918: Server-Side Request Forgery (SSRF). "Fetch avatar/webhook
 * preview" feature. See README.md for details and the expected
 * OpenGrep finding.
 */
public class SsrfExample {

    // Minimal allow-list used only by the "safe" variant below.
    private static final List<String> ALLOWED_HOSTS =
            Arrays.asList("images.example.com", "cdn.example.com");

    /** VULNERABLE: target URL taken verbatim from caller, fetched directly (SSRF). */
    public String fetchRemoteResourceVulnerable(String userSuppliedUrl) throws IOException {
        // TAINT SOURCE: userSuppliedUrl from an external caller,
        // e.g. request.getParameter("avatarUrl").
        URL url = new URL(userSuppliedUrl);
        // SINK: outbound request to an attacker-controlled destination.
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(3000);
        conn.setReadTimeout(3000);
        return readBody(conn);
    }

    /** SAFE: destination host allow-listed, scheme restricted to https, redirects disabled. */
    public String fetchRemoteResourceSafe(String userSuppliedUrl) throws IOException {
        URI uri;
        try {
            uri = new URI(userSuppliedUrl);
        } catch (Exception e) {
            throw new IllegalArgumentException("Malformed URL", e);
        }

        String scheme = uri.getScheme();
        String host = uri.getHost();
        if (!"https".equalsIgnoreCase(scheme) || host == null || !ALLOWED_HOSTS.contains(host.toLowerCase())) {
            throw new SecurityException("Destination host is not allow-listed: " + host);
        }

        URL url = uri.toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(3000);
        conn.setReadTimeout(3000);
        conn.setInstanceFollowRedirects(false); // avoid redirect-based allow-list bypass

        return readBody(conn);
    }

    private String readBody(HttpURLConnection conn) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
        } finally {
            conn.disconnect();
        }
        return sb.toString();
    }
}
