package com.example.vulnerable;

/**
 * CWE-798: Use of Hard-coded Credentials. Internal admin API client.
 * See README.md for details and the expected OpenGrep finding.
 */
public class HardcodedPassword {

    // VULNERABLE: real secrets embedded directly in source code.
    private static final String ADMIN_USERNAME = "admin";
    private static final String ADMIN_PASSWORD = "SuperSecretP@ssw0rd!"; // hardcoded secret
    private static final String INTERNAL_API_KEY = "FAKE_INTERNAL_API_KEY";
    public boolean loginToAdminConsoleVulnerable(String suppliedUsername, String suppliedPassword) {
        // SINK: comparison against a hardcoded secret baked into the binary.
        return ADMIN_USERNAME.equals(suppliedUsername) && ADMIN_PASSWORD.equals(suppliedPassword);
    }

    public String callInternalAdminApiVulnerable() {
        // SINK: hardcoded API key used directly for authentication.
        return "Authorization: Bearer " + INTERNAL_API_KEY;
    }

    /** SAFE: secrets read from environment/vault at runtime; fails closed if absent. */
    public boolean loginToAdminConsoleSafe(String suppliedUsername, String suppliedPassword) {
        String expectedUsername = System.getenv("ADMIN_USERNAME");
        String expectedPasswordHash = System.getenv("ADMIN_PASSWORD_HASH");
        if (expectedUsername == null || expectedPasswordHash == null) {
            // Fail closed: no credentials configured means no access.
            return false;
        }

        String suppliedHash = HashUtil.sha256Hex(suppliedPassword);
        return expectedUsername.equals(suppliedUsername) && expectedPasswordHash.equals(suppliedHash);
    }
}
