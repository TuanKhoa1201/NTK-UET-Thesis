package com.example.vulnerable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * CWE-328: Weak Hash (MD5) used for password storage. "Create
 * account" flow. See README.md for details and the expected
 * OpenGrep finding.
 */
public class WeakHash {

    /** VULNERABLE: MD5 is broken and unsalted here; unsuitable for passwords. */
    public String hashPasswordVulnerable(String plainTextPassword) {
        try {
            // SINK: weak algorithm selection for a security-sensitive value.
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            byte[] hash = md5.digest(plainTextPassword.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("MD5 not available", e);
        }
    }

    /**
     * SAFE (illustrative): salted + iterated SHA-256 stand-in for a
     * real KDF. In production, use bcrypt/scrypt/Argon2 instead.
     */
    public String hashPasswordSafe(String plainTextPassword, byte[] perUserSalt, int iterations) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] input = concat(perUserSalt, plainTextPassword.getBytes(StandardCharsets.UTF_8));
            byte[] hash = input;
            for (int i = 0; i < iterations; i++) {
                hash = sha256.digest(hash);
            }
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
