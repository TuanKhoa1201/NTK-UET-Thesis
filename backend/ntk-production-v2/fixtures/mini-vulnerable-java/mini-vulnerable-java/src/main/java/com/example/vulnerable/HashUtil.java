package com.example.vulnerable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Small shared helper used by the "safe" variants elsewhere in this
 * project. Not a vulnerability class itself.
 *
 * Note: SHA-256 of a raw password is shown here only to keep the
 * example short and dependency-free. In a real system, passwords must
 * be hashed with a slow, salted KDF such as bcrypt, scrypt, or
 * Argon2 - never a fast general-purpose digest like SHA-256 or MD5.
 */
final class HashUtil {

    private HashUtil() {
    }

    static String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
