package com.example.vulnerable;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.io.Serializable;

/**
 * CWE-502: Insecure Deserialization. "Restore session from cookie"
 * feature. See README.md for details and the expected OpenGrep
 * finding.
 */
public class InsecureDeserialization {

    /** Example payload class that would be serialized into the session token. */
    public static class SessionToken implements Serializable {
        private static final long serialVersionUID = 1L;
        public String userId;
        public long issuedAt;
    }

    /** VULNERABLE: readObject() on unfiltered bytes controlled entirely by the client. */
    public SessionToken restoreSessionVulnerable(byte[] userSuppliedSerializedBytes)
            throws IOException, ClassNotFoundException {

        // TAINT SOURCE: userSuppliedSerializedBytes from an external
        // caller, e.g. Base64.getDecoder().decode(cookieValue).
        InputStream byteStream = new ByteArrayInputStream(userSuppliedSerializedBytes);
        // SINK: readObject() on unfiltered, untrusted bytes.
        try (ObjectInputStream ois = new ObjectInputStream(byteStream)) {
            return (SessionToken) ois.readObject();
        }
    }

    /**
     * SAFE: JEP 290 ObjectInputFilter allow-lists the expected class
     * and bounds array size, rejecting everything else.
     */
    public SessionToken restoreSessionSafe(byte[] userSuppliedSerializedBytes)
            throws IOException, ClassNotFoundException {

        InputStream byteStream = new ByteArrayInputStream(userSuppliedSerializedBytes);
        try (ObjectInputStream ois = new ObjectInputStream(byteStream)) {
            ois.setObjectInputFilter(buildAllowListFilter());
            return (SessionToken) ois.readObject();
        }
    }

    private ObjectInputFilter buildAllowListFilter() {
        return filterInfo -> {
            Class<?> clazz = filterInfo.serialClass();
            if (clazz == null) {
                return ObjectInputFilter.Status.UNDECIDED;
            }

            boolean allowed = clazz == SessionToken.class
                    || clazz == String.class
                    || clazz == ObjectStreamClass.class;
            if (!allowed) {
                return ObjectInputFilter.Status.REJECTED;
            }

            if (filterInfo.arrayLength() >= 0 && filterInfo.arrayLength() > 1000) {
                return ObjectInputFilter.Status.REJECTED;
            }

            return ObjectInputFilter.Status.ALLOWED;
        };
    }
}
