package com.example.vulnerable;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * CWE-22: Path Traversal. "Download attachment" feature reading a
 * file from a fixed uploads directory by caller-supplied name. See
 * README.md for details and the expected OpenGrep finding.
 */
public class PathTraversal {

    private static final String UPLOAD_DIR = "/var/app/uploads";

    /** VULNERABLE: filename concatenated onto base dir, no containment check. */
    public byte[] readAttachmentVulnerable(String userSuppliedFileName) throws IOException {
        // TAINT SOURCE: userSuppliedFileName from an external request,
        // e.g. request.getParameter("file").
        File target = new File(UPLOAD_DIR, userSuppliedFileName);
        // SINK: file read using a path built from unsanitized input.
        return Files.readAllBytes(target.toPath());
    }

    /** SAFE: rejects traversal sequences, canonicalizes, verifies containment. */
    public byte[] readAttachmentSafe(String userSuppliedFileName) throws IOException {
        Path baseDir = Paths.get(UPLOAD_DIR).toRealPath();
        // Reject path separators / traversal sequences outright.
        if (userSuppliedFileName == null
                || userSuppliedFileName.contains("..")
                || userSuppliedFileName.contains("/")
                || userSuppliedFileName.contains("\\")) {
            throw new IllegalArgumentException("Invalid file name");
        }

        Path candidate = baseDir.resolve(userSuppliedFileName).normalize();
        // Defense in depth: verify containment even after normalization.
        if (!candidate.startsWith(baseDir)) {
            throw new SecurityException("Path traversal attempt detected");
        }

        return Files.readAllBytes(candidate);
    }
}
