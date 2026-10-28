package com.example.vulnerable;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * CWE-78: OS Command Injection.
 * A "ping host" diagnostic feature that shells out with a hostname
 * supplied by an external caller. See README.md for details and the
 * expected OpenGrep finding.
 */
public class CommandInjection {

    /** VULNERABLE: tainted host concatenated into a shell command line. */
    public String pingHostVulnerable(String userSuppliedHost) throws IOException {
        // TAINT SOURCE: userSuppliedHost originates from an external caller
        // (e.g. request.getParameter("host") in a real web handler).
        String command = "ping -c 1 " + userSuppliedHost;
        // SINK: shell interpretation of a tainted, concatenated string.
        Process process = Runtime.getRuntime().exec(new String[] { "/bin/sh", "-c", command });
        return readOutput(process);
    }

    /** SAFE: no shell, argv array, hostname validated against an allow-list pattern. */
    public String pingHostSafe(String userSuppliedHost) throws IOException {
        if (userSuppliedHost == null || !userSuppliedHost.matches("^[a-zA-Z0-9.\\-]{1,255}$")) {
            throw new IllegalArgumentException("Invalid hostname format");
        }

        // No shell, no string concatenation of a command line: arguments
        // are passed directly to the OS as an argv array.
        ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", userSuppliedHost);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        return readOutput(process);
    }

    private String readOutput(Process process) throws IOException {
        List<String> lines = new ArrayList<>();
        try (BufferedReader reader =
                     new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                lines.add(line);
            }
        }
        return String.join("\n", lines);
    }
}
