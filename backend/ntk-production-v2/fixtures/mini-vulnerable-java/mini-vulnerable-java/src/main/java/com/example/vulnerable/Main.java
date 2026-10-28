package com.example.vulnerable;

/**
 * Entry point for the mini-vulnerable-java demo application.
 *
 * This class does not itself contain a vulnerability; it exists only
 * to make the project a runnable, realistic mini-application (as
 * opposed to a bag of disconnected snippets) so that SAST tools can
 * exercise call-graph / data-flow analysis across class boundaries,
 * starting from a single external input source (args[]).
 *
 * Each subcommand forwards a single command-line argument -
 * standing in for untrusted external input such as an HTTP request
 * parameter - into the corresponding vulnerable class.
 */
public final class Main {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            printUsage();
            return;
        }

        String command = args[0];
        String userInput = args[1];
        switch (command) {
            case "ping":
                System.out.println(new CommandInjection().pingHostVulnerable(userInput));
                break;
            case "read-file":
                System.out.println(new String(new PathTraversal().readAttachmentVulnerable(userInput)));
                break;
            case "find-user":
                System.out.println(new SqlInjection().findUserVulnerable(userInput));
                break;
            case "fetch-url":
                System.out.println(new SsrfExample().fetchRemoteResourceVulnerable(userInput));
                break;
            case "hash-password":
                System.out.println(new WeakHash().hashPasswordVulnerable(userInput));
                break;
            case "parse-xml":
                System.out.println(new XxeExample().parseContactsXmlVulnerable(userInput));
                break;
            case "find-employee":
                System.out.println(new LdapInjection().findEmployeeVulnerable(userInput));
                break;
            default:
                printUsage();
        }
    }

    private static void printUsage() {
        System.out.println("Usage: java -cp target/classes com.example.vulnerable.Main <command> <input>");
        System.out.println("Commands: ping | read-file | find-user | fetch-url | hash-password | parse-xml | find-employee");
        System.out.println("Note: this is an intentionally vulnerable demo app. Do not expose it to untrusted input.");
    }
}
