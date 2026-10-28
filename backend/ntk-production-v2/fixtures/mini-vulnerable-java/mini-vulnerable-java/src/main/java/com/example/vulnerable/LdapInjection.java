package com.example.vulnerable;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.util.Hashtable;

/**
 * CWE-90: LDAP Injection. Corporate directory "look up employee by
 * username" feature. See README.md for details and the expected
 * OpenGrep finding.
 */
public class LdapInjection {

    private static final String LDAP_URL = "ldap://directory.example.com:389";
    private static final String SEARCH_BASE = "ou=people,dc=example,dc=com";

    /**
     * VULNERABLE: the username is concatenated directly into the LDAP
     * search filter. An attacker supplying something like:
     *   admin)(|(uid=*
     * can alter the filter's logical structure to bypass intended
     * restrictions or enumerate unintended attributes/entries.
     */
    public String findEmployeeVulnerable(String userSuppliedUsername) throws NamingException {
        DirContext ctx = createContext();
        try {
            // TAINT SOURCE: userSuppliedUsername from an external caller,
            // e.g. request.getParameter("username").
            // SINK: filter string built via direct concatenation of tainted input.
            String filter = "(uid=" + userSuppliedUsername + ")";
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            NamingEnumeration<SearchResult> results = ctx.search(SEARCH_BASE, filter, controls);
            return firstResultToString(results);
        } finally {
            ctx.close();
        }
    }

    /**
     * SAFE VERSION: the user-supplied value is escaped per RFC 4515
     * before being embedded in the filter, neutralizing the special
     * characters ( ) * \ and NUL that give an attacker control over
     * the filter's structure.
     */
    public String findEmployeeSafe(String userSuppliedUsername) throws NamingException {
        DirContext ctx = createContext();
        try {
            String escaped = escapeLdapSearchFilter(userSuppliedUsername);
            String filter = "(uid=" + escaped + ")";
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            NamingEnumeration<SearchResult> results = ctx.search(SEARCH_BASE, filter, controls);
            return firstResultToString(results);
        } finally {
            ctx.close();
        }
    }

    /** RFC 4515 filter-value escaping. */
    private String escapeLdapSearchFilter(String input) {
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            switch (c) {
                case '\\': sb.append("\\5c"); break;
                case '*':  sb.append("\\2a"); break;
                case '(':  sb.append("\\28"); break;
                case ')':  sb.append("\\29"); break;
                case '\0': sb.append("\\00"); break;
                default:   sb.append(c);
            }
        }
        return sb.toString();
    }

    private DirContext createContext() throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");
        env.put("java.naming.provider.url", LDAP_URL);
        return new InitialDirContext(env);
    }

    private String firstResultToString(NamingEnumeration<SearchResult> results) throws NamingException {
        if (results != null && results.hasMore()) {
            SearchResult result = results.next();
            return result.getNameInNamespace();
        }
        return null;
    }
}
