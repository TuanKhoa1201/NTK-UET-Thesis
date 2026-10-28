package com.example.vulnerable;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * CWE-89: SQL Injection (plain JDBC). "Find user by name" lookup.
 * See README.md for details and the expected OpenGrep finding.
 */
public class SqlInjection {

    private static final String JDBC_URL = "jdbc:postgresql://localhost:5432/appdb";
    private static final String DB_USER = "app_user";
    private static final String DB_PASSWORD = "app_password"; // see HardcodedPassword.java for the dedicated CWE-798 case

    /** VULNERABLE: username concatenated directly into SQL text via plain Statement. */
    public String findUserVulnerable(String userSuppliedName) throws SQLException {
        // TAINT SOURCE: userSuppliedName from an external caller,
        // e.g. request.getParameter("username").
        String sql = "SELECT id, email FROM users WHERE username = '" + userSuppliedName + "'";
        try (Connection conn = DriverManager.getConnection(JDBC_URL, DB_USER, DB_PASSWORD);
             Statement stmt = conn.createStatement();
             // SINK: executeQuery on a concatenated, tainted SQL string.
             ResultSet rs = stmt.executeQuery(sql)) {

            StringBuilder result = new StringBuilder();
            while (rs.next()) {
                result.append(rs.getString("id")).append(":").append(rs.getString("email")).append("\n");
            }
            return result.toString();
        }
    }

    /** SAFE: parameterized PreparedStatement, value always treated as data. */
    public String findUserSafe(String userSuppliedName) throws SQLException {
        String sql = "SELECT id, email FROM users WHERE username = ?";
        try (Connection conn = DriverManager.getConnection(JDBC_URL, DB_USER, DB_PASSWORD);
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1, userSuppliedName);
            try (ResultSet rs = stmt.executeQuery()) {
                StringBuilder result = new StringBuilder();
                while (rs.next()) {
                    result.append(rs.getString("id")).append(":").append(rs.getString("email")).append("\n");
                }
                return result.toString();
            }
        }
    }
}
