/* Servlet with SQL injection, command injection, path traversal and XSS */
package com.example.web;

import java.io.*;
import java.sql.*;
import java.util.Random;
import javax.servlet.http.*;

public class UserServlet extends HttpServlet {
    private static final String DB_URL = "jdbc:mysql://10.0.0.12:3306/app";
    private static final String DB_PASSWORD = "Pr0d#Passw0rd";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String user = request.getParameter("user");
        String file = request.getParameter("file");

        // SQL built by string concatenation
        try (Connection conn = DriverManager.getConnection(DB_URL, "admin", DB_PASSWORD)) {
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + user + "'");
            while (rs.next()) {
                response.getWriter().println("<p>Hello " + rs.getString("name") + "</p>");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }

        // Command injection: the parameter reaches a shell
        Runtime.getRuntime().exec("sh -c ping -c 1 " + request.getParameter("host"));

        // Path traversal
        FileInputStream in = new FileInputStream("/var/reports/" + file);
        in.close();

        // Reflected XSS
        response.getWriter().write("Searched for: " + user);
    }

    public String newResetToken() {
        Random rnd = new Random();
        String token = Long.toHexString(rnd.nextLong());
        return token;
    }

    public boolean checkAdmin(String password) {
        if (password.equals("letmein123")) {
            return true;
        }
        return false;
    }
}
