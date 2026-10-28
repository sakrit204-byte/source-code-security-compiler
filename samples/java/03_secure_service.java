/* A secure reference version: bound parameters, canonical paths, SecureRandom, output encoding */
package com.example.secure;

import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HexFormat;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class AccountService {
    private static final Logger LOG = Logger.getLogger(AccountService.class.getName());
    private static final File BASE_DIR = new File("/srv/app/reports");
    private final SecureRandom random = new SecureRandom();
    private final Connection connection;

    public AccountService(Connection connection) {
        this.connection = connection;
    }

    public String findEmail(String userName) throws SQLException {
        String sql = "SELECT email FROM users WHERE name = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, userName);
            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next() ? rs.getString("email") : null;
            }
        }
    }

    public File reportFile(String name) throws IOException {
        File candidate = new File(BASE_DIR, name).getCanonicalFile();
        if (!candidate.getPath().startsWith(BASE_DIR.getCanonicalPath() + File.separator)) {
            throw new IOException("report outside the allowed directory");
        }
        return candidate;
    }

    public String newResetToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    public int parseLimit(String value) {
        try {
            return Math.min(Integer.parseInt(value), 100);
        } catch (NumberFormatException e) {
            LOG.log(Level.WARNING, "invalid limit, using default");
            return 20;
        }
    }
}
