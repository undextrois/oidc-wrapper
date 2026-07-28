package com.kdysystems.oidc;

import java.sql.*;
import java.util.Optional;

public final class SqliteSessionStore implements SessionStore {

    private final String jdbcUrl;

    public SqliteSessionStore(String dbPath) {
        this.jdbcUrl = "jdbc:sqlite:" + dbPath;
        init();
    }

    private void init() {
        try (Connection c = connect()) {
            try (Statement s = c.createStatement()) {
                s.execute("""
                    CREATE TABLE IF NOT EXISTS sessions (
                        session_id TEXT PRIMARY KEY,
                        sub TEXT NOT NULL,
                        user_claims_enc TEXT NOT NULL,
                        access_token_enc TEXT NOT NULL,
                        refresh_token_enc TEXT,
                        id_token_enc TEXT NOT NULL,
                        access_expires_at INTEGER NOT NULL,
                        refresh_expires_at INTEGER,
                        created_at INTEGER NOT NULL,
                        last_accessed_at INTEGER NOT NULL
                    )
                """);
                s.execute("CREATE INDEX IF NOT EXISTS idx_refresh_expires ON sessions(refresh_expires_at)");
                s.execute("CREATE INDEX IF NOT EXISTS idx_access_expires ON sessions(access_expires_at)");
                s.execute("CREATE INDEX IF NOT EXISTS idx_sub ON sessions(sub)");
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to initialize session store", e);
        }
    }

    private Connection connect() throws SQLException {
        Connection c = DriverManager.getConnection(jdbcUrl);
        // WAL: readers (session lookups on every request) don't block behind writers (login/refresh/logout).
        try (Statement s = c.createStatement()) {
            s.execute("PRAGMA journal_mode=WAL");
            s.execute("PRAGMA busy_timeout=5000");
        }
        return c;
    }

    @Override
    public void create(SessionRecord r) {
        String sql = """
            INSERT INTO sessions
                (session_id, sub, user_claims_enc, access_token_enc, refresh_token_enc, id_token_enc,
                 access_expires_at, refresh_expires_at, created_at, last_accessed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """;
        try (Connection c = connect(); PreparedStatement ps = c.prepareStatement(sql)) {
            bind(ps, r);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to create session", e);
        }
    }

    @Override
    public Optional<SessionRecord> get(String sessionId) {
        String sql = "SELECT * FROM sessions WHERE session_id = ?";
        try (Connection c = connect(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, sessionId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return Optional.empty();
                return Optional.of(map(rs));
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to load session", e);
        }
    }

    @Override
    public void update(SessionRecord r) {
        String sql = """
            UPDATE sessions SET
                user_claims_enc = ?, access_token_enc = ?, refresh_token_enc = ?, id_token_enc = ?,
                access_expires_at = ?, refresh_expires_at = ?, last_accessed_at = ?
            WHERE session_id = ?
        """;
        try (Connection c = connect(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, r.userClaimsJsonEnc);
            ps.setString(2, r.accessTokenEnc);
            ps.setString(3, r.refreshTokenEnc);
            ps.setString(4, r.idTokenEnc);
            ps.setLong(5, r.accessExpiresAt);
            if (r.refreshExpiresAt != null) ps.setLong(6, r.refreshExpiresAt); else ps.setNull(6, Types.INTEGER);
            ps.setLong(7, r.lastAccessedAt);
            ps.setString(8, r.sessionId);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to update session", e);
        }
    }

    @Override
    public void delete(String sessionId) {
        try (Connection c = connect(); PreparedStatement ps = c.prepareStatement("DELETE FROM sessions WHERE session_id = ?")) {
            ps.setString(1, sessionId);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to delete session", e);
        }
    }

    @Override
    public void deleteExpired(long nowEpochSeconds) {
        // Sessions with no refresh token expire when the access token does;
        // sessions with a refresh token stay valid until the refresh token expires.
        String sql = """
            DELETE FROM sessions
            WHERE (refresh_expires_at IS NOT NULL AND refresh_expires_at < ?)
               OR (refresh_expires_at IS NULL AND access_expires_at < ?)
        """;
        try (Connection c = connect(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setLong(1, nowEpochSeconds);
            ps.setLong(2, nowEpochSeconds);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to sweep expired sessions", e);
        }
    }

    @Override
    public void deleteAllForSubject(String sub) {
        try (Connection c = connect(); PreparedStatement ps = c.prepareStatement("DELETE FROM sessions WHERE sub = ?")) {
            ps.setString(1, sub);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to revoke sessions for subject", e);
        }
    }

    private void bind(PreparedStatement ps, SessionRecord r) throws SQLException {
        ps.setString(1, r.sessionId);
        ps.setString(2, r.sub);
        ps.setString(3, r.userClaimsJsonEnc);
        ps.setString(4, r.accessTokenEnc);
        ps.setString(5, r.refreshTokenEnc);
        ps.setString(6, r.idTokenEnc);
        ps.setLong(7, r.accessExpiresAt);
        if (r.refreshExpiresAt != null) ps.setLong(8, r.refreshExpiresAt); else ps.setNull(8, Types.INTEGER);
        ps.setLong(9, r.createdAt);
        ps.setLong(10, r.lastAccessedAt);
    }

    private SessionRecord map(ResultSet rs) throws SQLException {
        SessionRecord r = new SessionRecord();
        r.sessionId = rs.getString("session_id");
        r.sub = rs.getString("sub");
        r.userClaimsJsonEnc = rs.getString("user_claims_enc");
        r.accessTokenEnc = rs.getString("access_token_enc");
        r.refreshTokenEnc = rs.getString("refresh_token_enc");
        r.idTokenEnc = rs.getString("id_token_enc");
        r.accessExpiresAt = rs.getLong("access_expires_at");
        long refreshExp = rs.getLong("refresh_expires_at");
        r.refreshExpiresAt = rs.wasNull() ? null : refreshExp;
        r.createdAt = rs.getLong("created_at");
        r.lastAccessedAt = rs.getLong("last_accessed_at");
        return r;
    }
}
