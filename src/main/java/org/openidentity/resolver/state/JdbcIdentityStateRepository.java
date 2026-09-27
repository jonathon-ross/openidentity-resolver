package org.openidentity.resolver.state;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class JdbcIdentityStateRepository implements IdentityStateRepository {
  private final JdbcClient jdbc;

  public JdbcIdentityStateRepository(JdbcClient jdbc) {
    this.jdbc = jdbc;
  }

  @Override
  public Optional<StoredIdentityState> findCurrent(byte[] identityId) {
    return jdbc.sql(
            """
            SELECT state_hash, identity_id, sequence, state_version, status,
                   canonical_state_bytes, created_at
            FROM identity_state
            WHERE identity_id = :identityId
            ORDER BY sequence DESC
            LIMIT 1
            """)
        .param("identityId", identityId)
        .query(this::map)
        .optional();
  }

  @Override
  public Optional<StoredIdentityState> findHistorical(byte[] identityId, byte[] stateHash) {
    return jdbc.sql(
            """
            SELECT state_hash, identity_id, sequence, state_version, status,
                   canonical_state_bytes, created_at
            FROM identity_state
            WHERE identity_id = :identityId AND state_hash = :stateHash
            """)
        .param("identityId", identityId)
        .param("stateHash", stateHash)
        .query(this::map)
        .optional();
  }

  private StoredIdentityState map(ResultSet rs, int rowNum) throws SQLException {
    return new StoredIdentityState(
        rs.getBytes("state_hash"),
        rs.getBytes("identity_id"),
        rs.getBigDecimal("sequence").toBigIntegerExact(),
        rs.getInt("state_version"),
        rs.getInt("status"),
        rs.getBytes("canonical_state_bytes"),
        rs.getTimestamp("created_at").toInstant());
  }
}
