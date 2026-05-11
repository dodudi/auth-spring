package com.auth.admin.domain;

import com.auth.admin.dto.ClientSummary;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@RequiredArgsConstructor
public class ClientRepositoryImpl implements ClientRepository {

    private static final String FIND_ALL_SQL =
            "SELECT id, client_id, client_name, authorization_grant_types, scopes, client_id_issued_at " +
                    "FROM oauth2_registered_client ORDER BY client_id_issued_at DESC";

    private static final String EXISTS_BY_CLIENT_ID_SQL =
            "SELECT COUNT(*) FROM oauth2_registered_client WHERE client_id = ?";

    private static final String DELETE_BY_ID_SQL =
            "DELETE FROM oauth2_registered_client WHERE id = ?";

    private final JdbcTemplate jdbcTemplate;

    @Override
    public List<ClientSummary> findAll() {
        return jdbcTemplate.query(FIND_ALL_SQL, (rs, rowNum) -> new ClientSummary(
                rs.getString("id"),
                rs.getString("client_id"),
                rs.getString("client_name"),
                rs.getString("authorization_grant_types"),
                rs.getString("scopes"),
                rs.getTimestamp("client_id_issued_at").toInstant()
        ));
    }

    @Override
    public boolean existsByClientId(String clientId) {
        Integer count = jdbcTemplate.queryForObject(EXISTS_BY_CLIENT_ID_SQL, Integer.class, clientId);
        return count != null && count > 0;
    }

    @Override
    public void deleteById(String id) {
        jdbcTemplate.update(DELETE_BY_ID_SQL, id);
    }
}
