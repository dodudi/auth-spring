package com.auth.admin.domain;

import com.auth.admin.dto.ClientSummary;

import java.util.List;

public interface ClientRepository {

    List<ClientSummary> findAll();

    boolean existsByClientId(String clientId);

    void deleteById(String id);

}
