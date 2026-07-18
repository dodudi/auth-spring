package com.auth.client.repository;

import com.auth.client.dto.ClientSummary;

import java.util.List;

public interface ClientRepository {

    List<ClientSummary> findAll();

    boolean existsByClientId(String clientId);

    void deleteById(String id);

}
