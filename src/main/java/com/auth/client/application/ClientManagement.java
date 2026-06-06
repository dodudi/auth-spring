package com.auth.client.application;

import com.auth.client.dto.ClientCreateRequest;
import com.auth.client.dto.ClientDetail;
import com.auth.client.dto.ClientSummary;
import com.auth.client.dto.ClientUpdateRequest;
import com.auth.client.dto.SecretRevealResponse;

import java.util.List;

public interface ClientManagement {

    List<ClientSummary> findAll();

    ClientDetail getDetail(String id);

    SecretRevealResponse create(ClientCreateRequest request);

    void update(String id, ClientUpdateRequest request);

    void delete(String id);

    SecretRevealResponse regenerateSecret(String id);
}
