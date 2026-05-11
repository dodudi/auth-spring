package com.auth.admin.application;

import com.auth.admin.dto.ClientCreateRequest;
import com.auth.admin.dto.ClientDetail;
import com.auth.admin.dto.ClientSummary;
import com.auth.admin.dto.ClientUpdateRequest;
import com.auth.admin.dto.SecretRevealResponse;

import java.util.List;

public interface AdminClientManagement {

    List<ClientSummary> findAll();

    ClientDetail getDetail(String id);

    SecretRevealResponse create(ClientCreateRequest request);

    void update(String id, ClientUpdateRequest request);

    void delete(String id);

    SecretRevealResponse regenerateSecret(String id);
}
