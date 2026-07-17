package com.auth.client.api;

import com.auth.client.application.ClientManagement;
import com.auth.client.dto.ClientCreateRequest;
import com.auth.client.dto.ClientDetail;
import com.auth.client.dto.ClientSummary;
import com.auth.client.dto.ClientUpdateRequest;
import com.auth.client.dto.SecretRevealResponse;
import com.auth.common.response.ApiResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/clients")
public class ClientController {

    private final ClientManagement clientManagement;

    @GetMapping
    public ResponseEntity<ApiResponse<List<ClientSummary>>> getClients() {
        return ResponseEntity.ok(ApiResponse.ok(clientManagement.findAll()));
    }

    @PostMapping
    public ResponseEntity<ApiResponse<SecretRevealResponse>> createClient(
            @Valid @RequestBody ClientCreateRequest request
    ) {
        SecretRevealResponse response = clientManagement.create(request);
        URI location = URI.create("/api/v1/clients/" + response.id());
        return ResponseEntity.created(location).body(ApiResponse.ok(response));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<ClientDetail>> getClient(@PathVariable String id) {
        return ResponseEntity.ok(ApiResponse.ok(clientManagement.getDetail(id)));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> updateClient(
            @PathVariable String id,
            @Valid @RequestBody ClientUpdateRequest request
    ) {
        clientManagement.update(id, request);
        return ResponseEntity.ok(ApiResponse.ok());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteClient(@PathVariable String id) {
        clientManagement.delete(id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/regenerate-secret")
    public ResponseEntity<ApiResponse<SecretRevealResponse>> regenerateSecret(@PathVariable String id) {
        return ResponseEntity.ok(ApiResponse.ok(clientManagement.regenerateSecret(id)));
    }
}
