package com.auth.client.application;

import com.auth.client.dto.ClientCreateRequest;
import com.auth.client.dto.ClientDetail;
import com.auth.client.dto.ClientSummary;
import com.auth.client.dto.ClientUpdateRequest;
import com.auth.client.dto.SecretRevealResponse;

import java.util.List;

public interface ClientManagement {

    /**
     * 등록된 모든 OAuth2 클라이언트의 요약 목록을 반환한다.
     */
    List<ClientSummary> findAll();

    /**
     * 지정한 내부 UUID({@code id})로 클라이언트 상세 정보를 반환한다.
     *
     * @param id 내부 UUID (clientId가 아님)
     */
    ClientDetail getDetail(String id);

    /**
     * 새 OAuth2 클라이언트를 등록하고, 평문 시크릿을 포함한 응답을 반환한다.
     * 평문 시크릿은 이 시점에만 노출되며 이후에는 복호화할 수 없다.
     */
    SecretRevealResponse create(ClientCreateRequest request);

    /**
     * 기존 클라이언트의 설정을 갱신한다.
     *
     * @param id 내부 UUID (clientId가 아님)
     */
    void update(String id, ClientUpdateRequest request);

    /**
     * 클라이언트를 삭제한다. 연결된 토큰·동의 정보도 함께 제거된다.
     *
     * @param id 내부 UUID (clientId가 아님)
     */
    void delete(String id);

    /**
     * 클라이언트 시크릿을 재발급한다. 기존 시크릿은 즉시 무효화되며,
     * 새 평문 시크릿은 이 시점에만 노출된다.
     *
     * @param id 내부 UUID (clientId가 아님)
     */
    SecretRevealResponse regenerateSecret(String id);
}
