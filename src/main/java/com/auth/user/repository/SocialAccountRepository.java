package com.auth.user.repository;

import com.auth.user.domain.SocialAccount;
import com.auth.user.domain.SocialProvider;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface SocialAccountRepository extends JpaRepository<SocialAccount, UUID> {

    @Query("SELECT sa FROM SocialAccount sa JOIN FETCH sa.user u LEFT JOIN FETCH u.roles WHERE sa.provider = :provider AND sa.providerId = :providerId")
    Optional<SocialAccount> findByProviderAndProviderId(
            @Param("provider") SocialProvider provider,
            @Param("providerId") String providerId);
}
