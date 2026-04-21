CREATE TABLE users
(
    id             UUID         NOT NULL,
    email          VARCHAR(255) NOT NULL,
    password       VARCHAR(255),
    nickname       VARCHAR(100) NOT NULL,
    email_verified BOOLEAN      NOT NULL DEFAULT FALSE,
    status         VARCHAR(20)  NOT NULL DEFAULT 'ACTIVE',
    created_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_users PRIMARY KEY (id),
    CONSTRAINT uk_users_email UNIQUE (email)
);

CREATE TABLE social_accounts
(
    id          UUID        NOT NULL,
    user_id     UUID        NOT NULL,
    provider    VARCHAR(20) NOT NULL,
    provider_id VARCHAR(255) NOT NULL,
    created_at  TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_social_accounts PRIMARY KEY (id),
    CONSTRAINT fk_social_accounts_user FOREIGN KEY (user_id) REFERENCES users (id),
    CONSTRAINT uk_social_accounts_provider UNIQUE (provider, provider_id)
);

CREATE TABLE roles
(
    id          BIGSERIAL    NOT NULL,
    name        VARCHAR(50)  NOT NULL,
    description VARCHAR(200),
    CONSTRAINT pk_roles PRIMARY KEY (id),
    CONSTRAINT uk_roles_name UNIQUE (name)
);

CREATE TABLE user_roles
(
    user_id    UUID      NOT NULL,
    role_id    BIGINT    NOT NULL,
    granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_user_roles PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users (id),
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles (id)
);
