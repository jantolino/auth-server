-- Esquema para el servidor de autorización OAuth2 con Spring Authorization Server
-- Compatible con H2 y MySQL

-- Tabla de clientes registrados
CREATE TABLE IF NOT EXISTS oauth2_registered_client (
    id VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    client_id_issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret VARCHAR(255) DEFAULT NULL,
    client_secret_expires_at TIMESTAMP DEFAULT NULL,
    client_name VARCHAR(255) NOT NULL,
    client_authentication_methods VARCHAR(1000) NOT NULL,
    authorization_grant_types VARCHAR(1000) NOT NULL,
    redirect_uris VARCHAR(1000) DEFAULT NULL,
    post_logout_redirect_uris VARCHAR(1000) DEFAULT NULL,
    scopes TEXT NOT NULL,
    client_settings LONGTEXT NOT NULL,
    token_settings LONGTEXT NOT NULL,
    PRIMARY KEY (id)
);

-- Tabla de autorizaciones OAuth2
CREATE TABLE IF NOT EXISTS oauth2_authorization (
    id VARCHAR(100) NOT NULL,
    registered_client_id VARCHAR(100) NOT NULL,
    principal_name VARCHAR(200) NOT NULL,
    authorization_grant_type VARCHAR(100) NOT NULL,
    authorized_scopes TEXT,
    attributes LONGTEXT,
    state VARCHAR(500),
    authorization_code_value LONGTEXT,
    authorization_code_issued_at TIMESTAMP,
    authorization_code_expires_at TIMESTAMP,
    authorization_code_metadata TEXT,
    access_token_value LONGTEXT,
    access_token_issued_at TIMESTAMP,
    access_token_expires_at TIMESTAMP,
    access_token_metadata TEXT,
    access_token_type VARCHAR(255),
    access_token_scopes TEXT,
    refresh_token_value LONGTEXT,
    refresh_token_issued_at TIMESTAMP,
    refresh_token_expires_at TIMESTAMP,
    refresh_token_metadata TEXT,
    oidc_id_token_value LONGTEXT,
    oidc_id_token_issued_at TIMESTAMP,
    oidc_id_token_expires_at TIMESTAMP,
    oidc_id_token_metadata TEXT,
    oidc_id_token_claims TEXT,
    user_code_value LONGTEXT,
    user_code_issued_at TIMESTAMP,
    user_code_expires_at TIMESTAMP,
    user_code_metadata LONGTEXT,
    device_code_value LONGTEXT,
    device_code_issued_at TIMESTAMP,
    device_code_expires_at TIMESTAMP,
    device_code_metadata LONGTEXT,
    PRIMARY KEY (id)
);

-- Índices para mejorar el rendimiento de las consultas
CREATE INDEX IF NOT EXISTS idx_oauth2_registered_client_client_id ON oauth2_registered_client (client_id);
CREATE INDEX IF NOT EXISTS idx_oauth2_authorization_registered_client_id ON oauth2_authorization (registered_client_id);
CREATE INDEX IF NOT EXISTS idx_oauth2_authorization_principal_name ON oauth2_authorization (principal_name);

-- H2 no admite la sintaxis (column_name(length)) para crear índices en columnas LONGTEXT/TEXT
-- Estos índices se crean sin especificar la longitud
CREATE INDEX IF NOT EXISTS idx_oauth2_authorization_authorization_code_value ON oauth2_authorization (authorization_code_value);
CREATE INDEX IF NOT EXISTS idx_oauth2_authorization_access_token_value ON oauth2_authorization (access_token_value);
CREATE INDEX IF NOT EXISTS idx_oauth2_authorization_refresh_token_value ON oauth2_authorization (refresh_token_value);
CREATE INDEX IF NOT EXISTS idx_oauth2_authorization_user_code_value ON oauth2_authorization (user_code_value);
CREATE INDEX IF NOT EXISTS idx_oauth2_authorization_device_code_value ON oauth2_authorization (device_code_value);