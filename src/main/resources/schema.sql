CREATE TABLE IF NOT EXISTS role (
    role_id VARCHAR(32) PRIMARY KEY,
    role_name VARCHAR(128) NOT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS "user" (
    user_id VARCHAR(64) PRIMARY KEY,
    first_name VARCHAR(128) NOT NULL,
    last_name VARCHAR(128) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role_id VARCHAR(32) NOT NULL REFERENCES role(role_id),
    status VARCHAR(32) NOT NULL DEFAULT 'Active',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
