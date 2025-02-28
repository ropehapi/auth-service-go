CREATE TABLE users
(
    id            BINARY(16) PRIMARY KEY,
    username      VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255)       NOT NULL
);