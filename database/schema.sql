-- schema.sql
-- 2026 Joey Manani & Anchorfish Team
-- Run by Postgres the first time the container starts with an empty volume

CREATE TABLE users (
    id            integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username      varchar(32)  NOT NULL UNIQUE,                     -- stored lowercase
    password_hash varchar(255) NOT NULL,
    role          varchar(16)  NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    created_at    timestamp    NOT NULL DEFAULT now()
);

CREATE TABLE checks ( -- another benefit is tracking this gives us more training data to hone in over time!!!
    id          integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id     integer       NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    url         varchar(2048) NOT NULL,
    probability double precision NOT NULL CHECK (probability >= 0 AND probability <= 1),
    label       varchar(16)   NOT NULL CHECK (label IN ('phishing', 'legitimate')),
    model_name  varchar(64)   NOT NULL,
    created_at  timestamp     NOT NULL DEFAULT now()
);

CREATE INDEX checks_user_newest ON checks (user_id, created_at);    -- history is always "my checks, newest first"
