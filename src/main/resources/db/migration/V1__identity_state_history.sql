CREATE TABLE identity_state (
    state_hash BYTEA PRIMARY KEY,
    identity_id BYTEA NOT NULL,
    sequence NUMERIC(20, 0) NOT NULL,
    state_version SMALLINT NOT NULL,
    status SMALLINT NOT NULL,
    canonical_state_bytes BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT ck_identity_id_length CHECK (octet_length(identity_id) = 32),
    CONSTRAINT ck_state_hash_length CHECK (octet_length(state_hash) = 34),
    CONSTRAINT ck_sequence_positive CHECK (sequence >= 1),
    CONSTRAINT ck_state_version CHECK (state_version IN (1, 2)),
    CONSTRAINT ck_status CHECK (status IN (1, 2)),
    CONSTRAINT uq_identity_sequence UNIQUE (identity_id, sequence)
);

CREATE INDEX ix_identity_state_current
    ON identity_state (identity_id, sequence DESC);
