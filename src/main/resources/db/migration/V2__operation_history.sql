CREATE TABLE identity_operation (
    identity_id BYTEA NOT NULL,
    sequence NUMERIC(20, 0) NOT NULL,
    operation_type SMALLINT NOT NULL,
    canonical_operation_bytes BYTEA NOT NULL,
    resulting_state_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (identity_id, sequence),
    CONSTRAINT ck_operation_identity_length CHECK (octet_length(identity_id) = 32),
    CONSTRAINT ck_operation_state_hash_length CHECK (octet_length(resulting_state_hash) = 34),
    CONSTRAINT ck_operation_sequence_positive CHECK (sequence >= 1),
    CONSTRAINT ck_operation_type CHECK (operation_type BETWEEN 1 AND 5),
    CONSTRAINT uq_operation_bytes UNIQUE (canonical_operation_bytes),
    CONSTRAINT fk_operation_resulting_state
      FOREIGN KEY (resulting_state_hash) REFERENCES identity_state(state_hash)
);

CREATE INDEX ix_identity_operation_state_hash
    ON identity_operation (resulting_state_hash);
