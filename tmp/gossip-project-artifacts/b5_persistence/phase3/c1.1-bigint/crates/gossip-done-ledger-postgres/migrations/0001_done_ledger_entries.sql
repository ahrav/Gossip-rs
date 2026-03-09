-- 0001_done_ledger_entries
--
-- Initial PostgreSQL schema for the done-ledger MVP backend.
--
-- This migration intentionally stores the full DoneLedgerRecord contract.
-- It does NOT use NUMERIC(20,0): hot-path fields stay on native BIGINT.
--
-- Mapping rules:
--   * equality/grouping IDs (run_id, shard_id) are stored as raw BIGINT bit
--     patterns and reinterpreted at the Rust boundary;
--   * ordered counters/times (fence_epoch, started_at, finished_at,
--     bytes_scanned) are stored as non-negative BIGINT so SQL ordering matches
--     semantic ordering.

CREATE TABLE done_ledger_entries (
    tenant_id      BYTEA    NOT NULL CHECK (octet_length(tenant_id) = 32),
    policy_hash    BYTEA    NOT NULL CHECK (octet_length(policy_hash) = 32),
    ovid_hash      BYTEA    NOT NULL CHECK (octet_length(ovid_hash) = 32),

    status         SMALLINT NOT NULL CHECK (status IN (1, 2, 3, 10, 11)),

    -- Ordered / monotonic fields.
    bytes_scanned  BIGINT   NOT NULL CHECK (bytes_scanned >= 0),
    findings_count INTEGER  NOT NULL CHECK (findings_count >= 0),
    fence_epoch    BIGINT   NOT NULL CHECK (fence_epoch >= 0),
    started_at     BIGINT   NOT NULL CHECK (started_at >= 0),
    finished_at    BIGINT   NOT NULL CHECK (finished_at >= started_at),

    -- Equality / grouping identifiers. Signedness is irrelevant inside SQL for
    -- these fields because the backend uses only equality/grouping semantics.
    run_id         BIGINT   NOT NULL,
    shard_id       BIGINT   NOT NULL,

    -- Compatibility/generated convenience alias matching the earlier ticket
    -- wording. The authoritative contract field is finished_at.
    scanned_at     BIGINT GENERATED ALWAYS AS (finished_at) STORED,

    error_code     TEXT,

    CONSTRAINT done_ledger_entries_pk
        PRIMARY KEY (tenant_id, policy_hash, ovid_hash),

    CONSTRAINT done_ledger_entries_error_code_size_ck
        CHECK (error_code IS NULL OR octet_length(error_code) BETWEEN 1 AND 128),

    -- Enforce the DoneLedgerRecord invariants already defined in
    -- gossip-contracts::persistence::DoneLedgerRecord::validate().
    CONSTRAINT done_ledger_entries_status_shape_ck
        CHECK (
            (status = 10 AND findings_count = 0 AND error_code IS NULL)
            OR (status = 11 AND findings_count > 0 AND error_code IS NULL)
            OR (status IN (1, 2, 3) AND error_code IS NOT NULL)
        )
);

-- Hot operational scan/retention path: enumerate rows for one tenant+policy
-- ordered by newest completion first.
CREATE INDEX done_ledger_entries_tenant_policy_scanned_at_idx
    ON done_ledger_entries (tenant_id, policy_hash, scanned_at DESC, ovid_hash);

-- Debug / provenance lookup path: inspect rows written by a specific run+shard.
CREATE INDEX done_ledger_entries_run_shard_idx
    ON done_ledger_entries (run_id, shard_id, tenant_id, policy_hash, ovid_hash);
