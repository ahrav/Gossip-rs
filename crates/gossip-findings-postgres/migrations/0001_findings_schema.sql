-- 0001_findings_schema
--
-- Initial PostgreSQL schema for the findings persistence backend.
--
-- The durable write-path model is intentionally normalized:
--   findings      : stable identity (policy-independent)
--   occurrences   : version + span identity (policy-independent)
--   observations  : policy-scoped detection/provenance
--
-- Policy-specific state must live in observations, not occurrences.

CREATE TABLE findings (
    tenant_id        BYTEA NOT NULL,
    finding_id       BYTEA NOT NULL,
    stable_item_id   BYTEA NOT NULL,
    rule_fingerprint BYTEA NOT NULL,
    secret_hash      BYTEA NOT NULL,

    CONSTRAINT findings_pk PRIMARY KEY (tenant_id, finding_id),
    CONSTRAINT findings_tenant_id_len_ck
        CHECK (octet_length(tenant_id) = 32),
    CONSTRAINT findings_finding_id_len_ck
        CHECK (octet_length(finding_id) = 32),
    CONSTRAINT findings_stable_item_id_len_ck
        CHECK (octet_length(stable_item_id) = 32),
    CONSTRAINT findings_rule_fingerprint_len_ck
        CHECK (octet_length(rule_fingerprint) = 32),
    CONSTRAINT findings_secret_hash_len_ck
        CHECK (octet_length(secret_hash) = 32),
    CONSTRAINT findings_natural_unique UNIQUE (
        tenant_id,
        stable_item_id,
        rule_fingerprint,
        secret_hash
    )
);

CREATE TABLE occurrences (
    tenant_id         BYTEA  NOT NULL,
    occurrence_id     BYTEA  NOT NULL,
    finding_id        BYTEA  NOT NULL,
    object_version_id BYTEA  NOT NULL,
    byte_offset       BIGINT NOT NULL,
    byte_length       BIGINT NOT NULL,

    CONSTRAINT occurrences_pk PRIMARY KEY (tenant_id, occurrence_id),
    CONSTRAINT occurrences_tenant_id_len_ck
        CHECK (octet_length(tenant_id) = 32),
    CONSTRAINT occurrences_occurrence_id_len_ck
        CHECK (octet_length(occurrence_id) = 32),
    CONSTRAINT occurrences_finding_id_len_ck
        CHECK (octet_length(finding_id) = 32),
    CONSTRAINT occurrences_object_version_id_len_ck
        CHECK (octet_length(object_version_id) = 32),
    CONSTRAINT occurrences_byte_offset_nonnegative_ck
        CHECK (byte_offset >= 0),
    CONSTRAINT occurrences_byte_length_positive_ck
        CHECK (byte_length > 0),
    CONSTRAINT occurrences_finding_fk
        FOREIGN KEY (tenant_id, finding_id)
        REFERENCES findings (tenant_id, finding_id)
        ON DELETE CASCADE,
    CONSTRAINT occurrences_natural_unique UNIQUE (
        tenant_id,
        finding_id,
        object_version_id,
        byte_offset,
        byte_length
    )
);

CREATE TABLE observations (
    tenant_id        BYTEA  NOT NULL,
    observation_id   BYTEA  NOT NULL,
    occurrence_id    BYTEA  NOT NULL,
    policy_hash      BYTEA  NOT NULL,
    ovid_hash        BYTEA  NOT NULL,
    run_id           BIGINT NOT NULL,
    shard_id         BIGINT NOT NULL,
    fence_epoch      BIGINT NOT NULL,
    seen_at          BIGINT NOT NULL,
    location_display TEXT,
    location_url     TEXT,

    CONSTRAINT observations_pk PRIMARY KEY (tenant_id, observation_id),
    CONSTRAINT observations_tenant_id_len_ck
        CHECK (octet_length(tenant_id) = 32),
    CONSTRAINT observations_observation_id_len_ck
        CHECK (octet_length(observation_id) = 32),
    CONSTRAINT observations_occurrence_id_len_ck
        CHECK (octet_length(occurrence_id) = 32),
    CONSTRAINT observations_policy_hash_len_ck
        CHECK (octet_length(policy_hash) = 32),
    CONSTRAINT observations_ovid_hash_len_ck
        CHECK (octet_length(ovid_hash) = 32),
    CONSTRAINT observations_fence_epoch_nonnegative_ck
        CHECK (fence_epoch >= 0),
    CONSTRAINT observations_seen_at_nonnegative_ck
        CHECK (seen_at >= 0),
    CONSTRAINT observations_occurrence_fk
        FOREIGN KEY (tenant_id, occurrence_id)
        REFERENCES occurrences (tenant_id, occurrence_id)
        ON DELETE CASCADE,
    CONSTRAINT observations_natural_unique UNIQUE (
        tenant_id,
        policy_hash,
        occurrence_id
    ),
    CONSTRAINT observations_location_display_ck
        CHECK (
            location_display IS NULL
            OR octet_length(location_display) BETWEEN 1 AND 4096
        ),
    CONSTRAINT observations_location_url_ck
        CHECK (
            location_url IS NULL
            OR octet_length(location_url) BETWEEN 1 AND 4096
        )
);

-- Tenant-filtered lookup paths.
CREATE INDEX findings_tenant_secret_hash_idx
    ON findings (tenant_id, secret_hash, finding_id);

CREATE INDEX findings_tenant_stable_item_id_idx
    ON findings (tenant_id, stable_item_id, finding_id);

CREATE INDEX occurrences_tenant_finding_id_idx
    ON occurrences (tenant_id, finding_id, occurrence_id);

CREATE INDEX occurrences_tenant_object_version_id_idx
    ON occurrences (tenant_id, object_version_id, occurrence_id);

-- Latest-seen queries and policy-filtered browsing live on observations.
CREATE INDEX observations_tenant_seen_at_idx
    ON observations (tenant_id, seen_at DESC, observation_id);

CREATE INDEX observations_tenant_policy_seen_at_idx
    ON observations (tenant_id, policy_hash, seen_at DESC, observation_id);

CREATE INDEX observations_tenant_occurrence_id_idx
    ON observations (tenant_id, occurrence_id, observation_id);

CREATE INDEX observations_tenant_ovid_hash_idx
    ON observations (tenant_id, ovid_hash, observation_id);

CREATE INDEX observations_tenant_run_shard_idx
    ON observations (tenant_id, run_id, shard_id, observation_id);
