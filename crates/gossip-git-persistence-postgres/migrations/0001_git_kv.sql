-- 0001_git_kv
--
-- Initial PostgreSQL schema for the Git runtime key/value backend.
--
-- The scanner runtime owns the encoding of both keys and values. PostgreSQL
-- stores them as opaque BYTEA payloads and provides:
--   * exact-key primary-key lookups for watermarks, seen bitmaps, and
--     mid-scan checkpoints;
--   * bounded key/value sizes to catch accidental misuse of this table;
--   * no secondary indexes because all access is by exact primary key.

CREATE TABLE git_kv (
    key   BYTEA NOT NULL,
    value BYTEA NOT NULL,

    CONSTRAINT git_kv_pk PRIMARY KEY (key),
    CONSTRAINT git_kv_key_size_ck
        CHECK (octet_length(key) <= 256),
    CONSTRAINT git_kv_value_size_ck
        CHECK (octet_length(value) <= 16777216)
);
