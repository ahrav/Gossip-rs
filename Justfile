# gossip-rs local development recipes
#
# Prerequisites: Docker Desktop running, `just` installed.
# Ports 2379 (etcd) and 5432 (postgres) must be free.

# List available recipes
default:
    @just --list

# ── Backend lifecycle ─────────────────────────────────────────────────

# Start etcd + postgres backends
up:
    docker compose up -d --wait

# Stop all backends
down:
    docker compose down

# Destroy all state and restart fresh
reset:
    docker compose down -v
    docker compose up -d --wait

# ── Database ──────────────────────────────────────────────────────────

# Apply embedded PostgreSQL migrations to both databases
migrate:
    cargo run -p dev-seed -- migrate

# ── Scan workflow ─────────────────────────────────────────────────────

# Submit a filesystem request for PATH (`single_file` or `directory_root`)
seed MODE PATH:
    cargo run -p dev-seed -- seed "{{MODE}}" "{{PATH}}"

# Run the distributed worker against local backends
run-worker PATH:
    GOSSIP_WORKER_MODE=connector \
    GOSSIP_WORKER_BACKEND=production \
    GOSSIP_WORKER_SOURCE=fs \
    GOSSIP_WORKER_PATH="{{PATH}}" \
    GOSSIP_ETCD_ENDPOINTS=http://127.0.0.1:2379 \
    GOSSIP_ETCD_NAMESPACE=/gossip/dev \
    GOSSIP_DONE_LEDGER_POSTGRES_DSN="postgresql://postgres:postgres@127.0.0.1:5432/done_ledger" \
    GOSSIP_FINDINGS_POSTGRES_DSN="postgresql://postgres:postgres@127.0.0.1:5432/findings" \
    GOSSIP_TENANT_ID=1111111111111111111111111111111111111111111111111111111111111111 \
    GOSSIP_RUN_ID=42 \
    GOSSIP_WORKER_ID=7 \
    GOSSIP_POLICY_HASH=2222222222222222222222222222222222222222222222222222222222222222 \
    GOSSIP_TENANT_SECRET_KEY=3333333333333333333333333333333333333333333333333333333333333333 \
    GOSSIP_STARTUP_SCHEMA_MODE=dev-auto-migrate \
    RUST_LOG=info \
    cargo run -p gossip-worker -- --mode=connector fs "{{PATH}}"

# Seed + run worker in one step (full distributed scan of PATH)
scan PATH: (seed "directory_root" PATH) (run-worker PATH)

# Show row counts from findings + done-ledger databases
inspect:
    cargo run -p dev-seed -- inspect
