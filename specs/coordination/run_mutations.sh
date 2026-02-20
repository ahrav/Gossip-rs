#!/usr/bin/env bash
# =========================================================================
# Mutation Test Suite for ShardFencing.tla
# =========================================================================
#
# Mutation testing validates that selected safety invariants and temporal
# properties in the TLA+ specification are *necessary* — that is, for each
# tested guard, removing or weakening it causes TLC to find a counterexample.
# Without this, an invariant could be vacuously true (never exercised) or
# redundant, and we would not know. Mutations 1-6 cover: ZombieRejection,
# TerminalUnleased, SplitAtomicity, TerminalIrreversibility, and
# CursorMonotonicity. The non-vacuity checks (mutations 7-8) complement this
# by confirming that temporal properties (reachability and liveness) are
# satisfiable under the LiveSpec fairness assumptions.
#
# Methodology (per mutation):
#   1. create_spec  — Copy the base spec, renaming the MODULE header so TLC
#                     treats it as an independent module.
#   2. create_cfg   — Copy the dev config (or write a custom one when the
#                     mutation needs different constants or properties).
#   3. sed mutation  — Apply a targeted text substitution that introduces a
#                     single deliberate defect (e.g., removing a guard,
#                     swapping assignments, weakening a precondition).
#   4. run_mutation — Invoke TLC on the mutated spec and assert the expected
#                     outcome: violation for safety mutations, clean pass
#                     for non-vacuity checks.
#
# Prerequisites:
#   - Java 11+ on PATH (for TLC)
#   - tla2tools.jar at $TOOLS_JAR (TLC model checker)
#
# Usage:
#   bash specs/coordination/run_mutations.sh
#
# Exit behavior:
#   Exits 0 if all mutations produce the expected outcome, 1 otherwise.
#   All temporary files (mutated specs, configs, TLC output, trace files)
#   are cleaned up after each mutation regardless of outcome.
# =========================================================================

# -u: treat unset variables as errors; -o pipefail: propagate pipe failures.
# Note: -e is intentionally omitted because TLC exits non-zero on invariant
# violations, which is the *expected* outcome for safety mutations.
set -uo pipefail

# -- Paths --
SPEC_DIR="/Users/ahrav/Projects/Gossip-rs/specs/coordination"
TOOLS_JAR="/Users/ahrav/Projects/Gossip-rs/specs/tla2tools.jar"
BASE_SPEC="$SPEC_DIR/ShardFencing.tla"
BASE_CFG="$SPEC_DIR/ShardFencing_dev.cfg"

# TLC flags:
#   -workers 1   Deterministic single-threaded execution for reproducible results.
#   -deadlock     Disable deadlock checking (TLC default checks for deadlock;
#                 disabled here because bounded models naturally deadlock when
#                 all bounds are exhausted).
#   -terse        Suppress progress output; only print errors and summaries.
#   -cleanup      Remove TLC's working directories after each run.
TLC_CMD="java -XX:+UseParallelGC -Xmx2g -cp $TOOLS_JAR tlc2.TLC -workers 1 -deadlock -terse -cleanup"

# -- Aggregate results --
PASS_COUNT=0
FAIL_COUNT=0
RESULTS=()

# run_mutation <num> <description> <expect_violation: "yes"|"no">
#
# Runs TLC on a previously prepared mutated spec and checks the outcome.
# When expect_violation="yes", PASS means TLC found an invariant/property
# violation (confirming the mutated guard was necessary for correctness).
# When expect_violation="no", PASS means TLC found no errors (confirming
# the property is satisfiable, i.e., non-vacuous).
#
# Side effects: increments PASS_COUNT or FAIL_COUNT, appends to RESULTS[],
# and cleans up the mutated spec, config, TLC output, and any trace files.
run_mutation() {
    local mut_num="$1"
    local description="$2"
    local expect_violation="$3"
    local mut_spec="$SPEC_DIR/ShardFencing_mut${mut_num}.tla"
    local mut_cfg="$SPEC_DIR/ShardFencing_mut${mut_num}.cfg"

    echo ""
    echo "================================================================"
    echo "  Mutation $mut_num: $description"
    echo "  Expected violation: $expect_violation"
    echo "================================================================"

    local exit_code=0
    local outfile="/tmp/tlc_mut${mut_num}.out"
    local metadir="/tmp/tlc_mut${mut_num}"
    $TLC_CMD -metadir "$metadir" -config "$mut_cfg" "$mut_spec" > "$outfile" 2>&1 || exit_code=$?

    tail -20 "$outfile"

    local result=""
    if [ "$expect_violation" = "yes" ]; then
        if [ "$exit_code" -ne 0 ] || grep -q "Error:" "$outfile" 2>/dev/null; then
            result="PASS"
            local violated
            violated=$(grep -oE "Invariant [^ ]+ is violated|Property [^ ]+ is violated" "$outfile" 2>/dev/null | head -1)
            echo "  >>> PASS (exit=$exit_code): violation found. $violated"
        else
            result="FAIL"
            echo "  >>> FAIL (exit=$exit_code): NO violation found"
        fi
    else
        if [ "$exit_code" -eq 0 ] && ! grep -q "Error:" "$outfile" 2>/dev/null; then
            result="PASS"
            echo "  >>> PASS (exit=$exit_code): no violation, as expected"
        else
            result="FAIL"
            local violated
            violated=$(grep -oE "Invariant [^ ]+ is violated|Property [^ ]+ is violated" "$outfile" 2>/dev/null | head -1)
            echo "  >>> FAIL (exit=$exit_code): unexpected violation. $violated"
        fi
    fi

    [ "$result" = "PASS" ] && PASS_COUNT=$((PASS_COUNT + 1)) || FAIL_COUNT=$((FAIL_COUNT + 1))
    RESULTS+=("Mutation $mut_num [$result]: $description")

    rm -f "$mut_spec" "$mut_cfg" "$outfile"
    rm -rf "$metadir"
    rm -f "$SPEC_DIR"/ShardFencing_mut${mut_num}_TTrace_*.tla 2>/dev/null || true
}

# create_spec <num>
#
# Copies the base spec into a mutation-specific file, renaming the TLA+
# MODULE header. TLC requires the module name to match the filename, so
# the rename is necessary for the mutated copy to be loadable.
create_spec() {
    local mut_num="$1"
    sed "s/---- MODULE ShardFencing ----/---- MODULE ShardFencing_mut${mut_num} ----/" \
        "$BASE_SPEC" > "$SPEC_DIR/ShardFencing_mut${mut_num}.tla"
}

# create_cfg <num> <custom_cfg_text>
#
# Creates the TLC config for a mutation. If custom_cfg_text is empty, the
# base dev config (ShardFencing_dev.cfg) is copied as-is. A non-empty
# argument writes a fully custom config — used when a mutation needs
# different constants (e.g., larger MaxEpoch) or checks different
# properties (e.g., LiveSpec with liveness temporal formulas).
create_cfg() {
    local mut_num="$1"
    local custom_cfg="$2"
    if [ -z "$custom_cfg" ]; then
        cp "$BASE_CFG" "$SPEC_DIR/ShardFencing_mut${mut_num}.cfg"
    else
        printf '%s\n' "$custom_cfg" > "$SPEC_DIR/ShardFencing_mut${mut_num}.cfg"
    fi
}

echo "========================================"
echo "  ShardFencing Mutation Test Suite"
echo "  $(date)"
echo "========================================"

# =========================================================================
# Mutations 1-6: Safety invariant necessity
#
# Each mutation removes or weakens a single guard in one action and expects
# TLC to find a violation of the targeted invariant or action property.
# If TLC does NOT find a violation, the guard was unnecessary (or the
# invariant is too weak), which is itself a specification bug.
# =========================================================================

# ---------------------------------------------------------------
# Mutation 1: Remove worker_epoch cache from Acquire
#   Worker acquires shard but doesn't cache the new epoch.
#   Expected: ZombieRejection violation
# ---------------------------------------------------------------
create_spec 1
create_cfg 1 ""
sed -i '' '/^Acquire(w, s) ==/,/UNCHANGED timeVars/ {
    s|/\\ worker_epoch. = \[worker_epoch EXCEPT !\[w\]\[s\] = newEpoch\]|/\\ UNCHANGED workerVars  \\\* MUTATED: worker does not cache epoch|
}' "$SPEC_DIR/ShardFencing_mut1.tla"
run_mutation 1 "Remove worker_epoch cache from Acquire (zombie)" "yes"

# ---------------------------------------------------------------
# Mutation 2: Remove status[s] = "Active" from Acquire
#   Allows acquiring Done/Split shards.
#   Expected: TerminalUnleased violation
# ---------------------------------------------------------------
create_spec 2
create_cfg 2 ""
sed -i '' '/^Acquire(w, s) ==/,/UNCHANGED ghostVars/ {
    s|/\\ status\[s\] = "Active"|/\\ TRUE  \\\* MUTATED: removed Active check|
}' "$SPEC_DIR/ShardFencing_mut2.tla"
run_mutation 2 "Remove status=Active check from Acquire" "yes"

# ---------------------------------------------------------------
# Mutation 3: Don't clear owner in Complete
#   Done shard retains owner, violating TerminalUnleased.
#   Expected: TerminalUnleased violation
# ---------------------------------------------------------------
create_spec 3
create_cfg 3 ""
sed -i '' '/^Complete(w, s) ==/,/UNCHANGED timeVars/ {
    s|/\\ owner. = \[owner EXCEPT !\[s\] = none\]|/\\ UNCHANGED owner  \\\* MUTATED: owner not cleared|
}' "$SPEC_DIR/ShardFencing_mut3.tla"
run_mutation 3 "Don't clear owner in Complete (terminal leased)" "yes"

# ---------------------------------------------------------------
# Mutation 4: Don't set children to Active in SplitReplace
#   Children remain NotCreated while parent is Split.
#   Expected: SplitAtomicity violation
# ---------------------------------------------------------------
create_spec 4
create_cfg 4 ""
sed -i '' '/^SplitReplace(w, s) ==/,/UNCHANGED timeVars/ {
    s|ELSE IF s2 \\in children THEN "Active"|ELSE IF s2 \\in children THEN "NotCreated"  \\\* MUTATED|
}' "$SPEC_DIR/ShardFencing_mut4.tla"
run_mutation 4 "Don't activate children in SplitReplace" "yes"

# ---------------------------------------------------------------
# Mutation 5: Allow Done -> Active in Unpark
#   Uses MaxEpoch=3 so Unpark guard (epoch < MaxEpoch) is satisfiable
#   after a shard reaches Done (which requires 1 Acquire, epoch=2).
#   Expected: TerminalIrreversibility (action property) violation
# ---------------------------------------------------------------
create_spec 5
create_cfg 5 "$(cat <<'LCFG'
SPECIFICATION SafetySpec

CONSTANT parent = parent
CONSTANT child1 = child1
CONSTANT child2 = child2
CONSTANT none = none

CONSTANT Workers = {w1, w2}
CONSTANT AllShards = {parent, child1, child2}
CONSTANT MaxEpoch = 3
CONSTANT MaxCursor = 2
CONSTANT MaxTime = 5
CONSTANT LeaseDuration = 2

SYMMETRY WorkerSymmetry

INVARIANT TypeOK
INVARIANT MutualExclusion
INVARIANT ZombieRejection
INVARIANT SplitAtomicity
INVARIANT ChildImpliesParentSplit
INVARIANT TerminalUnleased
INVARIANT FenceEpochSanity
INVARIANT CursorMonotonicity

PROPERTY AlwaysFenceMonotonicity
PROPERTY AlwaysTerminalIrreversibility
PROPERTY AlwaysCursorNonRegression
LCFG
)"
sed -i '' '/^Unpark(s) ==/,/UNCHANGED timeVars/ {
    s|/\\ status\[s\] = "Parked"|/\\ status[s] \\in {"Parked", "Done"}  \\\* MUTATED: allow Done unpark|
}' "$SPEC_DIR/ShardFencing_mut5.tla"
run_mutation 5 "Allow Done->Active in Unpark (terminal irreversibility)" "yes"

# ---------------------------------------------------------------
# Mutation 6: Swap cursor/prev_cursor in Checkpoint
#   Cursor stays, prev_cursor jumps ahead => CursorMonotonicity violated.
#   Expected: CursorMonotonicity violation
# ---------------------------------------------------------------
create_spec 6
create_cfg 6 ""
sed -i '' '/^Checkpoint(w, s) ==/,/UNCHANGED timeVars/ {
    s|/\\ cursor. = \[cursor EXCEPT !\[s\] = newCursor\]|/\\ cursor'\'' = [cursor EXCEPT ![s] = cursor[s]]  \\\* MUTATED: no advance|
    s|/\\ prev_cursor. = \[prev_cursor EXCEPT !\[s\] = cursor\[s\]\]|/\\ prev_cursor'\'' = [prev_cursor EXCEPT ![s] = newCursor]  \\\* MUTATED: prev jumps|
}' "$SPEC_DIR/ShardFencing_mut6.tla"
run_mutation 6 "Swap cursor/prev_cursor in Checkpoint (monotonicity)" "yes"

# =========================================================================
# Mutations 7-8: Non-vacuity (liveness satisfiability)
#
# These are NOT mutations in the traditional sense — the spec is unmodified.
# They verify that temporal properties are satisfiable under LiveSpec (which
# applies weak fairness to Acquire and omits the Tick action to prevent time
# from starving protocol progress). A PASS here means the property is
# non-vacuous: TLC found at least one behavior where the temporal formula
# is satisfied.
# =========================================================================

# ---------------------------------------------------------------
# Mutation 7 (Non-vacuity): EventuallyAcquired under LiveSpec
#   Should PASS.
# ---------------------------------------------------------------
create_spec 7
create_cfg 7 "$(cat <<'LCFG'
SPECIFICATION LiveSpec

CONSTANT parent = parent
CONSTANT child1 = child1
CONSTANT child2 = child2
CONSTANT none = none

CONSTANT Workers = {w1, w2}
CONSTANT AllShards = {parent, child1, child2}
CONSTANT MaxEpoch = 2
CONSTANT MaxCursor = 2
CONSTANT MaxTime = 4
CONSTANT LeaseDuration = 2

SYMMETRY WorkerSymmetry

PROPERTY EventuallyAcquired
LCFG
)"
run_mutation 7 "Non-vacuity: EventuallyAcquired with LiveSpec" "no"

# ---------------------------------------------------------------
# Mutation 8 (Non-vacuity): Liveness (INV-L01) under LiveSpec
#   Should PASS.
# ---------------------------------------------------------------
create_spec 8
create_cfg 8 "$(cat <<'LCFG'
SPECIFICATION LiveSpec

CONSTANT parent = parent
CONSTANT child1 = child1
CONSTANT child2 = child2
CONSTANT none = none

CONSTANT Workers = {w1, w2}
CONSTANT AllShards = {parent, child1, child2}
CONSTANT MaxEpoch = 2
CONSTANT MaxCursor = 2
CONSTANT MaxTime = 4
CONSTANT LeaseDuration = 2

SYMMETRY WorkerSymmetry

PROPERTY Liveness
LCFG
)"
run_mutation 8 "Non-vacuity: Liveness (INV-L01) with LiveSpec" "no"

# ---------------------------------------------------------------
# Summary
# ---------------------------------------------------------------
echo ""
echo "========================================"
echo "  MUTATION TEST SUMMARY"
echo "========================================"
for r in "${RESULTS[@]}"; do
    echo "  $r"
done
echo ""
echo "  Total: $((PASS_COUNT + FAIL_COUNT))  Passed: $PASS_COUNT  Failed: $FAIL_COUNT"
echo "========================================"

[ "$FAIL_COUNT" -gt 0 ] && exit 1 || exit 0
