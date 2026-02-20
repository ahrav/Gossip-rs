#!/usr/bin/env bash
# Mutation tests for ShardFencing.tla
# Each test mutates a copy of the spec, runs TLC, and checks for expected outcome.

set -uo pipefail

SPEC_DIR="/Users/ahrav/Projects/Gossip-rs/specs/coordination"
TOOLS_JAR="/Users/ahrav/Projects/Gossip-rs/specs/tla2tools.jar"
BASE_SPEC="$SPEC_DIR/ShardFencing.tla"
BASE_CFG="$SPEC_DIR/ShardFencing_dev.cfg"

TLC_CMD="java -XX:+UseParallelGC -Xmx2g -cp $TOOLS_JAR tlc2.TLC -workers 1 -deadlock -terse -cleanup"

PASS_COUNT=0
FAIL_COUNT=0
RESULTS=()

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
    $TLC_CMD -config "$mut_cfg" "$mut_spec" > "$outfile" 2>&1 || exit_code=$?

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
    rm -f "$SPEC_DIR"/ShardFencing_mut${mut_num}_TTrace_*.tla 2>/dev/null || true
}

create_spec() {
    local mut_num="$1"
    sed "s/---- MODULE ShardFencing ----/---- MODULE ShardFencing_mut${mut_num} ----/" \
        "$BASE_SPEC" > "$SPEC_DIR/ShardFencing_mut${mut_num}.tla"
}

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
