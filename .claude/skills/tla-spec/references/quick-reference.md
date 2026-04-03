## Common Mistakes Catalog

Mistakes ordered by frequency and severity. Each cites the research finding
that identifies it.

| # | Mistake | Consequence | Fix | Finding |
|---|---------|------------|-----|---------|
| 1 | Missing UNCHANGED for a variable | Variable is unconstrained; TLC explores all possible values | Add explicit UNCHANGED for every unmodified variable in every action | [T1, M5] |
| 2 | Using `[][Next]` instead of `[][Next]_vars` | Stuttering forbidden; breaks compositional refinement | Always use `_vars` subscript | [T1, M2] |
| 3 | CONSTRAINT in liveness config | **Unsound**: may hide liveness violations | Remove CONSTRAINT for all liveness checking | [T1, M11] |
| 4 | SYMMETRY in liveness config | **Dangerous**: may miss liveness counterexamples | Remove SYMMETRY for liveness checking | [T1, M11] |
| 5 | Fairness on environment actions | Over-constrains the model; hides real liveness bugs | Never apply fairness to actions representing external/adversarial behavior | [T2, M4] |
| 6 | Starting with SF instead of WF | Stronger assumption than needed; masks bugs | Start with WF, upgrade to SF only for intermittently disabled actions | [T2, M4, P3.3] |
| 7 | Fairness on composite Next only | Does not guarantee which sub-action executes | Apply fairness to individual actions, not Next | [T2, M4] |
| 8 | No TypeOK invariant | Domain errors caught late or not at all | Always define and check TypeOK first | [T1, M9] |
| 9 | Skipping deadlock check before liveness | Deadlocked spec can vacuously satisfy liveness | Check deadlock-freedom after safety, before liveness | [T1, P4.4.F6] |
| 10 | Modeling clocks for timeouts | Unnecessary complexity; wrong abstraction | Model timeouts as always-enabled nondeterministic actions | [T2, M14] |
| 11 | vars tuple missing a variable | That variable can change arbitrarily in stutter steps | Always verify vars contains ALL declared VARIABLES | [T1, M2, M5] |
| 12 | Using Nat instead of bounded range | TLC cannot enumerate infinite sets | Use `0..MaxBound` for model checking | [T1, M9, M12] |

---

## Quick Reference: Specification Template

Copy-paste starting point for a new distributed protocol specification:

```tla
---- MODULE ProtocolName ----
EXTENDS Integers, Sequences, FiniteSets, TLC

\*-------------------------------------------------------------
\* Constants
\*-------------------------------------------------------------
CONSTANTS
    Node,           \* Set of nodes (symmetry set for TLC)
    None            \* Sentinel: model value in TLC config

ASSUME NoneAssumption == None \notin Node

\*-------------------------------------------------------------
\* Variables
\*-------------------------------------------------------------
VARIABLES
    \* @type: NODE -> Str;
    state,          \* Per-node state
    \* @type: Set(MSG);
    msgs            \* Messages in flight (set model)

vars == <<state, msgs>>

\*-------------------------------------------------------------
\* Message constructors
\*-------------------------------------------------------------
Message == [type: {"request", "response"}, from: Node, to: Node]

\*-------------------------------------------------------------
\* Type invariant [T1, M9]
\*-------------------------------------------------------------
TypeOK ==
    /\ state \in [Node -> {"idle", "active", "done"}]
    /\ msgs \subseteq Message

\*-------------------------------------------------------------
\* Initial state
\*-------------------------------------------------------------
Init ==
    /\ state = [n \in Node |-> "idle"]
    /\ msgs = {}

\*-------------------------------------------------------------
\* Actions [T1, M5 — every action has explicit UNCHANGED]
\*-------------------------------------------------------------
SendRequest(sender, receiver) ==
    /\ state[sender] = "idle"
    /\ state' = [state EXCEPT ![sender] = "active"]
    /\ msgs' = msgs \cup {[type |-> "request",
                            from |-> sender,
                            to   |-> receiver]}

HandleRequest(n) ==
    /\ \E msg \in msgs :
        /\ msg.type = "request"
        /\ msg.to = n
        /\ state' = [state EXCEPT ![n] = "done"]
        /\ msgs' = (msgs \ {msg}) \cup
                    {[type |-> "response",
                      from |-> n,
                      to   |-> msg.from]}

HandleResponse(n) ==
    /\ \E msg \in msgs :
        /\ msg.type = "response"
        /\ msg.to = n
        /\ state' = [state EXCEPT ![n] = "done"]
        /\ msgs' = msgs \ {msg}

\*-------------------------------------------------------------
\* Next-state relation
\*-------------------------------------------------------------
Next ==
    \E n1, n2 \in Node :
        \/ SendRequest(n1, n2)
        \/ HandleRequest(n1)
        \/ HandleResponse(n1)

\*-------------------------------------------------------------
\* Fairness [T2, M4 — WF first, SF only if needed]
\*-------------------------------------------------------------
Fairness ==
    \A n \in Node :
        /\ WF_vars(HandleRequest(n))
        /\ WF_vars(HandleResponse(n))
    \* NO fairness on SendRequest — it is an environment/client action

\*-------------------------------------------------------------
\* Specification
\*-------------------------------------------------------------
\* Safety-only (check safety first):
SafetySpec == Init /\ [][Next]_vars

\* Full specification (add fairness for liveness):
Spec == Init /\ [][Next]_vars /\ Fairness

\*-------------------------------------------------------------
\* Safety properties
\*-------------------------------------------------------------
Safety1 == \A n \in Node :
    state[n] = "done" => \E msg \in msgs \cup {} : TRUE  \* placeholder

\*-------------------------------------------------------------
\* Liveness properties [T1, M3]
\*-------------------------------------------------------------
\* Every active node eventually completes
Liveness1 == \A n \in Node :
    state[n] = "active" ~> state[n] = "done"

====
```

---

## Quick Reference: Decision Tables

### Fairness Selection [T2, M4, P3.3]

```
Is the action an environment/external action?
  YES → No fairness. Stop.
  NO  ↓
Is the action continuously enabled once enabled?
  YES → WF_vars(Action). Stop.
  NO  ↓
Is the action repeatedly enabled then disabled (intermittently)?
  YES → SF_vars(Action). Document why WF is insufficient.
  NO  ↓
Is the action enabled only once?
  → WF_vars(Action) suffices (same as continuously enabled case).
```

### Communication Model [T2, P3.4]

```
Does your property depend on message ordering?
  YES → Sequence model (per-link Seq). Stop.
  NO  ↓
Does your property depend on detecting duplicates?
  YES → Bag model. Stop.
  NO  ↓
Use Set model (simplest).
```

### TLC Config for Checking Phase [T1, M11, M12]

```
Phase: Safety development?
  → CONSTRAINT ok, SYMMETRY ok, INVARIANT

Phase: Final safety?
  → NO CONSTRAINT, SYMMETRY ok, INVARIANT

Phase: Liveness development?
  → NO CONSTRAINT, NO SYMMETRY, PROPERTY, -lncheck

Phase: Final liveness?
  → NO CONSTRAINT, NO SYMMETRY, PROPERTY, -lncheck final, -workers auto
```

---

## Evidence Traceability Matrix

Maps each section of this skill to the research findings that support it.

| Section | Research Findings | Tier | Confidence |
|---------|-------------------|------|------------|
| 1.1 Canonical Form | M1, P4.1.F1 | T1 | HIGH (with caveat: default, not law) |
| 1.2 Stuttering & UNCHANGED | M2, M5 | T1 | HIGH |
| 1.3 TypeOK | M9 | T1 | HIGH |
| 2.1 Abstraction Framework | P3.1, M8 | T2 | HIGH |
| 2.2 Distributed Patterns | P3.4, M14 | T2 | HIGH |
| 3.1 Safety Checklist | M9, M5, M11, M12 | T1 | HIGH |
| 3.2 Deadlock-Freedom Gate | P4.4.F6 | T1 | HIGH (adversarial correction) |
| 3.3 TLC Safety Config | M11, M12 | T1 | HIGH |
| 4.1 Liveness Methodology | M3, P3.2, P3.3 | T1 | HIGH |
| 4.2 TLC Soundness Matrix | M11, M12, P3.2 | T1 | HIGH |
| 5.1 Small Model Heuristics | M10, P4.4.F3 | T2 | MEDIUM (caveats on thresholds) |
| 5.2 TLC Config Guide | M11, M12 | T1 | HIGH |
| 5.3 Multi-Tool Awareness | P4.3.F6, P4.4.F2 | T3 | MEDIUM |
| 6.1 PlusCal | M16, P4.4.F1 | T3 | MEDIUM |

---

## Why Every Rule Exists [P4.4.F5]

> **[Adversarial correction P4.4.F5]**: A template-based approach risks
> users following rules by rote without understanding WHY. Every rule in
> this skill includes its rationale. If you find yourself following a rule
> without understanding it, stop and read the "Why" or "Rationale" column.
> Rote rule-following produces specifications that look correct but miss
> the point.

---

## References

1. Lamport, L. *Specifying Systems: The TLA+ Language and Tools for Hardware and Software Engineers*. Addison-Wesley, 2002. [Primary source for M1-M5, M8, M14]
2. Lamport, L. "The Temporal Logic of Actions." *ACM Transactions on Programming Languages and Systems*, 16(3):872-923, 1994. [M4: fairness definitions]
3. Yu, Y., Manolios, P., Lamport, L. "Model Checking TLA+ Specifications." *Correct Hardware Design and Verification Methods*, LNCS 1703, 1999. [M12: TLC implementation]
4. Newcombe, C., Rath, T., Zhang, F., Muehlfield, B., Ring, A., Kirkwood, B. "How Amazon Web Services Uses Formal Methods." *Communications of the ACM*, 58(4):66-73, 2015. [M10: small model sufficiency, industrial practice]
5. Lamport, L. "A PlusCal User's Manual." 2009. [M16: PlusCal]
6. TLC Model Checker Reference. https://lamport.azurewebsites.net/tla/current-tools.html [M11: TLC config options]
7. Ongaro, D., Ousterhout, J. "In Search of an Understandable Consensus Algorithm (Extended Version)." Stanford University, 2014. [Raft TLA+ specification as exemplar]
8. Lamport, L. "Paxos Made Simple." *ACM SIGACT News*, 32(4):18-25, 2001. [Protocol specification methodology]
9. Kuppe, M., Lamport, L., Ricketts, D. "The TLA+ Toolbox." *arXiv:1912.10633*, 2019. [TLC tooling and configuration]
10. Konnov, I., Kukovec, J., Tran, T.-H. "TLA+ Model Checking Made Symbolic." *Proceedings of the ACM on Programming Languages*, 3(OOPSLA), 2019. [Apalache: symbolic model checking for TLA+]

## Related Skills

- `/deep-research` — use before this skill when entering unfamiliar
  protocol territory; gather evidence before specifying
- `/dist-sys-auditor` — complementary: audits distributed systems
  implementation code; this skill audits the specification
- `/sim-review` — after specification passes, sim-review ensures
  the implementation maintains specification-level properties
- `/sim-scaffold` — generate simulation-testable code from spec decisions
