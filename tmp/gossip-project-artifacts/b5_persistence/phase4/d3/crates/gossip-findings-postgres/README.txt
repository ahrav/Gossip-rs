PostgreSQL findings persistence backend for the Phase V write/query plane.

Write order inside one SQL transaction:
1. findings
2. occurrences
3. observations

Observation replays merge metadata instead of duplicating rows.
