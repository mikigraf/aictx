# Frozen ctxlane v0.2 schema-v1 metadata

This fixture was authored against and frozen from the schema implemented at ctxlane commit
`af5dab575f687250115d5798fd6ef9c19402cf9f`, immediately before config schema
v2. It freezes every auth shape supported by that build, optional profile pins,
settings, binary overrides, contexts, a directory binding, and mutable state.

Tests replace `__ROOT__`, `__CLAUDE_BIN__`, `__CODEX_BIN__`, `__TOKEN__`, and
`__BINDING__` with platform-valid private absolute paths. Keep the fixture at
schema version 1 and preserve its field order.
