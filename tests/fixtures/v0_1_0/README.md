# Frozen aictx v0.1.0 migration fixture

These files model metadata written by the immutable `v0.1.0` release at commit
`a6e44c0b61cca6a35841ee4ccd7bd3bcd0bc11a3`.

The fixture was derived with that tag's own `aictx` binary by running `init`,
`profile add`, `context add`, `bind`, and `use`. It was then made portable in
two mechanical ways:

- absolute roots became `{{LEGACY_ROOT}}` and `{{BINDING_PATH}}`;
- discovered vendor binary paths became the valid v0.1.0 defaults `claude` and
  `codex`.

The small vendor-state payloads are inert, hand-written files. They exercise
the v0.1.0 directory layout without calling Claude, Codex, or an OS keyring.

The integration test replaces only the two path placeholders. It does not use
the current serializers to create legacy metadata.

`with_state` exercises an active context, a directory binding, active and
retired vendor state, a regular runtime lock, a directory ending in `.lock`,
and an executable vendor hook. `missing_state` captures the v0.1.0 behavior
where an absent `state.toml` loads as the default mutable state. `malformed`
keeps account and keyring canaries on an invalid TOML line to verify that a
migration error never renders legacy metadata values.
