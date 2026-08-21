# Migrate from aictx v0.1

`ctxlane` uses a new application identity and new default storage paths. It never imports `aictx` data during normal startup. Migration is an explicit copy.

## Upgrade

Keep the old executable and data until the new installation works.

1. Preview the copy:

   ```bash
   ctxlane migrate aictx --dry-run
   ```

2. Run the migration:

   ```bash
   ctxlane migrate aictx
   ```

3. Check the result:

   ```bash
   ctxlane doctor
   ctxlane status
   ```

4. Test each account you use. Remove the old executable only after those checks pass.

There is no `aictx` executable or Cargo alias. Update scripts and shell configuration to call `ctxlane`.

## What is copied

Migration copies profiles, contexts, bindings, active state, and managed vendor state. It rewrites each managed profile state path to the new `ctxlane` location.

- Active and retired vendor-state directories are copied.
- Regular files ending in `.lock` are treated as runtime locks, skipped, and listed in the migration summary. Directories ending in `.lock` are copied normally.
- Safe owner-executable permissions are preserved for vendor scripts on Unix.
- Existing `keyring://aictx/...` and custom-service references are preserved exactly.
- Keyring secrets are not read, exported, copied, or printed.
- New profiles created by `ctxlane` use `keyring://ctxlane/...` references.

Legacy metadata, vendor state, and credential references are not changed or removed. Migration may create or normalize private advisory profile-lock files in the legacy state directory while it prevents concurrent profile changes.

## Custom roots

Without `--root`, `ctxlane` discovers the old and new platform application directories. Explicit roots are never guessed, so supply both paths:

```bash
ctxlane --root /absolute/new/root migrate aictx \
  --from-root /absolute/old/root \
  --dry-run

ctxlane --root /absolute/new/root migrate aictx \
  --from-root /absolute/old/root
```

Both paths must be absolute and must not overlap.

## Interrupted migration

Normal commands refuse to use a target while its migration journal exists. Recover with the same path selection used for the copy:

```bash
ctxlane migrate recover
```

For explicit roots:

```bash
ctxlane --root /absolute/new/root migrate recover \
  --from-root /absolute/old/root
```

Recovery behaves conservatively:

- A fully verified target is kept only after the legacy snapshot and the complete target are checked again.
- A committed partial target is renamed to a private sibling archive. The command prints every archive path and never deletes those archives automatically.
- Transaction-owned staging directories may be removed after their ownership marker is checked.
- Missing, changed, corrupt, or unowned data causes a refusal. The journal remains for inspection instead of guessing.

Migration and recovery are serialized with ordinary `ctxlane` startup. Files, journals, staged directories, and rename parents are synchronized where the platform supports directory syncing. The automated contract covers process interruption; keep a separate backup for hardware, filesystem, or power-loss failure.

## Start with an empty store

If the old default store exists but should not be copied, make that choice explicit:

```bash
ctxlane init --fresh
```

The guided Claude setup accepts the same choice:

```bash
ctxlane init --guided --fresh
```

`--fresh` does not remove the old store.

## Cleanup

Keep the old roots and any recovery archives until the migrated accounts and vendor logins have been verified. Delete them only through a deliberate operating-system action after review; `ctxlane` does not provide an automatic destructive cleanup command.
