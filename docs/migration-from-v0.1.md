# Migrate from aictx v0.1

`ctxlane` uses a new application identity and new default storage paths. It never imports `aictx` data during normal startup. Migration is an explicit copy.

## Upgrade

Keep the old executable and data until the new installation works.

1. If v0.1 was installed with Homebrew, update the renamed formula and install `ctxlane`:

   ```bash
   brew update
   brew migrate ctxlane
   HOMEBREW_NO_INSTALL_CLEANUP=1 brew upgrade ctxlane
   ```

   `brew migrate` changes the package name only. The no-cleanup setting retains the old v0.1 keg while you validate v0.2. Neither command migrates your local profiles or vendor state.

2. Preview the local data copy:

   ```bash
   ctxlane migrate aictx --dry-run
   ```

3. Run the migration:

   ```bash
   ctxlane migrate aictx
   ```

4. Check the result:

   Run each provider check that matches a migrated profile:

   ```bash
   ctxlane doctor --provider claude  # if you migrated Claude profiles
   ctxlane doctor --provider codex   # if you migrated Codex profiles
   ctxlane status
   ```

5. Test each account you use. Remove the old executable only after those checks pass.

The v0.2 package installs only `ctxlane`. It does not install an `aictx` compatibility executable or Cargo alias. If Homebrew retained the old v0.1 keg, that keg contains the old binary rather than a v0.2 shim. Update scripts and shell configuration to call `ctxlane`.

## What is copied

Migration copies profiles, contexts, bindings, active state, and managed vendor state. It rewrites each managed profile state path to the new `ctxlane` location.

- Active and retired vendor-state directories are copied.
- Regular files ending in `.lock` are treated as runtime locks, skipped, and listed in the migration summary. Directories ending in `.lock` are copied normally.
- Safe owner-executable permissions are preserved for vendor scripts on Unix.
- Existing `keyring://aictx/...` and custom-service references are preserved exactly.
- Keyring secrets are not read, exported, copied, or printed.
- New profiles created by `ctxlane` use `keyring://ctxlane/...` references.

Legacy metadata, vendor state, and credential references are not changed or removed. Migration may create or normalize private advisory profile-lock files in the legacy state directory while it prevents concurrent profile changes.

> **Shared credential:** A preserved legacy keyring reference still points to the same OS-keyring item from both tools. After migration, `ctxlane login`, `ctxlane logout`, or `ctxlane profile remove --delete-secret` can replace or delete the credential used by the old profile. Avoid those operations while you still depend on credential-level rollback, or be ready to log in again.

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
