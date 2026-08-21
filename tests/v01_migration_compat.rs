use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use aictx::{
    config::{AppPaths, MetadataStore, ensure_secure_directory},
    migration::MigrationPlan,
    model::{Name, ProfileId},
};
use tempfile::TempDir;

const LEGACY_KEYRING_REF: &str = concat!("keyring://ai", "ctx/claude-personal-frozen-v010");
const MISSING_STATE_KEYRING_REF: &str = concat!("keyring://ai", "ctx/claude-solo-frozen-v010");
const ACCOUNT_LEAK_CANARY: &str = "account-leak-canary-v010";
const KEYRING_LEAK_CANARY: &str = "keyring-leak-canary-v010";

#[derive(Clone, Copy)]
enum Snapshot {
    WithState,
    MissingState,
    Malformed,
}

impl Snapshot {
    const fn directory(self) -> &'static str {
        match self {
            Self::WithState => "with_state",
            Self::MissingState => "missing_state",
            Self::Malformed => "malformed",
        }
    }

    const fn has_state(self) -> bool {
        matches!(self, Self::WithState)
    }

    const fn vendor_files(self) -> &'static [&'static str] {
        match self {
            Self::WithState => &[
                "data/vendor-state/claude/personal/session.json",
                "data/vendor-state/claude/personal/cache.lock/manifest.json",
                "data/vendor-state/claude/personal.retired-v010/history.json",
                "data/vendor-state/codex/work/auth.json",
                "data/vendor-state/codex/work/session.lock",
                "data/vendor-state/codex/work/hooks/post-login",
            ],
            Self::MissingState => &["data/vendor-state/claude/solo/settings.json"],
            Self::Malformed => &[],
        }
    }
}

struct MaterializedFixture {
    _temporary: TempDir,
    legacy: AppPaths,
    target: AppPaths,
    binding_path: PathBuf,
    source_config: Vec<u8>,
    source_state: Option<Vec<u8>>,
}

impl MaterializedFixture {
    fn from_frozen(snapshot: Snapshot) -> Self {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let legacy_root = temporary.path().join("legacy-v0.1.0");
        let target_root = temporary.path().join("target-ctxlane");
        let binding_path = temporary.path().join("bound-project");
        let legacy = AppPaths::for_root(&legacy_root);
        let target = AppPaths::for_root(target_root);

        ensure_secure_directory(&binding_path)
            .unwrap_or_else(|error| panic!("create fixture binding path: {error}"));
        for directory in [
            &legacy.config_dir,
            &legacy.data_dir,
            &legacy.state_dir,
            &legacy.data_dir.join("vendor-state"),
            &legacy.state_dir.join("profile-locks"),
        ] {
            ensure_secure_directory(directory).unwrap_or_else(|error| {
                panic!(
                    "create frozen fixture directory {}: {error}",
                    directory.display()
                );
            });
        }

        let frozen_root = frozen_fixture_root().join(snapshot.directory());
        let template_path = frozen_root.join("config/config.toml.in");
        let template = fs::read_to_string(&template_path).unwrap_or_else(|error| {
            panic!(
                "read frozen config template {}: {error}",
                template_path.display()
            );
        });
        let config = instantiate_config(&template, &legacy_root, &binding_path);
        write_private(&legacy.config_file, config.as_bytes());

        let source_state = if snapshot.has_state() {
            let frozen_state = frozen_root.join("state/state.toml");
            let bytes = fs::read(&frozen_state).unwrap_or_else(|error| {
                panic!("read frozen state {}: {error}", frozen_state.display());
            });
            write_private(&legacy.state_file, &bytes);
            Some(bytes)
        } else {
            None
        };

        for lock in [
            legacy.config_dir.join("config.lock"),
            legacy.state_dir.join("metadata.lock"),
            legacy.state_dir.join("state.lock"),
        ] {
            write_private(&lock, b"");
        }

        for relative in snapshot.vendor_files() {
            copy_frozen_file(&frozen_root.join(relative), &legacy_root.join(relative));
        }

        Self {
            _temporary: temporary,
            legacy,
            target,
            binding_path,
            source_config: config.into_bytes(),
            source_state,
        }
    }

    fn assert_source_metadata_unchanged(&self) {
        assert_eq!(
            fs::read(&self.legacy.config_file)
                .unwrap_or_else(|error| panic!("read source config: {error}")),
            self.source_config
        );
        match &self.source_state {
            Some(expected) => assert_eq!(
                fs::read(&self.legacy.state_file)
                    .unwrap_or_else(|error| panic!("read source state: {error}")),
                *expected
            ),
            None => assert!(
                !self.legacy.state_file.exists(),
                "migration must not create missing legacy mutable state"
            ),
        }
    }
}

#[test]
fn frozen_v010_store_migrates_identity_state_and_vendor_files() {
    let fixture = MaterializedFixture::from_frozen(Snapshot::WithState);
    let plan = MigrationPlan::inspect(&fixture.legacy, &fixture.target)
        .unwrap_or_else(|error| panic!("inspect frozen v0.1.0 store: {error}"));

    let summary = plan.summary();
    assert_eq!(summary.profile_count(), 2);
    assert_eq!(summary.vendor_file_count(), 5);
    assert_eq!(summary.vendor_directory_count(), 7);
    assert_eq!(summary.skipped_lock_count(), 1);
    assert_eq!(
        summary.skipped_lock_paths(),
        &[PathBuf::from("codex/work/session.lock")]
    );

    plan.execute()
        .unwrap_or_else(|error| panic!("migrate frozen v0.1.0 store: {error}"));

    let store = MetadataStore::new(fixture.target.clone());
    let (config, state) = store
        .load_metadata()
        .unwrap_or_else(|error| panic!("load migrated v0.1.0 metadata: {error}"));
    let claude_id: ProfileId = "claude:personal"
        .parse()
        .unwrap_or_else(|error| panic!("parse Claude fixture profile: {error}"));
    let codex_id: ProfileId = "codex:work"
        .parse()
        .unwrap_or_else(|error| panic!("parse Codex fixture profile: {error}"));
    let claude = config
        .profiles
        .get(&claude_id)
        .unwrap_or_else(|| panic!("migrated Claude fixture profile is missing"));
    let codex = config
        .profiles
        .get(&codex_id)
        .unwrap_or_else(|| panic!("migrated Codex fixture profile is missing"));
    let expected_claude_state = fixture
        .target
        .profile_state_dir(claude_id.provider(), claude_id.name());
    let expected_codex_state = fixture
        .target
        .profile_state_dir(codex_id.provider(), codex_id.name());

    assert_eq!(claude.secret_ref(), Some(LEGACY_KEYRING_REF));
    assert_eq!(claude.state_dir(), expected_claude_state);
    assert_eq!(codex.state_dir(), expected_codex_state);
    assert_eq!(
        config.default_context.as_ref().map(Name::as_str),
        Some("mixed")
    );
    assert_eq!(
        state.current_context.as_ref().map(Name::as_str),
        Some("mixed")
    );
    let mixed = config
        .contexts
        .get(&Name::parse("mixed").unwrap_or_else(|error| panic!("parse context: {error}")))
        .unwrap_or_else(|| panic!("migrated mixed context is missing"));
    assert_eq!(mixed.claude.as_ref(), Some(&claude_id));
    assert_eq!(mixed.codex.as_ref(), Some(&codex_id));
    assert_eq!(config.bindings.len(), 1);
    assert_eq!(config.bindings[0].path, fixture.binding_path);
    assert_eq!(config.bindings[0].context.as_str(), "mixed");

    assert_vendor_file(
        &fixture
            .target
            .data_dir
            .join("vendor-state/claude/personal/session.json"),
        b"{\"fixture\":\"active-claude-v0.1.0\"}\n",
    );
    assert_vendor_file(
        &fixture
            .target
            .data_dir
            .join("vendor-state/claude/personal.retired-v010/history.json"),
        b"{\"fixture\":\"retired-claude-v0.1.0\"}\n",
    );
    assert_vendor_file(
        &fixture
            .target
            .data_dir
            .join("vendor-state/claude/personal/cache.lock/manifest.json"),
        b"{\"fixture\":\"directory-named-lock-v0.1.0\"}\n",
    );
    assert_vendor_file(
        &fixture
            .target
            .data_dir
            .join("vendor-state/codex/work/hooks/post-login"),
        b"#!/bin/sh\nexit 0\n",
    );
    assert!(
        !fixture
            .target
            .data_dir
            .join("vendor-state/codex/work/session.lock")
            .exists(),
        "a regular v0.1.0 runtime lock must not be copied"
    );
    assert_vendor_file(
        &fixture
            .legacy
            .data_dir
            .join("vendor-state/codex/work/session.lock"),
        b"frozen runtime lock: do not migrate\n",
    );

    assert_executable_mode_preserved(&fixture);
    fixture.assert_source_metadata_unchanged();
}

#[test]
fn frozen_v010_store_without_state_toml_uses_default_state() {
    let fixture = MaterializedFixture::from_frozen(Snapshot::MissingState);
    assert!(!fixture.legacy.state_file.exists());

    let plan = MigrationPlan::inspect(&fixture.legacy, &fixture.target)
        .unwrap_or_else(|error| panic!("inspect state-less v0.1.0 store: {error}"));
    assert_eq!(plan.summary().profile_count(), 1);
    assert_eq!(plan.summary().vendor_file_count(), 1);
    assert_eq!(plan.summary().vendor_directory_count(), 2);
    assert_eq!(plan.summary().skipped_lock_count(), 0);

    plan.execute()
        .unwrap_or_else(|error| panic!("migrate state-less v0.1.0 store: {error}"));
    assert!(fixture.target.state_file.is_file());

    let store = MetadataStore::new(fixture.target.clone());
    let (config, state) = store
        .load_metadata()
        .unwrap_or_else(|error| panic!("load migrated default state: {error}"));
    let profile_id: ProfileId = "claude:solo"
        .parse()
        .unwrap_or_else(|error| panic!("parse state-less fixture profile: {error}"));
    let profile = config
        .profiles
        .get(&profile_id)
        .unwrap_or_else(|| panic!("migrated state-less profile is missing"));
    let expected_state_dir = fixture
        .target
        .profile_state_dir(profile_id.provider(), profile_id.name());
    assert_eq!(profile.secret_ref(), Some(MISSING_STATE_KEYRING_REF));
    assert_eq!(profile.state_dir(), expected_state_dir);
    assert_eq!(state.version, 1);
    assert!(state.current_context.is_none());
    assert_vendor_file(
        &fixture
            .target
            .data_dir
            .join("vendor-state/claude/solo/settings.json"),
        b"{\"fixture\":\"missing-state-v0.1.0\"}\n",
    );
    fixture.assert_source_metadata_unchanged();
}

#[test]
fn malformed_v010_metadata_never_leaks_the_source_line_or_canaries() {
    let fixture = MaterializedFixture::from_frozen(Snapshot::Malformed);
    let template_path = frozen_fixture_root().join("malformed/config/config.toml.in");
    let template = fs::read_to_string(&template_path).unwrap_or_else(|error| {
        panic!(
            "read malformed fixture template {}: {error}",
            template_path.display()
        );
    });
    let offending_line = template
        .lines()
        .find(|line| line.contains(ACCOUNT_LEAK_CANARY))
        .unwrap_or_else(|| panic!("malformed fixture does not contain its canary line"));

    let Err(error) = MigrationPlan::inspect(&fixture.legacy, &fixture.target) else {
        panic!("malformed v0.1.0 metadata must be refused");
    };
    let display = error.to_string();
    let debug = format!("{error:?}");
    for rendered in [&display, &debug] {
        assert!(!rendered.contains(ACCOUNT_LEAK_CANARY));
        assert!(!rendered.contains(KEYRING_LEAK_CANARY));
        assert!(!rendered.contains(offending_line));
    }
    assert!(!fixture.target.config_dir.exists());
    fixture.assert_source_metadata_unchanged();
}

fn frozen_fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v0_1_0")
}

fn instantiate_config(template: &str, legacy_root: &Path, binding_path: &Path) -> String {
    let config = template
        .replace("{{LEGACY_ROOT}}", &toml_string_fragment(legacy_root))
        .replace("{{BINDING_PATH}}", &toml_string_fragment(binding_path));
    assert!(
        !config.contains("{{"),
        "fixture placeholder was not replaced"
    );
    config
}

fn toml_string_fragment(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

fn copy_frozen_file(source: &Path, target: &Path) {
    let parent = target
        .parent()
        .unwrap_or_else(|| panic!("fixture target has no parent: {}", target.display()));
    ensure_secure_directory(parent).unwrap_or_else(|error| {
        panic!(
            "create fixture vendor directory {}: {error}",
            parent.display()
        );
    });
    fs::copy(source, target).unwrap_or_else(|error| {
        panic!(
            "copy frozen fixture {} to {}: {error}",
            source.display(),
            target.display()
        );
    });
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .unwrap_or_else(|error| panic!("create private fixture file {}: {error}", path.display()));
    file.write_all(bytes)
        .unwrap_or_else(|error| panic!("write private fixture file {}: {error}", path.display()));
}

fn assert_vendor_file(path: &Path, expected: &[u8]) {
    assert_eq!(
        fs::read(path)
            .unwrap_or_else(|error| panic!("read vendor file {}: {error}", path.display())),
        expected
    );
}

#[cfg(unix)]
fn assert_executable_mode_preserved(fixture: &MaterializedFixture) {
    use std::os::unix::fs::PermissionsExt;

    let relative = "vendor-state/codex/work/hooks/post-login";
    let source = fixture.legacy.data_dir.join(relative);
    let target = fixture.target.data_dir.join(relative);
    let source_mode = fs::metadata(&source)
        .unwrap_or_else(|error| panic!("read source executable metadata: {error}"))
        .permissions()
        .mode();
    let target_mode = fs::metadata(&target)
        .unwrap_or_else(|error| panic!("read target executable metadata: {error}"))
        .permissions()
        .mode();
    assert_ne!(source_mode & 0o100, 0, "frozen hook must be executable");
    assert_eq!(target_mode & 0o777, 0o700);
}

#[cfg(not(unix))]
fn assert_executable_mode_preserved(_fixture: &MaterializedFixture) {}
