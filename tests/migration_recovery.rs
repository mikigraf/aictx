use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use ctxlane::{
    config::{AppPaths, ensure_secure_directory},
    migration::{RecoveryOutcome, migration_journal_path, recover_incomplete},
};
use serde::Serialize;
use tempfile::TempDir;

const TRANSACTION_ID: &str = "deadbeef-4242";

struct Fixture {
    _temporary: TempDir,
    legacy: AppPaths,
    target: AppPaths,
    anchors: Vec<Anchor>,
}

impl Fixture {
    fn new() -> Self {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let legacy = AppPaths::for_root(temporary.path().join("aictx"));
        let target_root = temporary.path().join("ctxlane");
        let target = AppPaths::for_root(&target_root);
        ensure_secure_directory(&target_root)
            .unwrap_or_else(|error| panic!("create target root: {error}"));
        let mut targets = [
            target.config_dir.clone(),
            target.data_dir.clone(),
            target.state_dir.clone(),
        ];
        targets.sort();
        let anchors = targets
            .into_iter()
            .enumerate()
            .map(|(index, target)| Anchor {
                stage: stage_path(&target, index),
                target,
                committed: false,
                archive: None,
            })
            .collect();
        Self {
            _temporary: temporary,
            legacy,
            target,
            anchors,
        }
    }

    fn create_stage(&self, index: usize) {
        create_owned_tree(&self.anchors[index].stage, &format!("stage-{index}"));
    }

    fn create_target(&self, index: usize) {
        create_owned_tree(&self.anchors[index].target, &format!("target-{index}"));
    }

    fn write_journal(&self, phase: &str, anchors: Vec<Anchor>) {
        let journal = Journal {
            version: 1,
            transaction_id: TRANSACTION_ID,
            legacy: Paths::from(&self.legacy),
            target: Paths::from(&self.target),
            phase,
            anchors,
        };
        let text = toml::to_string_pretty(&journal)
            .unwrap_or_else(|error| panic!("serialize recovery journal: {error}"));
        write_private(
            &migration_journal_path(&self.target),
            format!("{text}\n").as_bytes(),
        );
    }
}

#[test]
fn recovery_covers_every_preverified_journal_transition() {
    struct Scenario {
        name: &'static str,
        phase: &'static str,
        stages: &'static [usize],
        targets: &'static [usize],
        committed: &'static [usize],
    }

    let scenarios = [
        Scenario {
            name: "partially staging",
            phase: "staging",
            stages: &[0],
            targets: &[],
            committed: &[],
        },
        Scenario {
            name: "fully staged",
            phase: "staged",
            stages: &[0, 1, 2],
            targets: &[],
            committed: &[],
        },
        Scenario {
            name: "first anchor committed",
            phase: "committing",
            stages: &[0, 2],
            targets: &[1],
            committed: &[1],
        },
        Scenario {
            name: "second anchor committed",
            phase: "committing",
            stages: &[0],
            targets: &[1, 2],
            committed: &[1, 2],
        },
        Scenario {
            name: "last anchor committed before verification",
            phase: "committing",
            stages: &[],
            targets: &[0, 1, 2],
            committed: &[0, 1, 2],
        },
    ];

    for scenario in scenarios {
        let fixture = Fixture::new();
        for &index in scenario.stages {
            fixture.create_stage(index);
        }
        for &index in scenario.targets {
            fixture.create_target(index);
        }
        let mut anchors = fixture.anchors.clone();
        for &index in scenario.committed {
            anchors[index].committed = true;
        }
        fixture.write_journal(scenario.phase, anchors);

        let outcome = recover_incomplete(&fixture.legacy, &fixture.target)
            .unwrap_or_else(|error| panic!("recover {}: {error}", scenario.name));
        let RecoveryOutcome::RolledBack { archives } = outcome else {
            panic!("{} should roll back", scenario.name);
        };
        assert_eq!(archives.len(), scenario.targets.len(), "{}", scenario.name);
        assert!(
            !migration_journal_path(&fixture.target).exists(),
            "{}",
            scenario.name
        );
        assert!(
            fixture
                .anchors
                .iter()
                .all(|anchor| !anchor.target.exists() && !anchor.stage.exists()),
            "{}",
            scenario.name
        );
        assert!(archives.iter().all(|archive| archive.is_dir()));
    }
}

#[test]
fn recovery_archives_an_observed_rename_not_yet_recorded_in_the_journal() {
    let fixture = Fixture::new();
    fixture.create_stage(0);
    fixture.create_target(1);
    fixture.create_stage(2);
    fixture.write_journal("staged", fixture.anchors.clone());

    let outcome = recover_incomplete(&fixture.legacy, &fixture.target)
        .unwrap_or_else(|error| panic!("recover unrecorded rename: {error}"));
    let RecoveryOutcome::RolledBack { archives } = outcome else {
        panic!("unrecorded rename should roll back");
    };
    assert_eq!(archives.len(), 1);
    assert!(archives[0].join("target-1").is_file());
    assert!(!migration_journal_path(&fixture.target).exists());
}

#[test]
fn recovery_resumes_after_a_target_was_already_archived() {
    let fixture = Fixture::new();
    fixture.create_stage(0);
    fixture.create_stage(2);
    let archive = archive_path(&fixture.anchors[1].target, 1, 0);
    create_owned_tree(&archive, "already-archived");
    let mut anchors = fixture.anchors.clone();
    anchors[1].committed = true;
    anchors[1].archive = Some(archive.clone());
    fixture.write_journal("committing", anchors);

    let outcome = recover_incomplete(&fixture.legacy, &fixture.target)
        .unwrap_or_else(|error| panic!("resume archived rollback: {error}"));
    assert_eq!(
        outcome,
        RecoveryOutcome::RolledBack {
            archives: vec![archive.clone()]
        }
    );
    assert!(archive.join("already-archived").is_file());
    assert!(!migration_journal_path(&fixture.target).exists());
    assert!(fixture.anchors.iter().all(|anchor| !anchor.stage.exists()));
}

#[test]
fn recovery_refuses_a_recorded_commit_when_target_and_archive_are_missing() {
    let fixture = Fixture::new();
    fixture.create_stage(0);
    fixture.create_stage(2);
    let mut anchors = fixture.anchors.clone();
    anchors[1].committed = true;
    fixture.write_journal("committing", anchors);

    let Err(error) = recover_incomplete(&fixture.legacy, &fixture.target) else {
        panic!("missing committed target must be refused");
    };
    assert!(error.to_string().contains("target is missing"));
    assert!(migration_journal_path(&fixture.target).is_file());
}

fn create_owned_tree(path: &Path, payload_name: &str) {
    ensure_secure_directory(path)
        .unwrap_or_else(|error| panic!("create owned tree {}: {error}", path.display()));
    write_private(
        &path.join(".ctxlane-migration-owner"),
        format!("{TRANSACTION_ID}\n").as_bytes(),
    );
    write_private(&path.join(payload_name), b"partial\n");
}

fn stage_path(target: &Path, index: usize) -> PathBuf {
    let name = target
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("ctxlane");
    target.with_file_name(format!(
        ".{name}.ctxlane-migration-stage-{TRANSACTION_ID}-{index}"
    ))
}

fn archive_path(target: &Path, index: usize, collision: u32) -> PathBuf {
    let name = target
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("ctxlane");
    target.with_file_name(format!(
        ".{name}.ctxlane-migration-rollback-{TRANSACTION_ID}-{index}-{collision}"
    ))
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut file = open_private(path);
    file.set_len(0)
        .unwrap_or_else(|error| panic!("truncate {}: {error}", path.display()));
    file.write_all(bytes)
        .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
    file.sync_all()
        .unwrap_or_else(|error| panic!("sync {}: {error}", path.display()));
}

fn open_private(path: &Path) -> File {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .unwrap_or_else(|error| panic!("open {}: {error}", path.display()))
}

#[derive(Clone, Serialize)]
struct Anchor {
    target: PathBuf,
    stage: PathBuf,
    committed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    archive: Option<PathBuf>,
}

#[derive(Serialize)]
struct Journal<'a> {
    version: u32,
    transaction_id: &'a str,
    legacy: Paths,
    target: Paths,
    phase: &'a str,
    anchors: Vec<Anchor>,
}

#[derive(Serialize)]
struct Paths {
    config: PathBuf,
    data: PathBuf,
    state: PathBuf,
}

impl From<&AppPaths> for Paths {
    fn from(paths: &AppPaths) -> Self {
        Self {
            config: paths.config_dir.clone(),
            data: paths.data_dir.clone(),
            state: paths.state_dir.clone(),
        }
    }
}
