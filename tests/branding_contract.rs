use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const LEGACY_OCCURRENCE_ALLOWLIST: &[(&str, usize)] = &[
    ("CHANGELOG.md", 4),
    ("SECURITY.md", 1),
    ("docs/command-reference.md", 2),
    ("docs/compatibility.md", 1),
    ("docs/configuration.md", 1),
    ("src/brand.rs", 8),
    ("src/cli.rs", 13),
    ("src/commands.rs", 13),
    ("src/config.rs", 8),
    ("src/identity.rs", 5),
    ("src/migration.rs", 1),
    ("src/migration/journal.rs", 1),
    ("src/runner.rs", 10),
    ("src/secret.rs", 1),
    ("tests/cli_workflow.rs", 3),
    ("tests/migration_cli.rs", 9),
    ("tests/migration_core.rs", 3),
    ("tests/runner_contract.rs", 1),
];

#[test]
fn legacy_branding_is_limited_to_the_audited_migration_contract() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
    let legacy_name = ["ai", "ctx"].concat();
    let retired_title = ["coding agent", " profiles"].concat();
    let expected = LEGACY_OCCURRENCE_ALLOWLIST
        .iter()
        .map(|(path, count)| ((*path).to_owned(), *count))
        .collect::<BTreeMap<_, _>>();
    let mut observed = BTreeMap::new();

    for relative_path in repository_files(repository) {
        let normalized_path = relative_path.to_string_lossy().replace('\\', "/");
        let lowercase_path = normalized_path.to_ascii_lowercase();
        assert!(
            !lowercase_path.contains(&legacy_name),
            "legacy product name remains in tracked path {normalized_path:?}"
        );
        assert!(
            !lowercase_path.contains(&retired_title),
            "retired project title remains in tracked path {normalized_path:?}"
        );

        let contents = fs::read(repository.join(&relative_path))
            .unwrap_or_else(|error| panic!("read {normalized_path}: {error}"));
        let lowercase_contents = String::from_utf8_lossy(&contents).to_ascii_lowercase();
        assert!(
            !lowercase_contents.contains(&retired_title),
            "retired project title remains in {normalized_path}"
        );

        let legacy_count = lowercase_contents.matches(&legacy_name).count();
        if legacy_count > 0 {
            observed.insert(normalized_path, legacy_count);
        }
    }

    assert_eq!(
        observed, expected,
        "legacy product-name occurrences changed; remove current-facing branding or audit the exact migration requirement"
    );
}

fn repository_files(repository: &Path) -> Vec<PathBuf> {
    let output = Command::new("git")
        .current_dir(repository)
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ])
        .output();

    if let Ok(output) = output
        && output.status.success()
    {
        return output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|path| !path.is_empty())
            .map(|path| PathBuf::from(String::from_utf8_lossy(path).into_owned()))
            .collect();
    }

    let mut files = Vec::new();
    collect_repository_files(repository, repository, &mut files);
    files
}

fn collect_repository_files(repository: &Path, directory: &Path, files: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("read directory {}: {error}", directory.display()));

    for entry in entries {
        let entry = entry.unwrap_or_else(|error| panic!("read directory entry: {error}"));
        let path = entry.path();
        let relative_path = path
            .strip_prefix(repository)
            .unwrap_or_else(|error| panic!("make repository-relative path: {error}"));
        let file_type = entry
            .file_type()
            .unwrap_or_else(|error| panic!("inspect {}: {error}", path.display()));

        if file_type.is_dir() {
            let is_top_level_build_metadata = relative_path
                .parent()
                .is_some_and(|parent| parent.as_os_str().is_empty())
                && matches!(
                    relative_path.file_name().and_then(|name| name.to_str()),
                    Some(".git" | "target")
                );
            if !is_top_level_build_metadata {
                collect_repository_files(repository, &path, files);
            }
        } else if file_type.is_file() {
            files.push(relative_path.to_path_buf());
        }
    }
}
