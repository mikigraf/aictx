#![cfg(windows)]

use std::process::Command;

use ctxlane::{
    config::{AppPaths, MetadataStore, ensure_secure_directory},
    migration::MigrationPlan,
};
use tempfile::TempDir;

#[test]
fn migration_refuses_a_windows_directory_junction_in_vendor_state() {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let legacy = AppPaths::for_root(temporary.path().join("aictx"));
    let target = AppPaths::for_root(temporary.path().join("ctxlane"));
    MetadataStore::new(legacy.clone())
        .initialize()
        .unwrap_or_else(|error| panic!("initialize legacy store: {error}"));

    let outside = temporary.path().join("outside-vendor-state");
    ensure_secure_directory(&outside)
        .unwrap_or_else(|error| panic!("create junction target: {error}"));
    let junction = legacy.data_dir.join("vendor-state").join("junction");
    let output = Command::new("cmd.exe")
        .args(["/D", "/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&outside)
        .output()
        .unwrap_or_else(|error| panic!("run mklink /J: {error}"));
    if !output.status.success() {
        let diagnostic = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if diagnostic.to_ascii_lowercase().contains("privilege") {
            eprintln!("skipping junction contract after explicit privilege failure: {diagnostic}");
            return;
        }
        panic!("mklink /J failed: {diagnostic}");
    }

    let Err(error) = MigrationPlan::inspect(&legacy, &target) else {
        panic!("migration must refuse a Windows directory junction");
    };
    assert!(error.to_string().contains("reparse point"));
    assert!(!target.config_dir.exists());
}
