use std::{
    sync::{Arc, Barrier, mpsc},
    thread,
    time::Duration,
};

use ctxlane::{
    config::AppPaths,
    migration::{acquire_migration_startup_guard, migration_operation_lock_path},
};
use tempfile::TempDir;

#[test]
fn simultaneous_first_start_reuses_the_valid_private_lock_directory() {
    const STARTERS: usize = 16;

    let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let target = AppPaths::for_root(temporary.path().join("target"));
    let start = Arc::new(Barrier::new(STARTERS + 1));
    let (sender, receiver) = mpsc::channel();
    let mut workers = Vec::new();

    for _ in 0..STARTERS {
        let target = target.clone();
        let start = Arc::clone(&start);
        let sender = sender.clone();
        workers.push(thread::spawn(move || {
            start.wait();
            let _ = sender.send(acquire_migration_startup_guard(&target));
        }));
    }
    drop(sender);
    start.wait();

    let mut guards = Vec::new();
    for _ in 0..STARTERS {
        let result = receiver
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|error| panic!("receive startup result: {error}"));
        guards.push(result.unwrap_or_else(|error| panic!("acquire startup guard: {error}")));
    }
    for worker in workers {
        worker
            .join()
            .unwrap_or_else(|_| panic!("startup worker panicked"));
    }

    assert!(migration_operation_lock_path(&target).is_file());
    assert!(!temporary.path().join("target").exists());
    drop(guards);
}
