use std::fs;
use std::sync::Arc;

use codex_protocol::ThreadId;
use tempfile::TempDir;

use super::COORDINATION_LOCK_FILE;
use super::WRITER_LOCK_DIR;
use super::WriterLockCoordinator;
use crate::ThreadStoreError;

#[test]
fn writer_locks_reject_competing_owners_and_release_their_files() {
    let home = TempDir::new().expect("temp dir");
    let primary = Arc::new(WriterLockCoordinator::new(home.path()));
    let secondary = Arc::new(WriterLockCoordinator::new(home.path()));
    let thread_id = ThreadId::default();
    let other_thread_id = ThreadId::default();

    let owner = primary.acquire(thread_id).expect("acquire writer lock");
    let lock_path = home
        .path()
        .join(WRITER_LOCK_DIR)
        .join(format!("{thread_id}.lock"));
    assert!(lock_path.exists());

    let err = match secondary.acquire(thread_id) {
        Ok(_) => panic!("competing owner should fail"),
        Err(err) => err,
    };
    assert!(matches!(err, ThreadStoreError::Conflict { .. }));
    let other_owner = secondary
        .acquire(other_thread_id)
        .expect("other thread should acquire its own lock");

    drop(owner);
    assert!(!lock_path.exists());
    let next_owner = secondary
        .acquire(thread_id)
        .expect("released thread should accept another owner");
    drop(next_owner);
    drop(other_owner);

    let entries = fs::read_dir(home.path().join(WRITER_LOCK_DIR))
        .expect("read lock directory")
        .map(|entry| entry.expect("lock directory entry").file_name())
        .collect::<Vec<_>>();
    assert_eq!(entries, vec![COORDINATION_LOCK_FILE]);
}

#[test]
fn first_acquisition_removes_stale_locks_without_removing_active_locks() {
    let home = TempDir::new().expect("temp dir");
    let primary = Arc::new(WriterLockCoordinator::new(home.path()));
    let active_thread_id = ThreadId::default();
    let active_owner = primary
        .acquire(active_thread_id)
        .expect("acquire active writer lock");

    let stale_thread_id = ThreadId::default();
    let stale_path = home
        .path()
        .join(WRITER_LOCK_DIR)
        .join(format!("{stale_thread_id}.lock"));
    fs::File::create(&stale_path).expect("create stale writer lock");

    let secondary = Arc::new(WriterLockCoordinator::new(home.path()));
    let secondary_owner = secondary
        .acquire(ThreadId::default())
        .expect("acquire writer lock after cleanup");

    assert!(!stale_path.exists());
    let err = match secondary.acquire(active_thread_id) {
        Ok(_) => panic!("active writer should survive cleanup"),
        Err(err) => err,
    };
    assert!(matches!(err, ThreadStoreError::Conflict { .. }));

    drop(secondary_owner);
    drop(active_owner);
}

/// #928: a dropped coordination lock is free at once, even while a child that
/// another thread forked still holds a copy of its descriptor.
#[cfg(unix)]
#[test]
fn coordination_lock_is_released_while_a_forked_child_holds_its_descriptor() -> std::io::Result<()>
{
    use std::io::Read;
    use std::io::Write;
    use std::os::unix::process::CommandExt;

    let home = TempDir::new()?;
    let coordinator = WriterLockCoordinator::new(home.path());
    let held = coordinator
        .lock_coordination()
        .expect("lock the coordination file");

    // A child forked now has a copy of every descriptor, the lock's too, until
    // it starts its program; this one waits 2 s first and reports the fork.
    let (mut forked, mut forked_tx) = std::io::pipe()?;
    let spawner = std::thread::spawn(move || {
        let mut command = std::process::Command::new("/bin/sh");
        command.args(["-c", "exit 0"]);
        // SAFETY: the hook only writes to a pipe and sleeps, both safe after fork.
        unsafe {
            command.pre_exec(move || {
                forked_tx.write_all(b"f")?;
                std::thread::sleep(std::time::Duration::from_secs(2));
                Ok(())
            });
        }
        command.status()
    });
    let mut byte = [0; 1];
    forked.read_exact(&mut byte)?;

    let other = fs::OpenOptions::new().read(true).write(true).open(
        home.path()
            .join(WRITER_LOCK_DIR)
            .join(COORDINATION_LOCK_FILE),
    )?;
    assert!(other.try_lock().is_err(), "the lock is held");
    drop(held);
    assert!(
        other.try_lock().is_ok(),
        "the dropped coordination lock is still held through the forked child's copy"
    );
    let status = spawner.join().expect("spawner thread")?;
    assert!(status.success(), "{status:?}");
    Ok(())
}

// A retained clone models the shared open-file description inherited across
// fork, without starting a child or depending on how long it takes to exec.
#[cfg(unix)]
#[test]
fn writer_lock_is_released_with_a_retained_descriptor() -> std::io::Result<()> {
    let home = TempDir::new()?;
    let coordinator = Arc::new(WriterLockCoordinator::new(home.path()));
    let owner = coordinator
        .acquire(ThreadId::default())
        .expect("acquire writer lock");
    let path = owner.path.clone();
    let retained = owner.file.as_ref().expect("owned file").try_clone()?;
    let observer = fs::OpenOptions::new().read(true).write(true).open(&path)?;
    assert!(matches!(
        observer.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));

    drop(owner);

    assert!(!path.exists(), "normal cleanup removes the pathname");
    let reacquired = observer.try_lock();
    assert!(
        reacquired.is_ok(),
        "writer lock remained held through its retained descriptor: {reacquired:?}"
    );
    // Keep the duplicate alive until after the assertion; closing it must not
    // be what lets the independent observer acquire the lock.
    drop(retained);
    Ok(())
}

#[cfg(unix)]
#[test]
fn writer_lock_is_released_when_file_removal_fails() -> std::io::Result<()> {
    let home = TempDir::new()?;
    let coordinator = Arc::new(WriterLockCoordinator::new(home.path()));
    let owner = coordinator
        .acquire(ThreadId::default())
        .expect("acquire writer lock");
    let path = owner.path.clone();
    let retained = owner.file.as_ref().expect("owned file").try_clone()?;
    let saved = home.path().join("retained-writer-inode");
    fs::rename(&path, &saved)?;
    fs::create_dir(&path)?;
    let observer = fs::OpenOptions::new().read(true).write(true).open(&saved)?;
    assert!(matches!(
        observer.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));

    drop(owner);

    assert!(
        path.is_dir(),
        "failed cleanup keeps the replacement directory"
    );
    assert!(saved.is_file(), "the observed inode remains reachable");
    let reacquired = observer.try_lock();
    assert!(
        reacquired.is_ok(),
        "failed removal left the writer lock held: {reacquired:?}"
    );
    drop(retained);
    Ok(())
}

#[cfg(unix)]
#[test]
fn writer_lock_is_released_when_coordination_fails() -> std::io::Result<()> {
    let home = TempDir::new()?;
    let coordinator = Arc::new(WriterLockCoordinator::new(home.path()));
    let owner = coordinator
        .acquire(ThreadId::default())
        .expect("acquire writer lock");
    let path = owner.path.clone();
    let retained = owner.file.as_ref().expect("owned file").try_clone()?;
    let observer = fs::OpenOptions::new().read(true).write(true).open(&path)?;
    assert!(matches!(
        observer.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    let coordination_path = home
        .path()
        .join(WRITER_LOCK_DIR)
        .join(COORDINATION_LOCK_FILE);
    fs::remove_file(&coordination_path)?;
    fs::create_dir(&coordination_path)?;

    drop(owner);

    assert!(
        coordination_path.is_dir(),
        "coordination failure is preserved"
    );
    assert!(
        path.is_file(),
        "uncoordinated cleanup does not remove the lock file"
    );
    let reacquired = observer.try_lock();
    assert!(
        reacquired.is_ok(),
        "failed coordination left the writer lock held: {reacquired:?}"
    );
    drop(retained);
    Ok(())
}
