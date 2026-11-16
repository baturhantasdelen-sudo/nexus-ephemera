#[test]
fn private_file_creation_and_handle_bounded_reads_fail_closed() {
    use std::io::Write;
    let directory = std::env::temp_dir().join(format!("private-files-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let invalid = directory.join("invalid\0suffix");
    assert!(nexus_ephemera_ipc_os::create_private_file(&invalid).is_err());
    assert!(!directory.join("invalid").exists());
    let path = directory.join("credential");
    let mut file = nexus_ephemera_ipc_os::create_private_file(&path).unwrap();
    file.write_all(b"public-fixture").unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert_eq!(
        nexus_ephemera_ipc_os::read_private_file(&path, 64).unwrap(),
        b"public-fixture"
    );
    assert!(nexus_ephemera_ipc_os::create_private_file(&path).is_err());
    assert!(nexus_ephemera_ipc_os::read_private_file(&path, 4).is_err());
    assert!(nexus_ephemera_ipc_os::read_private_file(&path, usize::MAX).is_err());
    #[cfg(unix)]
    {
        let link = directory.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(nexus_ephemera_ipc_os::read_private_file(&link, 64).is_err());
        let hardlink = directory.join("hardlink");
        std::fs::hard_link(&path, hardlink).unwrap();
        assert!(nexus_ephemera_ipc_os::read_private_file(&path, 64).is_err());
    }
    std::fs::remove_dir_all(directory).unwrap();
}
