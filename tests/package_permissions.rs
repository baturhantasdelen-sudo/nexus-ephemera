//! Unix security contract: signing must never implicitly repair loose inputs.
#![cfg(unix)]

use nexus_ephemera::packaging;
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

fn template() -> PathBuf {
    let path = std::env::temp_dir().join(format!("nexus-permissions-{}", uuid::Uuid::new_v4()));
    packaging::write_template(
        &path,
        "/tmp/nexus-permissions.sock",
        include_bytes!("../policies/pilot_support_agent.json"),
    )
    .unwrap();
    path
}

#[test]
fn loose_required_inputs_fail_before_key_creation_and_require_explicit_repair() {
    for name in ["config.toml", ".env", "pilot_support_agent.json"] {
        let package = template();
        let input = package.join(name);
        fs::set_permissions(&input, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            packaging::seal(&package).is_err(),
            "loose {name} was signed"
        );
        assert_eq!(
            fs::metadata(&input).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert!(!package.join("hmac.key").exists());
        assert!(!package.join("policy.hmac").exists());
        nexus_ephemera_ipc_os::lock_file_to_current_user(&input).unwrap();
        packaging::seal(&package).unwrap();
        packaging::load(&package).unwrap();
        fs::remove_dir_all(package).unwrap();
    }
}

#[test]
fn loose_existing_key_or_signature_cannot_be_repaired_or_replaced_by_seal() {
    for name in ["hmac.key", "policy.hmac"] {
        let package = template();
        packaging::seal(&package).unwrap();
        let key = zeroize::Zeroizing::new(fs::read(package.join("hmac.key")).unwrap());
        let signature = fs::read(package.join("policy.hmac")).unwrap();
        let input = package.join(name);
        fs::set_permissions(&input, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(packaging::seal(&package).is_err());
        assert!(
            fs::read(package.join("hmac.key")).unwrap() == *key,
            "key changed on rejected seal"
        );
        assert!(
            fs::read(package.join("policy.hmac")).unwrap() == signature,
            "tag changed on rejected seal"
        );
        assert_eq!(
            fs::metadata(&input).unwrap().permissions().mode() & 0o777,
            0o644
        );
        nexus_ephemera_ipc_os::lock_file_to_current_user(&input).unwrap();
        packaging::load(&package).unwrap();
        fs::remove_dir_all(package).unwrap();
    }
}
