//! Keşif ve ortam haritalama modülü.

#![forbid(unsafe_code)]

use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::apoptosis::{ApoptosisError, EphemeralBuffer, acquire_operation_permit, acquire_permit};
use crate::crypto::{self, SealedBlob};

/// Keşfedilen bir düğüm veya kaynak için minimal tanımlayıcı.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveredPeer {
    pub id: String,
    pub endpoint_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessMeta {
    pub pid: u32,
    pub name: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvKeyMeta {
    pub key: String,
    pub value_digest_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScoutSnapshot {
    pub host_label: String,
    pub open_ports_simulated: Vec<u16>,
    pub processes_simulated: Vec<ProcessMeta>,
    pub env_keys_redacted: Vec<EnvKeyMeta>,
    pub scanned_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScoutReportMeta {
    pub host_label: String,
    pub scanned_at_unix: u64,
    pub encrypted_bytes: usize,
}

/// Mesh'e aktarım için şifreli keşif paketi.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedScoutHandoff {
    pub sealed: SealedBlob,
    pub meta: ScoutReportMeta,
}

/// Şifrelenmiş keşif çıktısı + apoptosis tampon referansı.
pub struct EncryptedScoutReport {
    pub sealed: SealedBlob,
    pub meta: ScoutReportMeta,
    vault: EphemeralBuffer,
}

impl EncryptedScoutReport {
    pub fn sealed(&self) -> &SealedBlob {
        &self.sealed
    }

    pub fn meta(&self) -> &ScoutReportMeta {
        &self.meta
    }

    pub fn vault_len(&self) -> usize {
        self.vault.len()
    }

    pub fn into_handoff(self) -> EncryptedScoutHandoff {
        EncryptedScoutHandoff {
            sealed: self.sealed,
            meta: self.meta,
        }
    }
}

struct ScoutState {
    #[allow(dead_code)]
    last_peers: Vec<DiscoveredPeer>,
}

static SCOUT: OnceLock<Mutex<ScoutState>> = OnceLock::new();

fn scout_state() -> Result<std::sync::MutexGuard<'static, ScoutState>, String> {
    SCOUT
        .get()
        .ok_or_else(|| "scout not initialized".to_string())?
        .lock()
        .map_err(|_| "scout lock poisoned".to_string())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Scout alt sistemini hazırlar.
pub async fn initialize() -> Result<(), String> {
    tracing_log("scout: initialize");
    let _permit = acquire_operation_permit()?;

    crypto::init_session_from_entropy()?;

    if SCOUT.get().is_some() {
        return Ok(());
    }

    let state = ScoutState {
        last_peers: vec![DiscoveredPeer {
            id: "local-node".into(),
            endpoint_hint: Some("loopback://0".into()),
        }],
    };

    let _ = SCOUT.set(Mutex::new(state));
    Ok(())
}

/// Tek keşif döngüsü: tarama → şifreleme → apoptosis tamponu.
pub async fn run_discovery_cycle() -> Result<EncryptedScoutReport, String> {
    let _permit = acquire_operation_permit()?;
    {
        let _guard = scout_state()?;
    }

    let snapshot = scan_environment()?;
    let plaintext = EphemeralBuffer::from_serializable(&snapshot)?;
    let sealed = crypto::seal_plaintext(&plaintext)?;

    let meta = ScoutReportMeta {
        host_label: snapshot.host_label.clone(),
        scanned_at_unix: snapshot.scanned_at_unix,
        encrypted_bytes: sealed.ciphertext_b64.len(),
    };

    let vault = EphemeralBuffer::from_serializable(&sealed)?;

    tracing_log(&format!(
        "scout: cycle complete host={} vault={}B",
        meta.host_label,
        vault.len()
    ));

    Ok(EncryptedScoutReport {
        sealed,
        meta,
        vault,
    })
}

/// Ana keşif döngüsü: bir tam tarama yürütür.
pub async fn run_discovery_loop() -> Result<(), String> {
    let report = run_discovery_cycle().await?;
    tracing_log(&format!(
        "scout: sealed scout report host={} ciphertext_b64={}B",
        report.meta().host_label,
        report.sealed().ciphertext_b64.len()
    ));
    Ok(())
}

/// Ortam taramasını simüle eder; hassas değerler özetlenir.
pub fn scan_environment() -> Result<ScoutSnapshot, ApoptosisError> {
    // Fail-closed: `acquire_permit()` → `ApoptosisError` (String API: `acquire_operation_permit()`).
    let _permit = acquire_permit()?;
    let host_label = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".into());

    Ok(ScoutSnapshot {
        host_label,
        open_ports_simulated: simulate_active_ports(),
        processes_simulated: simulate_process_list(),
        env_keys_redacted: collect_env_metadata(),
        scanned_at_unix: unix_now(),
    })
}

fn simulate_active_ports() -> Vec<u16> {
    vec![22, 80, 135, 443, 445, 3000, 5353, 7680]
}

fn simulate_process_list() -> Vec<ProcessMeta> {
    vec![
        ProcessMeta {
            pid: 0,
            name: "System Idle".into(),
            state: "running".into(),
        },
        ProcessMeta {
            pid: 4,
            name: "System".into(),
            state: "running".into(),
        },
        ProcessMeta {
            pid: 128,
            name: "nexus-ephemera".into(),
            state: "simulated".into(),
        },
    ]
}

fn is_sensitive_env_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();

    const DENY_FRAGMENTS: &[&str] = &[
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "TOKEN",
        "CREDENTIAL",
        "CRED",
        "PRIVATE",
        "AUTH",
        "BEARER",
        "DATABASE",
        "DB_",
        "CONNECTION",
        "CONNSTR",
        "URL",
        "URI",
        "API_KEY",
        "APIKEY",
        "ACCESS_KEY",
        "SIGNING",
        "CERT",
        "CERTIFICATE",
        "MNEMONIC",
        "WALLET",
        "OAUTH",
        "JWT",
        "SESSION",
        "COOKIE",
    ];

    if DENY_FRAGMENTS.iter().any(|frag| upper.contains(frag)) {
        return true;
    }

    if upper.ends_with("_KEY") {
        return true;
    }

    // OpenSSH / cloud tarzı ortak kalıplar
    matches!(
        upper.as_str(),
        "SSH_AUTH_SOCK" | "AWS_SESSION_TOKEN" | "GCP_METADATA" | "AZURE_CLIENT_SECRET"
    )
}

fn collect_env_metadata() -> Vec<EnvKeyMeta> {
    let mut out = Vec::new();
    for (raw_key, raw_val) in std::env::vars() {
        let mut key = Zeroizing::new(raw_key);
        let val = Zeroizing::new(raw_val);

        if is_sensitive_env_key(&key) {
            // `key` ve `val` kapsam sonunda / unwind'da Zeroizing ile sıfırlanır.
            continue;
        }

        let value_digest_hex = short_digest_hex(val.as_bytes());
        drop(val);

        out.push(EnvKeyMeta {
            key: std::mem::take(&mut *key),
            value_digest_hex,
        });
    }
    out.sort_by(|a, b| a.key.cmp(&b.key));
    out.truncate(12);
    out
}

fn short_digest_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

fn tracing_log(message: &str) {
    eprintln!("[{message}]");
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: [u8; 32] = [0x42_u8; 32];

    #[test]
    fn scan_environment_produces_snapshot() {
        let _guard = crate::apoptosis::test_serial();
        crate::apoptosis::reset_coordinator_for_tests();
        let snap = scan_environment().expect("scan");
        assert!(!snap.host_label.is_empty());
        assert!(!snap.open_ports_simulated.is_empty());
        assert!(!snap.processes_simulated.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    #[allow(clippy::await_holding_lock)]
    async fn discovery_cycle_seals_and_stores_in_vault() {
        let _guard = crate::apoptosis::test_serial();
        crate::apoptosis::reset_coordinator_for_tests();
        crypto::init_session_for_tests(TEST_KEY).expect("session");
        initialize().await.expect("init");

        let report = run_discovery_cycle().await.expect("cycle");
        assert!(!report.sealed().ciphertext_b64.is_empty());
        assert!(report.vault_len() > 0);

        let plain = crypto::open_to_plaintext(report.sealed()).expect("decrypt");
        let decoded: ScoutSnapshot = plain.decode_json().expect("json");
        assert_eq!(decoded.host_label, report.meta().host_label);
    }

    #[test]
    fn env_denylist_covers_common_patterns() {
        let _guard = crate::apoptosis::test_serial();
        assert!(is_sensitive_env_key("AWS_SECRET_ACCESS_KEY"));
        assert!(is_sensitive_env_key("MY_DATABASE_URL"));
        assert!(is_sensitive_env_key("OAUTH_BEARER"));
        assert!(is_sensitive_env_key("SIGNING_PRIVATE_MATERIAL"));
        assert!(!is_sensitive_env_key("OS"));
        assert!(!is_sensitive_env_key("PATH"));
    }

    #[test]
    fn scan_environment_fails_closed_after_apoptosis() {
        let _guard = crate::apoptosis::test_serial();
        crate::apoptosis::reset_coordinator_for_tests();
        let _ = crate::apoptosis::trigger_apoptosis();
        assert!(scan_environment().is_err());
    }

    #[test]
    fn env_metadata_skips_sensitive_keys() {
        let _guard = crate::apoptosis::test_serial();
        let keys: Vec<_> = collect_env_metadata().into_iter().map(|e| e.key).collect();
        assert!(!keys.iter().any(|k| is_sensitive_env_key(k)));
    }
}
