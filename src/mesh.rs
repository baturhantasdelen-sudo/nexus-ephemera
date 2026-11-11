//! Çevrimdışı eşler arası (p2p) haberleşme modülü.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::apoptosis::{self, EphemeralBuffer, acquire_operation_permit, lock_or_recover};
use crate::crypto::{self, SealedBlob};
use crate::scout::{EncryptedScoutHandoff, ScoutSnapshot};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransportKind {
    SimulatedLocalFile,
    InMemoryQueue,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalFileMeta {
    pub virtual_path: String,
    pub size_bytes: u64,
    pub checksum_hex: String,
}

fn zeroize_string(s: &mut String) {
    let mut bytes = std::mem::take(s).into_bytes();
    bytes.zeroize();
    *s = String::new();
}

impl LocalFileMeta {
    fn wipe(&mut self) {
        zeroize_string(&mut self.virtual_path);
        zeroize_string(&mut self.checksum_hex);
        self.size_bytes = 0;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvelopeBody {
    pub inner: serde_json::Value,
    pub scout_snapshot: Option<ScoutSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshEnvelope {
    pub id: Uuid,
    pub topic: String,
    pub created_at_unix: u64,
    pub sender_id: String,
    pub transport: TransportKind,
    pub sealed: SealedBlob,
    pub local_file: Option<LocalFileMeta>,
    pub plaintext_digest_hex: String,
}

impl Drop for MeshEnvelope {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl MeshEnvelope {
    fn wipe(&mut self) {
        let mut id_bytes = *self.id.as_bytes();
        id_bytes.zeroize();
        self.id = uuid::Uuid::nil();
        self.created_at_unix = 0;
        zeroize_string(&mut self.topic);
        zeroize_string(&mut self.sender_id);
        zeroize_string(&mut self.plaintext_digest_hex);
        self.sealed.wipe();
        if let Some(mut file) = self.local_file.take() {
            file.wipe();
        }
    }
}

struct MeshState {
    outbound: EphemeralBuffer,
    local_channel: VecDeque<MeshEnvelope>,
}

static MESH: OnceLock<Mutex<Option<MeshState>>> = OnceLock::new();

fn mesh_slot() -> &'static Mutex<Option<MeshState>> {
    MESH.get_or_init(|| Mutex::new(None))
}

fn ensure_mesh_viable(slot: &mut Option<MeshState>) -> Result<(), String> {
    let needs_fresh = match slot.as_ref() {
        None => true,
        Some(state) => !state.outbound.memlock_accepts_writes(),
    };
    if needs_fresh {
        *slot = Some(MeshState {
            outbound: EphemeralBuffer::with_capacity(4096)?,
            local_channel: VecDeque::new(),
        });
    }
    Ok(())
}

struct MeshGuard<'a> {
    lock: std::sync::MutexGuard<'a, Option<MeshState>>,
}

impl std::ops::Deref for MeshGuard<'_> {
    type Target = MeshState;

    fn deref(&self) -> &MeshState {
        self.lock.as_ref().expect("mesh state present after ensure")
    }
}

impl std::ops::DerefMut for MeshGuard<'_> {
    fn deref_mut(&mut self) -> &mut MeshState {
        self.lock.as_mut().expect("mesh state present after ensure")
    }
}

#[cfg(test)]
pub(crate) fn reset_mesh_for_tests() {
    if let Some(mesh) = MESH.get() {
        *lock_or_recover(mesh) = None;
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn mesh_state() -> Result<MeshGuard<'static>, String> {
    let mut lock = lock_or_recover(mesh_slot());
    ensure_mesh_viable(&mut lock)?;
    Ok(MeshGuard { lock })
}

fn digest_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Apoptosiz ile mesh temizliğini bağlar.
pub fn register_apoptosis_integration() {
    apoptosis::register_cleanup_hook(wipe_on_apoptosis);
}

pub fn ensure_mesh_cleanup_registered() {
    register_apoptosis_integration();
}

/// Mesh kuyruğu, outbound tampon ve zarf alanlarını bellekten temizler.
pub fn wipe_on_apoptosis() -> Result<(), &'static str> {
    let Some(mesh) = MESH.get() else {
        return Ok(());
    };
    let mut guard = lock_or_recover(mesh);
    let Some(state) = guard.as_mut() else {
        return Ok(());
    };
    for mut envelope in state.local_channel.drain(..) {
        envelope.wipe();
    }
    state
        .outbound
        .try_wipe()
        .map_err(|_| "mesh outbound wipe failed")?;
    Ok(())
}

pub async fn initialize() -> Result<(), String> {
    let _permit = acquire_operation_permit()?;

    crypto::init_session_from_entropy()?;

    let mut slot = lock_or_recover(mesh_slot());
    ensure_mesh_viable(&mut slot)?;
    ensure_mesh_cleanup_registered();
    Ok(())
}

pub fn ingest_scout_handoff(handoff: EncryptedScoutHandoff) -> Result<MeshEnvelope, String> {
    let _permit = acquire_operation_permit()?;

    let snapshot_plain = crypto::open_to_plaintext(&handoff.sealed)?;
    let snapshot: ScoutSnapshot = snapshot_plain.decode_json()?;

    let body = EnvelopeBody {
        inner: serde_json::json!({
            "kind": "scout_report",
            "host": handoff.meta.host_label,
            "scanned_at": handoff.meta.scanned_at_unix,
        }),
        scout_snapshot: Some(snapshot),
    };

    let plaintext = EphemeralBuffer::from_serializable(&body)?;
    let sealed = crypto::seal_plaintext(&plaintext)?;
    let digest = plaintext.digest_sha256_hex()?;

    let wire_buf = EphemeralBuffer::from_serializable(&sealed)?;
    let local_file = LocalFileMeta {
        virtual_path: format!("offline://nexus/inbox/{}.nxs", handoff.meta.scanned_at_unix),
        size_bytes: sealed.ciphertext_b64.len() as u64,
        checksum_hex: digest_hex(sealed.ciphertext_b64.as_bytes()),
    };

    let envelope = MeshEnvelope {
        id: Uuid::new_v4(),
        topic: "scout/encrypted".into(),
        created_at_unix: unix_now(),
        sender_id: "local-scout".into(),
        transport: TransportKind::SimulatedLocalFile,
        sealed,
        local_file: Some(local_file),
        plaintext_digest_hex: digest,
    };

    {
        let mut guard = mesh_state()?;
        wire_buf.with_sensitive_bytes(|wire| guard.outbound.fill(wire))?;
        guard.local_channel.push_back(envelope.clone());
    }

    Ok(envelope)
}

pub fn receive_next() -> Result<Option<MeshEnvelope>, String> {
    let _permit = acquire_operation_permit()?;
    let mut guard = mesh_state()?;
    Ok(guard.local_channel.pop_front())
}

pub fn open_envelope(envelope: &MeshEnvelope) -> Result<EnvelopeBody, String> {
    let _permit = acquire_operation_permit()?;
    let plain = crypto::open_to_plaintext(&envelope.sealed)?;
    if plain.digest_sha256_hex()? != envelope.plaintext_digest_hex {
        return Err("plaintext digest mismatch".into());
    }
    plain.decode_json()
}

pub fn publish_encrypted(
    topic: impl Into<String>,
    payload: serde_json::Value,
) -> Result<MeshEnvelope, String> {
    let _permit = acquire_operation_permit()?;

    let body = EnvelopeBody {
        inner: payload,
        scout_snapshot: None,
    };
    let plaintext = EphemeralBuffer::from_serializable(&body)?;
    let sealed = crypto::seal_plaintext(&plaintext)?;
    let digest = plaintext.digest_sha256_hex()?;

    let envelope = MeshEnvelope {
        id: Uuid::new_v4(),
        topic: topic.into(),
        created_at_unix: unix_now(),
        sender_id: "local-node".into(),
        transport: TransportKind::InMemoryQueue,
        sealed,
        local_file: None,
        plaintext_digest_hex: digest,
    };

    mesh_state()?.local_channel.push_back(envelope.clone());

    Ok(envelope)
}

pub async fn run_event_loop() -> Result<(), String> {
    eprintln!("[mesh: event loop start]");

    let mut processed = 0_u32;
    while let Some(envelope) = receive_next()? {
        let body = open_envelope(&envelope)?;
        eprintln!(
            "[mesh: processed topic={} id={} scout={}]",
            envelope.topic,
            envelope.id,
            body.scout_snapshot.is_some()
        );
        processed += 1;
    }

    eprintln!("[mesh: event loop complete processed={processed}]");
    Ok(())
}

#[cfg(test)]
fn drain_local_channel() -> Result<(), String> {
    while receive_next()?.is_some() {}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: [u8; 32] = [0x33_u8; 32];

    fn init_mesh_for_test() {
        let _ = crypto::init_session_for_tests(TEST_KEY);
    }

    #[tokio::test(flavor = "current_thread")]
    #[allow(clippy::await_holding_lock)]
    async fn ingest_and_open_scout_handoff() {
        let _guard = apoptosis::test_serial();
        crate::apoptosis::reset_coordinator_for_tests();
        init_mesh_for_test();
        crate::scout::initialize().await.expect("scout");
        initialize().await.expect("mesh");
        drain_local_channel().expect("drain");

        let handoff = crate::scout::run_discovery_cycle()
            .await
            .expect("scout")
            .into_handoff();

        let envelope = ingest_scout_handoff(handoff).expect("ingest");
        assert_eq!(envelope.topic, "scout/encrypted");
        assert!(envelope.local_file.is_some());

        let opened = open_envelope(&envelope).expect("open");
        assert!(opened.scout_snapshot.is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    #[allow(clippy::await_holding_lock)]
    async fn publish_receive_roundtrip() {
        let _guard = apoptosis::test_serial();
        crate::apoptosis::reset_coordinator_for_tests();
        init_mesh_for_test();
        initialize().await.expect("mesh");
        drain_local_channel().expect("drain");

        let published =
            publish_encrypted("telemetry/ping", serde_json::json!({"seq": 1})).expect("publish");
        let received = receive_next().expect("recv").expect("some");
        assert_eq!(published.id, received.id);

        let body = open_envelope(&received).expect("open");
        assert_eq!(body.inner["seq"], 1);
    }

    #[test]
    fn mesh_envelope_carries_local_file_meta() {
        let _guard = apoptosis::test_serial();
        let envelope = MeshEnvelope {
            id: Uuid::new_v4(),
            topic: "test".into(),
            created_at_unix: 0,
            sender_id: "x".into(),
            transport: TransportKind::SimulatedLocalFile,
            sealed: SealedBlob {
                nonce_b64: "AA".into(),
                ciphertext_b64: "BB".into(),
            },
            local_file: Some(LocalFileMeta {
                virtual_path: "offline://a".into(),
                size_bytes: 10,
                checksum_hex: "abc".into(),
            }),
            plaintext_digest_hex: "deadbeef".into(),
        };
        assert!(envelope.local_file.is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    #[allow(clippy::await_holding_lock)]
    async fn run_event_loop_drains_queue() {
        let _guard = apoptosis::test_serial();
        crate::apoptosis::reset_coordinator_for_tests();
        init_mesh_for_test();
        initialize().await.expect("mesh");
        drain_local_channel().expect("drain");

        publish_encrypted("a", serde_json::json!({})).expect("pub");
        publish_encrypted("b", serde_json::json!({})).expect("pub");

        run_event_loop().await.expect("loop");
        assert!(receive_next().expect("recv").is_none());
    }

    #[test]
    fn wipe_on_apoptosis_clears_queue() {
        let _guard = apoptosis::test_serial();
        crate::apoptosis::reset_coordinator_for_tests();
        init_mesh_for_test();
        {
            let mut slot = lock_or_recover(mesh_slot());
            ensure_mesh_viable(&mut slot).expect("mesh viable");
        }

        {
            let mut guard = mesh_state().expect("mesh");
            guard.local_channel.push_back(MeshEnvelope {
                id: Uuid::new_v4(),
                topic: "t".into(),
                created_at_unix: 0,
                sender_id: "s".into(),
                transport: TransportKind::InMemoryQueue,
                sealed: SealedBlob {
                    nonce_b64: "n".into(),
                    ciphertext_b64: "c".into(),
                },
                local_file: None,
                plaintext_digest_hex: "d".into(),
            });
        }

        wipe_on_apoptosis().expect("mesh wipe");
        let slot = lock_or_recover(mesh_slot());
        let state = slot.as_ref().expect("mesh state");
        assert!(state.local_channel.is_empty());
        assert!(!state.outbound.memlock_accepts_writes());
    }

    #[test]
    fn ingest_denied_after_apoptosis() {
        let _guard = apoptosis::test_serial();
        crate::apoptosis::reset_coordinator_for_tests();
        init_mesh_for_test();
        let _ = apoptosis::trigger_apoptosis();
        let sealed = SealedBlob {
            nonce_b64: "n".into(),
            ciphertext_b64: "c".into(),
        };
        let handoff = EncryptedScoutHandoff {
            sealed,
            meta: crate::scout::ScoutReportMeta {
                host_label: "x".into(),
                scanned_at_unix: 0,
                encrypted_bytes: 1,
            },
        };
        assert!(ingest_scout_handoff(handoff).is_err());
    }
}
