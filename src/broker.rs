//! Güvenli işlem aracısı. Ajan ham anahtarı almaz; `ExecuteWithPolicy` gönderir.
//!
//! Anahtar `EphemeralContext` içindeki kilitli tamponda durur. Dış çağrıya yalnızca
//! uç nokta, yük özeti, süreç içi nonce ve bağ özeti gider. Bağ özeti bir MAC
//! veya mTLS değildir; süreç içi IPC/API sınırıdır. `SingleUse` yetkisi taşıyıcı
//! çağrısından önce tüketilir ve panikte `Drop` anahtarı siler. İşlem izni
//! özet ve mühür aşamalarında tutulur; dış taşıyıcı çağrısında tutulmaz. `Partial` veya `Failed`
//! mühür fişte gizlenmez. `ExpiresAt` süresi dolunca kasayı kapatır.
//! `ProviderBound` başka ucu reddeder.
//! `LocalOnly` ağ çağrısına çıkmaz.

#![forbid(unsafe_code)]

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::apoptosis;
use crate::context::{
    AuditStatus, BufferGrant, ContextError, EphemeralContext, LifecycleState, ResourceBudget,
    SecurityPolicy,
};
use crate::exposure::{ExposureError, ExposureTags, LogSanitizer, Scope};

/// Ajanın aracıya ilettiği komut. Ham sır alanı yoktur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecuteWithPolicy {
    pub context_id: Uuid,
    pub target_endpoint: String,
    pub payload_hash: String,
    /// Client token for daemon replay. Not part of the binding digest and not a secret.
    pub idempotency_key: String,
}

/// Taşıyıcının gördüğü çağrı. Anahtar baytları bu yapıda yoktur.
///
/// `binding_digest_hex`, anahtar, uç, yük özeti, `call_nonce` ve zaman damgasının
/// SHA-256 değeridir. Bu bir MAC değildir ve uzak kimlik doğrulaması sağlamaz.
/// Yeniden oynatma sınırı yalnızca bu süreçteki nonce ve damgadır.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedCall<'a> {
    pub target_endpoint: &'a str,
    pub payload_hash: &'a str,
    pub binding_digest_hex: &'a str,
    pub call_nonce: u64,
    pub issued_at_unix_ms: u64,
    /// Opaque client token. It is not mixed into the binding digest.
    pub idempotency_key: &'a str,
}

static CALL_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportReply {
    pub status: u16,
}

/// Bu çağrının mühür sonucu. `Retained` yetkinin açık kaldığı anlamına gelir.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealReport {
    Retained,
    Complete,
    Partial,
    Failed,
}

impl SealReport {
    fn from_status(status: AuditStatus) -> Self {
        match status {
            AuditStatus::Complete => Self::Complete,
            AuditStatus::Partial => Self::Partial,
            AuditStatus::Failed => Self::Failed,
        }
    }

    fn is_failure(self) -> bool {
        matches!(self, Self::Partial | Self::Failed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Owned call material for a provider invocation that runs off the runtime.
///
/// The secret is not in this value. The permit is not held while it is in flight.
pub(crate) struct PendingDispatch {
    pub command: ExecuteWithPolicy,
    pub digest: String,
    pub nonce: u64,
    pub issued_at_unix_ms: u64,
    pub single_use: bool,
}

impl PendingDispatch {
    pub(crate) fn as_call(&self) -> AuthorizedCall<'_> {
        AuthorizedCall {
            target_endpoint: &self.command.target_endpoint,
            payload_hash: &self.command.payload_hash,
            binding_digest_hex: &self.digest,
            call_nonce: self.nonce,
            issued_at_unix_ms: self.issued_at_unix_ms,
            idempotency_key: &self.command.idempotency_key,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionReceipt {
    pub target_endpoint: String,
    pub payload_hash: String,
    pub binding_digest_hex: String,
    pub transport_status: u16,
    /// `Complete` temiz mühürdür. `Partial` ve `Failed` başarı sayılmaz.
    pub seal_report: SealReport,
    pub idempotency_key: String,
}

pub trait SecureTransport {
    fn dispatch(&mut self, call: &AuthorizedCall<'_>) -> Result<TransportReply, BrokerError>;
}

/// Ajan tutamacı. Anahtarı okuyan bir yöntemi yoktur.
pub struct SecureTransactionAgent {
    ctx: EphemeralContext,
    grant: BufferGrant,
    tags: ExposureTags,
    consumed: bool,
    sanitizer: LogSanitizer,
}

impl SecureTransactionAgent {
    pub fn admit(secret: &[u8], tags: ExposureTags) -> Result<Self, BrokerError> {
        tags.validate_for_broker().map_err(BrokerError::from)?;
        if secret.is_empty() {
            return Err(BrokerError::EmptySecret);
        }
        nexus_ephemera_memlock::harden_process_memory()
            .map_err(|err| BrokerError::Memlock(apoptosis::memlock_err_public(err)))?;
        let span = nexus_ephemera_memlock::locked_span_for(secret.len())
            .map_err(|err| BrokerError::Memlock(apoptosis::memlock_err_public(err)))?;
        let max_bytes = span.checked_mul(2).ok_or(BrokerError::Context(
            "locked span does not fit the broker budget",
        ))?;
        let mut ctx = EphemeralContext::open(
            SecurityPolicy::default(),
            ResourceBudget {
                max_bytes,
                timeout: None,
            },
        )
        .map_err(map_context)?;
        let grant = ctx.insert(secret).map_err(map_context)?;
        let mut sanitizer = LogSanitizer::new();
        sanitizer.register(secret).map_err(BrokerError::from)?;
        ctx.charge_auxiliary(span).map_err(|err| {
            sanitizer.wipe();
            map_context(err)
        })?;
        Ok(Self {
            ctx,
            grant,
            tags,
            consumed: false,
            sanitizer,
        })
    }

    pub fn context_id(&self) -> Uuid {
        self.ctx.task_id()
    }

    pub fn lifecycle_state(&self) -> LifecycleState {
        self.ctx.lifecycle_state()
    }

    pub fn allows_plaintext_export(&self) -> bool {
        false
    }

    pub fn sanitize_log(&self, line: &str) -> Result<String, BrokerError> {
        self.sanitizer.sanitize(line).map_err(BrokerError::from)
    }

    pub fn execute(
        &mut self,
        command: ExecuteWithPolicy,
        transport: &mut impl SecureTransport,
    ) -> Result<TransactionReceipt, BrokerError> {
        let pending = self.begin_dispatch(command)?;
        let reply = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            transport.dispatch(&pending.as_call())
        }));
        match reply {
            Ok(reply) => self.end_dispatch(pending, reply),
            Err(payload) => {
                // Seal a single-use authority before the panic leaves this frame.
                let _ = self.end_dispatch(pending, Err(BrokerError::Inconclusive));
                std::panic::resume_unwind(payload);
            }
        }
    }

    /// Checks, digest, and single-use consume. The permit covers only this
    /// section. The provider call runs after the permit drops.
    pub(crate) fn begin_dispatch(
        &mut self,
        command: ExecuteWithPolicy,
    ) -> Result<PendingDispatch, BrokerError> {
        let _permit = apoptosis::acquire_operation_permit().map_err(BrokerError::Memlock)?;
        if command.context_id != self.ctx.task_id() {
            return Err(BrokerError::ContextMismatch);
        }
        if self.ctx.lifecycle_state() != LifecycleState::Active || self.consumed {
            return Err(if self.consumed {
                BrokerError::SingleUseConsumed
            } else {
                BrokerError::Sealed
            });
        }
        if let Some(deadline) = self.tags.expires_at
            && SystemTime::now() >= deadline
        {
            self.wipe_secret();
            return Err(BrokerError::Expired);
        }
        match &self.tags.scope {
            Scope::LocalOnly => return Err(BrokerError::LocalOnlyDenied),
            Scope::ProviderBound { endpoint } if endpoint != &command.target_endpoint => {
                return Err(BrokerError::ProviderMismatch);
            }
            Scope::ProviderBound { .. } => {}
            Scope::Allowlist { endpoints }
                if !endpoints
                    .iter()
                    .any(|endpoint| endpoint == &command.target_endpoint) =>
            {
                return Err(BrokerError::ProviderMismatch);
            }
            Scope::Allowlist { .. } => {}
        }

        let nonce = CALL_NONCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| BrokerError::Sealed)?;
        let issued_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        let digest = match self.binding_digest(&command, nonce, issued_at_unix_ms) {
            Ok(digest) => digest,
            Err(err) => {
                if apoptosis::is_shutting_down() {
                    return Err(self.refuse_engaged(command, String::new()));
                }
                return Err(err);
            }
        };
        if apoptosis::is_shutting_down() {
            return Err(self.refuse_engaged(command, digest));
        }
        let single_use = self.tags.single_use;
        if single_use {
            self.consumed = true;
        }
        Ok(PendingDispatch {
            command,
            digest,
            nonce,
            issued_at_unix_ms,
            single_use,
        })
    }

    /// Seal after the provider returns. A missing permit means apoptosis ran
    /// during the call; the outcome is not a successful receipt.
    pub(crate) fn end_dispatch(
        &mut self,
        pending: PendingDispatch,
        reply: Result<TransportReply, BrokerError>,
    ) -> Result<TransactionReceipt, BrokerError> {
        let PendingDispatch {
            command,
            digest,
            single_use,
            ..
        } = pending;
        let _permit = match apoptosis::acquire_operation_permit() {
            Ok(permit) => permit,
            Err(_) => return Err(self.refuse_engaged(command, digest)),
        };
        let seal_report = if single_use {
            SealReport::from_status(self.settle_secret())
        } else {
            SealReport::Retained
        };
        let transport_status = match reply {
            Ok(reply) => reply.status,
            Err(err) => {
                if seal_report.is_failure() {
                    return Err(BrokerError::CleanupIncomplete(TransactionReceipt {
                        target_endpoint: command.target_endpoint,
                        payload_hash: command.payload_hash,
                        binding_digest_hex: digest,
                        transport_status: 0,
                        seal_report,
                        idempotency_key: command.idempotency_key,
                    }));
                }
                return Err(err);
            }
        };
        let receipt = TransactionReceipt {
            target_endpoint: command.target_endpoint,
            payload_hash: command.payload_hash,
            binding_digest_hex: digest,
            transport_status,
            seal_report,
            idempotency_key: command.idempotency_key,
        };
        if seal_report.is_failure() {
            return Err(BrokerError::CleanupIncomplete(receipt));
        }
        Ok(receipt)
    }

    fn refuse_engaged(&mut self, command: ExecuteWithPolicy, digest: String) -> BrokerError {
        let seal_report = SealReport::from_status(self.settle_secret());
        if seal_report.is_failure() {
            BrokerError::CleanupIncomplete(TransactionReceipt {
                target_endpoint: command.target_endpoint,
                payload_hash: command.payload_hash,
                binding_digest_hex: digest,
                transport_status: 0,
                seal_report,
                idempotency_key: command.idempotency_key,
            })
        } else {
            BrokerError::ApoptosisEngaged
        }
    }

    fn binding_digest(
        &mut self,
        command: &ExecuteWithPolicy,
        nonce: u64,
        issued_at_unix_ms: u64,
    ) -> Result<String, BrokerError> {
        let endpoint = command.target_endpoint.clone();
        let payload_hash = command.payload_hash.clone();
        let grant = self.grant;
        self.ctx
            .with_buffer(&grant, |key| {
                digest_hex(key, &endpoint, &payload_hash, nonce, issued_at_unix_ms)
            })
            .map_err(map_context)
    }

    fn settle_secret(&mut self) -> AuditStatus {
        self.consumed = true;
        let failed = self.sanitizer.wipe();
        self.ctx.note_external_quarantine(failed);
        self.ctx.seal().final_status
    }

    fn wipe_secret(&mut self) {
        let _ = self.settle_secret();
    }

    #[cfg(test)]
    fn fail_next_seal_for_tests(&mut self) {
        self.ctx.note_external_quarantine(1);
    }
}

impl fmt::Display for SecureTransactionAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecureTransactionAgent([REDACTED])")
    }
}

impl fmt::Debug for SecureTransactionAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureTransactionAgent")
            .field("context_id", &self.ctx.task_id())
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SecureTransactionAgent {
    fn drop(&mut self) {
        self.wipe_secret();
    }
}

fn digest_hex(
    key: &[u8],
    endpoint: &str,
    payload_hash: &str,
    nonce: u64,
    issued_at_unix_ms: u64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key);
    // Versioned, length-prefixed fields. `ab`+`c` and `a`+`bc` no longer collide.
    hasher.update(b"v1");
    write_len_prefixed(&mut hasher, endpoint.as_bytes());
    write_len_prefixed(&mut hasher, payload_hash.as_bytes());
    hasher.update(nonce.to_le_bytes());
    hasher.update(issued_at_unix_ms.to_le_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 0x0f) as usize] as char);
    }
    hex
}

fn write_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    hasher.update(len.to_le_bytes());
    hasher.update(bytes);
}

const HEX: &[u8; 16] = b"0123456789abcdef";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerError {
    ContextMismatch,
    Expired,
    SingleUseConsumed,
    LocalOnlyDenied,
    ProviderMismatch,
    Sealed,
    EmptySecret,
    EmptyEndpoint,
    PlaintextExportForbidden,
    Transport(&'static str),
    Context(&'static str),
    Memlock(String),
    ApoptosisEngaged,
    /// The provider outcome is unknown. Preserve a reservation before retrying.
    Inconclusive,
    CleanupIncomplete(TransactionReceipt),
}

impl From<ExposureError> for BrokerError {
    fn from(err: ExposureError) -> Self {
        match err {
            ExposureError::EmptySecret => Self::EmptySecret,
            ExposureError::EmptyEndpoint => Self::EmptyEndpoint,
            ExposureError::PlaintextExportForbidden => Self::PlaintextExportForbidden,
            ExposureError::WipeFailed => Self::Sealed,
            ExposureError::Memlock(message) => Self::Memlock(message),
        }
    }
}

fn map_context(err: ContextError) -> BrokerError {
    match err {
        ContextError::Sealed => BrokerError::Sealed,
        ContextError::Expired => BrokerError::Expired,
        ContextError::Quarantined => BrokerError::Sealed,
        ContextError::Failed => BrokerError::Sealed,
        ContextError::PolicyRejected(_) => BrokerError::PlaintextExportForbidden,
        ContextError::Memlock(message) => BrokerError::Memlock(message),
        ContextError::BudgetExceeded { .. }
        | ContextError::UnknownBuffer
        | ContextError::ContextMismatch => BrokerError::Context("context rejected buffer access"),
    }
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContextMismatch => write!(f, "broker: context mismatch"),
            Self::Expired => write!(f, "broker: authority expired"),
            Self::SingleUseConsumed => write!(f, "broker: single-use authority consumed"),
            Self::LocalOnlyDenied => write!(f, "broker: local-only secret cannot leave the host"),
            Self::ProviderMismatch => write!(f, "broker: endpoint is outside the provider binding"),
            Self::Sealed => write!(f, "broker: secret context is sealed"),
            Self::EmptySecret => write!(f, "broker: empty secret"),
            Self::EmptyEndpoint => write!(f, "broker: empty endpoint"),
            Self::PlaintextExportForbidden => write!(f, "broker: plaintext export is forbidden"),
            Self::Transport(msg) => write!(f, "broker transport: {msg}"),
            Self::Context(msg) => write!(f, "broker context: {msg}"),
            Self::Memlock(msg) => write!(f, "broker memlock: {msg}"),
            Self::ApoptosisEngaged => {
                write!(f, "broker: apoptosis engaged before dispatch")
            }
            Self::Inconclusive => write!(f, "broker: provider outcome is inconclusive"),
            Self::CleanupIncomplete(receipt) => write!(
                f,
                "broker: cleanup {:?} after transport {}",
                receipt.seal_report, receipt.transport_status
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apoptosis;
    use std::time::Duration;
    use zeroize::Zeroize;

    struct OkTransport;
    impl SecureTransport for OkTransport {
        fn dispatch(&mut self, call: &AuthorizedCall<'_>) -> Result<TransportReply, BrokerError> {
            assert!(!call.binding_digest_hex.contains("sk-"));
            assert!(!call.payload_hash.is_empty());
            Ok(TransportReply { status: 200 })
        }
    }

    struct PanicTransport;
    impl SecureTransport for PanicTransport {
        fn dispatch(&mut self, _: &AuthorizedCall<'_>) -> Result<TransportReply, BrokerError> {
            panic!("transport must not see a rejected call");
        }
    }

    struct BoomTransport;
    impl SecureTransport for BoomTransport {
        fn dispatch(&mut self, _: &AuthorizedCall<'_>) -> Result<TransportReply, BrokerError> {
            panic!("transport failed mid-dispatch");
        }
    }

    fn command(agent: &SecureTransactionAgent, endpoint: &str) -> ExecuteWithPolicy {
        ExecuteWithPolicy {
            context_id: agent.context_id(),
            target_endpoint: endpoint.into(),
            payload_hash: "payload-hash".into(),
            idempotency_key: "broker-test".into(),
        }
    }

    /// Tehdit: ajan "anahtarı ver" der. Sınır: fiş ve görüntü sır içermez;
    /// `SingleUse` işlem bitince kasayı kapatır.
    #[test]
    fn single_use_execute_hides_key_and_wipes() {
        let _guard = apoptosis::test_serial();
        apoptosis::reset_coordinator_for_tests();

        let canary = "sk-broker-canary-42";
        let mut agent = SecureTransactionAgent::admit(
            canary.as_bytes(),
            ExposureTags::provider_bound("https://provider.example/charge", true, None)
                .expect("tags"),
        )
        .expect("admit");
        let rendered = format!("{agent} {agent:?}");
        assert!(!agent.allows_plaintext_export());
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains(canary));
        let clean = agent
            .sanitize_log("bearer sk-broker-canary-42")
            .expect("redact");
        assert_eq!(clean, "bearer [REDACTED]");

        let first = command(&agent, "https://provider.example/charge");
        let receipt = agent.execute(first, &mut OkTransport).expect("execute");
        assert_eq!(receipt.transport_status, 200);
        assert_eq!(receipt.seal_report, SealReport::Complete);
        assert!(!receipt.binding_digest_hex.contains(canary));
        assert_eq!(agent.lifecycle_state(), LifecycleState::Closed);
        let second = command(&agent, "https://provider.example/charge");
        assert_eq!(
            agent.execute(second, &mut PanicTransport),
            Err(BrokerError::SingleUseConsumed)
        );
    }

    /// Tehdit: `LocalOnly` sır uzak uca gider; `ProviderBound` başka hostta kullanılır.
    #[test]
    fn local_only_and_provider_binding_reject_before_transport() {
        let _guard = apoptosis::test_serial();
        apoptosis::reset_coordinator_for_tests();

        let mut local =
            SecureTransactionAgent::admit(b"local-only-secret", ExposureTags::local_only(None))
                .expect("local");
        let local_call = command(&local, "https://anywhere.example");
        assert_eq!(
            local.execute(local_call, &mut PanicTransport),
            Err(BrokerError::LocalOnlyDenied)
        );

        let mut bound = SecureTransactionAgent::admit(
            b"provider-bound-secret",
            ExposureTags::provider_bound("https://provider.example/charge", false, None)
                .expect("tags"),
        )
        .expect("bound");
        let wrong = command(&bound, "https://other.example");
        assert_eq!(
            bound.execute(wrong, &mut PanicTransport),
            Err(BrokerError::ProviderMismatch)
        );
        assert_eq!(bound.lifecycle_state(), LifecycleState::Active);
    }

    /// Tehdit: süresi dolmuş yetki anahtarı bellekte tutup çağrı yapar.
    #[test]
    fn expired_authority_seals_without_dispatch() {
        let _guard = apoptosis::test_serial();
        apoptosis::reset_coordinator_for_tests();

        let expired = SystemTime::now()
            .checked_sub(Duration::from_secs(60))
            .expect("past");
        let mut agent = SecureTransactionAgent::admit(
            b"expired-secret",
            ExposureTags::provider_bound("https://provider.example/charge", true, Some(expired))
                .expect("tags"),
        )
        .expect("admit");
        let call = command(&agent, "https://provider.example/charge");
        assert_eq!(
            agent.execute(call, &mut PanicTransport),
            Err(BrokerError::Expired)
        );
        assert_eq!(agent.lifecycle_state(), LifecycleState::Closed);
    }

    /// Tehdit: taşıyıcı panikler ve `SingleUse` yetkisi ile anahtar durur.
    /// Sınır: yetki çağrıdan önce tüketilir; `Drop` kasayı kapatır.
    #[test]
    fn single_use_panic_consumes_authority() {
        let _guard = apoptosis::test_serial();
        apoptosis::reset_coordinator_for_tests();

        let mut agent = SecureTransactionAgent::admit(
            b"panic-secret",
            ExposureTags::provider_bound("https://provider.example/charge", true, None)
                .expect("tags"),
        )
        .expect("admit");
        let cmd = command(&agent, "https://provider.example/charge");
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = agent.execute(cmd, &mut BoomTransport);
        }));
        assert!(caught.is_err());
        assert_eq!(agent.lifecycle_state(), LifecycleState::Closed);
        let second = command(&agent, "https://provider.example/charge");
        assert_eq!(
            agent.execute(second, &mut PanicTransport),
            Err(BrokerError::SingleUseConsumed)
        );
    }

    /// Tehdit: yavaş sağlayıcı global wipe'ı izin arkasında bekletir.
    /// Sınır: taşıyıcı çağrısı izni tutmaz; wipe dispatch bitmeden terminal olabilir.
    #[test]
    fn dispatch_does_not_hold_the_wipe_permit() {
        let _guard = apoptosis::test_serial();
        apoptosis::reset_coordinator_for_tests();

        let mut agent = SecureTransactionAgent::admit(
            b"permit-holds-across-dispatch",
            ExposureTags::provider_bound("https://provider.example/charge", true, None)
                .expect("tags"),
        )
        .expect("admit");
        let cmd = command(&agent, "https://provider.example/charge");
        let mut transport = ApoptosisDuringDispatch::default();
        let outcome = agent.execute(cmd, &mut transport);
        assert!(
            transport
                .wipe_finished
                .load(std::sync::atomic::Ordering::SeqCst),
            "wipe stayed blocked for the whole provider call"
        );
        assert!(
            outcome.is_err(),
            "a finished wipe is not a successful receipt"
        );
        assert_eq!(agent.lifecycle_state(), LifecycleState::Closed);
        let joined = transport
            .joiner
            .take()
            .expect("wipe thread")
            .join()
            .expect("join");
        assert!(joined.is_ok());
    }

    /// Tehdit: taşıyıcı 200 döner ve kısmi mühür başarı gibi yutulur.
    /// Sınır: fiş `Partial` taşır ve `execute` hata döner.
    #[test]
    fn partial_seal_is_not_a_successful_receipt() {
        let _guard = apoptosis::test_serial();
        apoptosis::reset_coordinator_for_tests();

        let mut agent = SecureTransactionAgent::admit(
            b"partial-secret",
            ExposureTags::provider_bound("https://provider.example/charge", true, None)
                .expect("tags"),
        )
        .expect("admit");
        agent.fail_next_seal_for_tests();
        let cmd = command(&agent, "https://provider.example/charge");
        let err = agent.execute(cmd, &mut OkTransport).expect_err("partial");
        let rendered = err.to_string();
        assert!(!rendered.contains("partial-secret"));
        match err {
            BrokerError::CleanupIncomplete(receipt) => {
                assert_eq!(receipt.seal_report, SealReport::Partial);
                assert_eq!(receipt.transport_status, 200);
                assert!(!receipt.binding_digest_hex.is_empty());
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(agent.lifecycle_state(), LifecycleState::Quarantined);
        let _ = apoptosis::wait_apoptosis_complete(Duration::from_secs(10));
    }

    #[test]
    fn inconclusive_provider_does_not_hide_partial_cleanup() {
        let _guard = apoptosis::test_serial();
        apoptosis::reset_coordinator_for_tests();
        let mut agent = SecureTransactionAgent::admit(
            b"partial-secret",
            ExposureTags::provider_bound("https://provider.example/charge", true, None)
                .expect("tags"),
        )
        .expect("admit");
        let cmd = command(&agent, "https://provider.example/charge");
        let pending = agent.begin_dispatch(cmd).expect("pending");
        agent.fail_next_seal_for_tests();
        assert!(
            matches!(agent.end_dispatch(pending, Err(BrokerError::Inconclusive)), Err(BrokerError::CleanupIncomplete(receipt)) if receipt.seal_report == SealReport::Partial)
        );
        let _ = apoptosis::wait_apoptosis_complete(Duration::from_secs(10));
    }

    #[test]
    fn split_dispatch_cannot_bypass_single_use_or_provider_policy() {
        let _guard = apoptosis::test_serial();
        apoptosis::reset_coordinator_for_tests();
        let mut agent = SecureTransactionAgent::admit(
            b"policy-key",
            ExposureTags::provider_bound("https://provider.example/charge", true, None)
                .expect("tags"),
        )
        .expect("admit");
        let wrong = command(&agent, "https://other.example/charge");
        assert!(matches!(
            agent.begin_dispatch(wrong),
            Err(BrokerError::ProviderMismatch)
        ));
        let first = command(&agent, "https://provider.example/charge");
        let pending = agent.begin_dispatch(first).expect("first");
        let second = command(&agent, "https://provider.example/charge");
        assert!(matches!(
            agent.begin_dispatch(second),
            Err(BrokerError::SingleUseConsumed)
        ));
        let _ = agent.end_dispatch(pending, Err(BrokerError::Inconclusive));
    }

    /// Tehdit: gerçekçi istek arabelleği sır taşır veya kısmi mühür 200 ile yutulur.
    /// Sınır: gövde sıfırlanır ve `execute` `CleanupIncomplete` döner.
    #[test]
    fn realistic_partial_seal_zeroizes_request_and_returns_cleanup_incomplete() {
        let _guard = apoptosis::test_serial();
        apoptosis::reset_coordinator_for_tests();

        let mut agent = SecureTransactionAgent::admit(
            b"partial-realistic-secret",
            ExposureTags::provider_bound("https://provider.example/charge", true, None)
                .expect("tags"),
        )
        .expect("admit");
        agent.fail_next_seal_for_tests();
        let cmd = command(&agent, "https://provider.example/charge");
        let mut transport = ZeroizingHttpTransport::default();
        let err = agent
            .execute(cmd, &mut transport)
            .expect_err("partial seal");
        assert!(transport.wiped);
        assert!(!err.to_string().contains("partial-realistic-secret"));
        match err {
            BrokerError::CleanupIncomplete(receipt) => {
                assert_eq!(receipt.seal_report, SealReport::Partial);
                assert_eq!(receipt.transport_status, 201);
                assert_eq!(classify_seal(receipt.seal_report), CleanupView::Incomplete);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(agent.lifecycle_state(), LifecycleState::Quarantined);
        let _ = apoptosis::wait_apoptosis_complete(Duration::from_secs(10));
    }

    struct ApoptosisDuringDispatch {
        wipe_finished: std::sync::Arc<std::sync::atomic::AtomicBool>,
        joiner: Option<
            std::thread::JoinHandle<Result<apoptosis::WipeStatus, apoptosis::ApoptosisError>>,
        >,
    }

    impl Default for ApoptosisDuringDispatch {
        fn default() -> Self {
            Self {
                wipe_finished: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                joiner: None,
            }
        }
    }

    impl SecureTransport for ApoptosisDuringDispatch {
        fn dispatch(&mut self, _: &AuthorizedCall<'_>) -> Result<TransportReply, BrokerError> {
            let flag = std::sync::Arc::clone(&self.wipe_finished);
            self.joiner = Some(std::thread::spawn(apoptosis::trigger_apoptosis));
            let start = std::time::Instant::now();
            while !apoptosis::wipe_status().is_terminal()
                && start.elapsed() < Duration::from_secs(2)
            {
                std::thread::yield_now();
            }
            let finished = apoptosis::wipe_status().is_terminal();
            flag.store(finished, std::sync::atomic::Ordering::SeqCst);
            assert!(finished, "provider dispatch still blocked the global wipe");
            Ok(TransportReply { status: 202 })
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum CleanupView {
        Usable,
        Incomplete,
    }

    fn classify_seal(report: SealReport) -> CleanupView {
        match report {
            SealReport::Retained | SealReport::Complete => CleanupView::Usable,
            SealReport::Partial | SealReport::Failed => CleanupView::Incomplete,
        }
    }

    #[test]
    fn failed_seal_is_not_classified_as_success() {
        assert_eq!(classify_seal(SealReport::Failed), CleanupView::Incomplete);
        assert_eq!(classify_seal(SealReport::Partial), CleanupView::Incomplete);
        assert_eq!(classify_seal(SealReport::Complete), CleanupView::Usable);
        assert_eq!(classify_seal(SealReport::Retained), CleanupView::Usable);
    }

    #[derive(Default)]
    struct ZeroizingHttpTransport {
        wiped: bool,
    }

    impl SecureTransport for ZeroizingHttpTransport {
        fn dispatch(&mut self, call: &AuthorizedCall<'_>) -> Result<TransportReply, BrokerError> {
            let mut body = http_request_bytes(call);
            assert!(body.iter().any(|byte| *byte != 0));
            assert!(
                !body
                    .windows(b"partial-realistic-secret".len())
                    .any(|window| { window == b"partial-realistic-secret" })
            );
            body.zeroize();
            assert!(body.iter().all(|byte| *byte == 0));
            self.wiped = true;
            Ok(TransportReply { status: 201 })
        }
    }

    fn http_request_bytes(call: &AuthorizedCall<'_>) -> Vec<u8> {
        format!(
            "POST {} HTTP/1.1\r\nx-nonce: {}\r\nx-issued-at: {}\r\nx-binding: {}\r\n\r\n{}",
            call.target_endpoint,
            call.call_nonce,
            call.issued_at_unix_ms,
            call.binding_digest_hex,
            call.payload_hash
        )
        .into_bytes()
    }
}
