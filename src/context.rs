//! Görev ömürlü kasa: `EphemeralContext`.
//!
//! # Tehdit sınırı (Sensitive-Memory Lifecycle Protection)
//! Kapsam içi: aynı süreçte context izolasyonu, bütçe aşımında doğrulanan
//! sıfırlama, kısmi kilit açmada karantina ve apoptosis.
//! Kapsam dışı: cold boot, DMA, fiziksel DRAM ve ayrıcalıklı `ptrace`.
//! `open` süreç sertleştirmesini zorunlu kılar. `mlock` bu okumaları kapatmaz.
//! Kapanmış bir context yeniden açılmaz. Bu modül "sıfır iz" iddia etmez;
//! yönetilen bölgelerde sınırlı kalıcılık ve doğrulanan wipe sağlar.
//! Ayrıntı: `docs/data_flow.md`.

#![forbid(unsafe_code)]

use std::fmt;
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::apoptosis::{self, EphemeralBuffer};

/// Platformdan beklenen kilit ve advice duruşu.
///
/// `mlock` bu sürümde zorunludur. `advise_dontdump` / `advise_dontfork`
/// Linux `madvise` bayraklarının sözleşmesidir; uygulayan katman `memlock`'tur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityPolicy {
    pub require_mlock: bool,
    pub advise_dontdump: bool,
    pub advise_dontfork: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            require_mlock: true,
            advise_dontdump: true,
            advise_dontfork: true,
        }
    }
}

/// Yönetilen düz metin için üst sınır. `timeout == None` süre sınırı koymaz.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceBudget {
    pub max_bytes: usize,
    pub timeout: Option<Duration>,
}

impl Default for ResourceBudget {
    fn default() -> Self {
        Self {
            max_bytes: 64 * 1024,
            timeout: None,
        }
    }
}

/// Context bir kez `Active` dışına çıkınca geri dönmez.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    Active,
    Closed,
    Quarantined,
    Failed,
}

impl LifecycleState {
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Active)
    }
}

/// Kapanış nedeni. Düz metin veya özet taşımaz.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosingReason {
    ExplicitSeal,
    BudgetExceeded,
    Expired,
    Drop,
    UnlockFailure,
    AllocationFailed,
}

/// Denetim kapanış durumu. Sır veya plaintext hash içermez.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditStatus {
    Complete,
    Partial,
    Failed,
}

/// Bu context'te tutan kilitlerden türetilir. Boş kasa `mlock: false` raporlar.
/// Ayrıcalıklı `ptrace` ve donanım okuması kapsam dışıdır.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformProtections {
    pub mlock: bool,
    pub madv_dontdump: bool,
    pub madv_dontfork: bool,
}

/// Context kapanışının denetlenebilir özeti.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditSummaryReport {
    pub context_id: Uuid,
    pub closing_reason: ClosingReason,
    pub managed_buffers_count: usize,
    pub total_bytes_wiped: usize,
    pub quarantined_allocations_count: usize,
    pub platform_protections_active: PlatformProtections,
    pub final_status: AuditStatus,
}

impl fmt::Display for AuditSummaryReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "context_id={} closing_reason={:?} managed_buffers_count={} total_bytes_wiped={} quarantined_allocations_count={} platform_protections_active={:?} final_status={:?}",
            self.context_id,
            self.closing_reason,
            self.managed_buffers_count,
            self.total_bytes_wiped,
            self.quarantined_allocations_count,
            self.platform_protections_active,
            self.final_status
        )
    }
}

fn status_for_state(state: LifecycleState) -> AuditStatus {
    match state {
        LifecycleState::Quarantined => AuditStatus::Partial,
        LifecycleState::Failed => AuditStatus::Failed,
        LifecycleState::Active | LifecycleState::Closed => AuditStatus::Complete,
    }
}

fn observed_protections(
    harden_ok: bool,
    locks_succeeded: u32,
    policy: &SecurityPolicy,
) -> PlatformProtections {
    let locked = harden_ok && locks_succeeded > 0 && policy.require_mlock;
    PlatformProtections {
        mlock: locked,
        madv_dontdump: locked && cfg!(target_os = "linux") && policy.advise_dontdump,
        madv_dontfork: locked && cfg!(target_os = "linux") && policy.advise_dontfork,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextError {
    Sealed,
    Quarantined,
    Failed,
    Expired,
    BudgetExceeded { requested: usize, limit: usize },
    UnknownBuffer,
    ContextMismatch,
    PolicyRejected(&'static str),
    Memlock(String),
}

/// Yalnızca sahibi olan context'in okuyabildiği tampon bileti. Düz metin taşımaz.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferGrant {
    context_id: Uuid,
    buffer_id: u64,
}

struct ManagedBuffer {
    id: u64,
    byte_len: usize,
    buf: EphemeralBuffer,
}

/// Görev kasası. Statik oturum değildir; her örnek kendi tamponlarına sahiptir.
pub struct EphemeralContext {
    task_id: Uuid,
    security_policy: SecurityPolicy,
    resource_budget: ResourceBudget,
    buffers: Vec<ManagedBuffer>,
    next_buffer_id: u64,
    bytes_allocated: usize,
    locks_succeeded: u32,
    harden_ok: bool,
    external_quarantine: usize,
    lifecycle_state: LifecycleState,
    opened_at: Instant,
    last_audit: Option<AuditSummaryReport>,
}

impl EphemeralContext {
    pub fn open(policy: SecurityPolicy, budget: ResourceBudget) -> Result<Self, ContextError> {
        if !policy.require_mlock {
            return Err(ContextError::PolicyRejected(
                "unlocked secret retention is outside Sensitive-Memory Lifecycle Protection",
            ));
        }
        nexus_ephemera_memlock::harden_process_memory()
            .map_err(|err| ContextError::Memlock(apoptosis::memlock_err_public(err)))?;
        let _permit = apoptosis::acquire_operation_permit().map_err(ContextError::Memlock)?;
        Ok(Self {
            task_id: Uuid::new_v4(),
            security_policy: policy,
            resource_budget: budget,
            buffers: Vec::new(),
            next_buffer_id: 1,
            bytes_allocated: 0,
            locks_succeeded: 0,
            harden_ok: true,
            external_quarantine: 0,
            lifecycle_state: LifecycleState::Active,
            opened_at: Instant::now(),
            last_audit: None,
        })
    }

    pub fn task_id(&self) -> Uuid {
        self.task_id
    }

    pub fn security_policy(&self) -> SecurityPolicy {
        self.security_policy
    }

    pub fn resource_budget(&self) -> ResourceBudget {
        self.resource_budget
    }

    pub fn lifecycle_state(&self) -> LifecycleState {
        self.lifecycle_state
    }

    pub fn bytes_allocated(&self) -> usize {
        self.bytes_allocated
    }

    pub fn managed_buffer_count(&self) -> usize {
        self.buffers.len()
    }

    /// Terminal durumdan `Active`'e dönüş yoktur.
    pub fn reopen(&mut self) -> Result<(), ContextError> {
        match self.lifecycle_state {
            LifecycleState::Active => Ok(()),
            LifecycleState::Closed => Err(ContextError::Sealed),
            LifecycleState::Quarantined => Err(ContextError::Quarantined),
            LifecycleState::Failed => Err(ContextError::Failed),
        }
    }

    pub fn insert(&mut self, data: &[u8]) -> Result<BufferGrant, ContextError> {
        self.ensure_mutable()?;
        let charge = match nexus_ephemera_memlock::locked_span_for(data.len()) {
            Ok(span) => span,
            Err(err) => {
                self.fail_allocation();
                return Err(ContextError::Memlock(apoptosis::memlock_err_public(err)));
            }
        };
        let Some(next) = self.bytes_allocated.checked_add(charge) else {
            let limit = self.resource_budget.max_bytes;
            self.close_with(ClosingReason::BudgetExceeded);
            return Err(ContextError::BudgetExceeded {
                requested: charge,
                limit,
            });
        };
        if next > self.resource_budget.max_bytes {
            let limit = self.resource_budget.max_bytes;
            self.close_with(ClosingReason::BudgetExceeded);
            return Err(ContextError::BudgetExceeded {
                requested: charge,
                limit,
            });
        }
        let buf = match EphemeralBuffer::from_bytes(data) {
            Ok(buf) => buf,
            Err(err) => {
                self.fail_allocation();
                return Err(ContextError::Memlock(err));
            }
        };
        let id = self.next_buffer_id;
        self.next_buffer_id = self.next_buffer_id.saturating_add(1);
        self.bytes_allocated = next;
        self.locks_succeeded = self.locks_succeeded.saturating_add(1);
        self.buffers.push(ManagedBuffer {
            id,
            byte_len: data.len(),
            buf,
        });
        Ok(BufferGrant {
            context_id: self.task_id,
            buffer_id: id,
        })
    }

    /// Sanitizer kopyası gibi context dışı kilitli tahsisi bütçeye yazar.
    pub(crate) fn charge_auxiliary(&mut self, bytes: usize) -> Result<(), ContextError> {
        self.ensure_mutable()?;
        let Some(next) = self.bytes_allocated.checked_add(bytes) else {
            let limit = self.resource_budget.max_bytes;
            self.close_with(ClosingReason::BudgetExceeded);
            return Err(ContextError::BudgetExceeded {
                requested: bytes,
                limit,
            });
        };
        if next > self.resource_budget.max_bytes {
            let limit = self.resource_budget.max_bytes;
            self.close_with(ClosingReason::BudgetExceeded);
            return Err(ContextError::BudgetExceeded {
                requested: bytes,
                limit,
            });
        }
        self.bytes_allocated = next;
        Ok(())
    }

    pub(crate) fn note_external_quarantine(&mut self, count: usize) {
        self.external_quarantine = self.external_quarantine.saturating_add(count);
    }

    pub fn with_buffer<R>(
        &mut self,
        grant: &BufferGrant,
        f: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, ContextError> {
        if grant.context_id != self.task_id {
            return Err(ContextError::ContextMismatch);
        }
        self.ensure_mutable()?;
        let _permit = apoptosis::acquire_operation_permit().map_err(ContextError::Memlock)?;
        let managed = self
            .buffers
            .iter()
            .find(|buf| buf.id == grant.buffer_id)
            .ok_or(ContextError::UnknownBuffer)?;
        if managed.byte_len != managed.buf.len() {
            return Err(ContextError::Quarantined);
        }
        managed
            .buf
            .with_sensitive_bytes(|bytes| Ok(f(bytes)))
            .map_err(ContextError::Memlock)
    }

    pub fn audit_report(&self) -> Option<&AuditSummaryReport> {
        self.last_audit.as_ref()
    }

    /// Başarılı wipe `Closed` ve `Complete` bırakır. Kilit açma hatası `Partial` raporu yazar.
    pub fn seal(&mut self) -> AuditSummaryReport {
        self.close_with(ClosingReason::ExplicitSeal)
    }

    fn close_with(&mut self, reason: ClosingReason) -> AuditSummaryReport {
        if self.lifecycle_state != LifecycleState::Active {
            return self.last_audit.clone().unwrap_or_else(|| {
                self.build_report(reason, 0, 0, 0, status_for_state(self.lifecycle_state))
            });
        }
        let managed = self.buffers.len();
        let bytes = self.bytes_allocated;
        let quarantined = self
            .wipe_and_count()
            .saturating_add(self.external_quarantine);
        let (status, reason) = if quarantined > 0 {
            self.enter_quarantine();
            (AuditStatus::Partial, ClosingReason::UnlockFailure)
        } else if reason == ClosingReason::AllocationFailed {
            self.lifecycle_state = LifecycleState::Failed;
            (AuditStatus::Failed, reason)
        } else {
            self.lifecycle_state = LifecycleState::Closed;
            (AuditStatus::Complete, reason)
        };
        let report = self.build_report(reason, managed, bytes, quarantined, status);
        self.last_audit = Some(report.clone());
        report
    }

    fn build_report(
        &self,
        reason: ClosingReason,
        managed: usize,
        bytes: usize,
        quarantined: usize,
        status: AuditStatus,
    ) -> AuditSummaryReport {
        AuditSummaryReport {
            context_id: self.task_id,
            closing_reason: reason,
            managed_buffers_count: managed,
            total_bytes_wiped: bytes,
            quarantined_allocations_count: quarantined,
            platform_protections_active: observed_protections(
                self.harden_ok,
                self.locks_succeeded,
                &self.security_policy,
            ),
            final_status: status,
        }
    }

    fn ensure_mutable(&mut self) -> Result<(), ContextError> {
        match self.lifecycle_state {
            LifecycleState::Active => {
                if self.lifetime_exceeded() {
                    self.close_with(ClosingReason::Expired);
                    Err(ContextError::Expired)
                } else {
                    Ok(())
                }
            }
            LifecycleState::Closed => Err(ContextError::Sealed),
            LifecycleState::Quarantined => Err(ContextError::Quarantined),
            LifecycleState::Failed => Err(ContextError::Failed),
        }
    }

    fn lifetime_exceeded(&self) -> bool {
        self.resource_budget
            .timeout
            .is_some_and(|limit| self.opened_at.elapsed() >= limit)
    }

    fn wipe_and_count(&mut self) -> usize {
        let mut quarantined = 0;
        for managed in self.buffers.drain(..) {
            if managed.buf.try_wipe().is_err() {
                quarantined += 1;
            }
        }
        self.bytes_allocated = 0;
        quarantined
    }

    fn fail_allocation(&mut self) {
        let _ = self.close_with(ClosingReason::AllocationFailed);
    }

    fn enter_quarantine(&mut self) {
        self.lifecycle_state = LifecycleState::Quarantined;
        self.bytes_allocated = 0;
        crate::metrics::record_quarantine_trigger();
        let _ = apoptosis::trigger_apoptosis();
    }

    /// OS kilit açma hatası enjekte edilemez; üretimdeki karantina raporuyla aynı alanları yazar.
    #[cfg(test)]
    pub(crate) fn simulate_partial_unlock(&mut self) -> AuditSummaryReport {
        let managed = self.buffers.len();
        let bytes = self.bytes_allocated;
        self.buffers.clear();
        self.bytes_allocated = 0;
        self.enter_quarantine();
        let report = self.build_report(
            ClosingReason::UnlockFailure,
            managed,
            bytes,
            managed,
            AuditStatus::Partial,
        );
        self.last_audit = Some(report.clone());
        report
    }

    /// Tahsis hatasında wipe temiz biterse rapor `Failed` olur; apoptosis tetiklenmez.
    #[cfg(test)]
    pub(crate) fn simulate_allocation_failure(&mut self) -> AuditSummaryReport {
        let managed = self.buffers.len();
        let bytes = self.bytes_allocated;
        self.buffers.clear();
        self.bytes_allocated = 0;
        self.lifecycle_state = LifecycleState::Failed;
        let report = self.build_report(
            ClosingReason::AllocationFailed,
            managed,
            bytes,
            0,
            AuditStatus::Failed,
        );
        self.last_audit = Some(report.clone());
        report
    }
}

impl Drop for EphemeralContext {
    fn drop(&mut self) {
        if self.lifecycle_state == LifecycleState::Active {
            let _ = self.close_with(ClosingReason::Drop);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span_of(len: usize) -> usize {
        nexus_ephemera_memlock::locked_span_for(len).expect("page span")
    }

    fn fresh() -> EphemeralContext {
        EphemeralContext::open(
            SecurityPolicy::default(),
            ResourceBudget {
                max_bytes: span_of(64).saturating_mul(4),
                timeout: None,
            },
        )
        .expect("open")
    }

    /// Tehdit: `ptrace` veya aynı süreçteki başka bir görev, komşu context'in
    /// düz metnini grant ile okur. Sınır: bilet `task_id` ile bağlıdır.
    /// Cold boot / DMA bu testin kapsamı dışındadır.
    #[test]
    fn isolated_contexts_cannot_read_each_other() {
        let _guard = apoptosis::test_serial();
        apoptosis::reset_coordinator_for_tests();

        let mut left = fresh();
        let mut right = fresh();
        assert_ne!(left.task_id(), right.task_id());

        let left_secret = b"left-context-secret";
        let right_secret = b"right-context-secret";
        let left_grant = left.insert(left_secret).expect("left insert");
        let right_grant = right.insert(right_secret).expect("right insert");

        assert_eq!(
            left.with_buffer(&right_grant, |bytes| bytes.to_vec()),
            Err(ContextError::ContextMismatch)
        );
        assert_eq!(
            right.with_buffer(&left_grant, |bytes| bytes.to_vec()),
            Err(ContextError::ContextMismatch)
        );
        assert_eq!(
            left.with_buffer(&left_grant, |bytes| bytes.to_vec())
                .expect("left read"),
            left_secret
        );
        assert_eq!(
            right
                .with_buffer(&right_grant, |bytes| bytes.to_vec())
                .expect("right read"),
            right_secret
        );
    }

    /// Tehdit: sınırsız tahsis, swap ve core dump penceresini büyütür.
    /// Sınır: `max_bytes` aşımında context kapanır ve yönetilen tampon silinir.
    #[test]
    fn budget_overrun_seals_context_and_wipes() {
        let _guard = apoptosis::test_serial();
        apoptosis::reset_coordinator_for_tests();

        let span = span_of(16);
        let mut ctx = EphemeralContext::open(
            SecurityPolicy::default(),
            ResourceBudget {
                max_bytes: span,
                timeout: None,
            },
        )
        .expect("open");
        let grant = ctx.insert(b"0123456789abcdef").expect("within budget");
        assert_eq!(ctx.bytes_allocated(), span);

        let err = ctx.insert(b"overflow").expect_err("over budget");
        assert_eq!(
            err,
            ContextError::BudgetExceeded {
                requested: span_of(b"overflow".len()),
                limit: span,
            }
        );
        assert_eq!(ctx.lifecycle_state(), LifecycleState::Closed);
        assert_eq!(ctx.bytes_allocated(), 0);
        assert_eq!(ctx.managed_buffer_count(), 0);
        assert_eq!(ctx.with_buffer(&grant, |_| ()), Err(ContextError::Sealed));
        assert_eq!(ctx.reopen(), Err(ContextError::Sealed));
        assert!(ctx.insert(b"again").is_err());
    }

    /// Tehdit: kısmi `munlock` / `VirtualUnlock` kilitli kirli sayfa bırakır.
    /// Sınır: context `Quarantined` olur, yeniden açılmaz, apoptosis tetiklenir.
    /// Fiziksel DRAM okuma kapsam dışıdır.
    #[test]
    fn partial_unlock_quarantines_and_blocks_reopen() {
        let _guard = apoptosis::test_serial();
        apoptosis::reset_coordinator_for_tests();

        let mut ctx = fresh();
        let _grant = ctx.insert(b"unlock-fail").expect("insert");
        let report = ctx.simulate_partial_unlock();
        assert_eq!(report.final_status, AuditStatus::Partial);
        assert_eq!(report.closing_reason, ClosingReason::UnlockFailure);
        assert_eq!(report.quarantined_allocations_count, 1);
        assert_eq!(report.total_bytes_wiped, span_of(b"unlock-fail".len()));
        assert!(!format!("{report}").contains("unlock-fail"));

        assert_eq!(ctx.lifecycle_state(), LifecycleState::Quarantined);
        assert!(apoptosis::wipe_status().is_terminal() || apoptosis::is_shutting_down());
        assert_eq!(ctx.reopen(), Err(ContextError::Quarantined));
        assert_eq!(ctx.insert(b"nope"), Err(ContextError::Quarantined));
    }

    /// Tehdit: süresi dolan görev, fork veya dump penceresinde sır tutmaya devam eder.
    #[test]
    fn expired_context_seals_instead_of_accepting_more_data() {
        let _guard = apoptosis::test_serial();
        apoptosis::reset_coordinator_for_tests();

        let mut ctx = EphemeralContext::open(
            SecurityPolicy::default(),
            ResourceBudget {
                max_bytes: 32,
                timeout: Some(Duration::from_millis(0)),
            },
        )
        .expect("open");
        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(ctx.insert(b"late"), Err(ContextError::Expired));
        assert_eq!(ctx.lifecycle_state(), LifecycleState::Closed);
        assert_eq!(ctx.reopen(), Err(ContextError::Sealed));
        let report = ctx.audit_report().expect("audit");
        assert_eq!(report.closing_reason, ClosingReason::Expired);
        assert_eq!(report.final_status, AuditStatus::Complete);
    }

    /// Tehdit: kapanış kaydı plaintext veya onun hash'ini denetim günlüğüne yazar.
    /// Sınır: rapor yalnızca kimlik, sayaç ve durum taşır.
    #[test]
    fn audit_report_omits_secret_on_complete_and_failed() {
        let _guard = apoptosis::test_serial();
        apoptosis::reset_coordinator_for_tests();

        let canary = b"audit-canary-secret";
        let mut ctx = fresh();
        let ctx_id = ctx.task_id();
        ctx.insert(canary).expect("insert");
        let report = ctx.seal();
        assert_eq!(report.context_id, ctx_id);
        assert_eq!(report.closing_reason, ClosingReason::ExplicitSeal);
        assert_eq!(report.managed_buffers_count, 1);
        assert_eq!(report.total_bytes_wiped, span_of(canary.len()));
        assert_eq!(report.quarantined_allocations_count, 0);
        assert_eq!(report.final_status, AuditStatus::Complete);
        assert!(report.platform_protections_active.mlock);
        let rendered = format!("{report} {report:?}");
        assert!(!rendered.contains("audit-canary-secret"));

        let mut failed = fresh();
        failed.insert(b"alloc-fail-secret").expect("insert");
        let failed_report = failed.simulate_allocation_failure();
        assert_eq!(failed_report.final_status, AuditStatus::Failed);
        assert_eq!(
            failed_report.closing_reason,
            ClosingReason::AllocationFailed
        );
        assert_eq!(failed_report.quarantined_allocations_count, 0);
        assert!(!format!("{failed_report}").contains("alloc-fail-secret"));
        assert_eq!(failed.lifecycle_state(), LifecycleState::Failed);
    }

    /// Tehdit: hiç kilit alınmadan rapor `mlock: true` der.
    /// Sınır: koruma bayrakları gerçekleşen kilit sayısından gelir.
    #[test]
    fn empty_seal_reports_no_observed_lock() {
        let _guard = apoptosis::test_serial();
        apoptosis::reset_coordinator_for_tests();

        let mut ctx = fresh();
        let report = ctx.seal();
        assert!(!report.platform_protections_active.mlock);
        assert!(!report.platform_protections_active.madv_dontdump);
        assert!(!report.platform_protections_active.madv_dontfork);
        assert_eq!(report.total_bytes_wiped, 0);
        assert_eq!(report.managed_buffers_count, 0);
    }

    /// Tehdit: apoptosis `ENGAGED` olduktan sonra okuma tampon kilidini alır.
    /// Sınır: izin reddedilir; çağrı `Memlock` döner.
    #[test]
    fn read_after_apoptosis_is_denied() {
        let _guard = apoptosis::test_serial();
        apoptosis::reset_coordinator_for_tests();

        let mut ctx = fresh();
        let grant = ctx.insert(b"still-here").expect("insert");
        apoptosis::trigger_apoptosis().expect("apoptosis");
        let err = ctx
            .with_buffer(&grant, |bytes| bytes.to_vec())
            .expect_err("read denied");
        assert!(matches!(err, ContextError::Memlock(_)));
    }
}
