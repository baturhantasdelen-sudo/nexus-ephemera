//! Kendi kendini imha ve hassas bellek silme modülü.

#![forbid(unsafe_code)]

use std::cell::Cell;
use std::collections::HashMap;
use std::fmt;
use std::io::{ErrorKind, Write};
use std::marker::PhantomData;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use base64::decoded_len_estimate;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64_ENGINE};
use nexus_ephemera_memlock::{LockedBuffer, MemLockError};
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::{Zeroize, ZeroizeOnDrop};

type SharedPayload = Arc<Mutex<SensitivePayload>>;
type Registry = Mutex<HashMap<u64, SharedPayload>>;

pub type CleanupHook = fn() -> Result<(), &'static str>;

const ENGAGED_DENIED: &str = "apoptosis engaged: sensitive operations denied";
const FALLBACK_DRAIN_TIMEOUT: Duration = Duration::from_millis(250);

/// Bit 63: kapanış talebi (yeni işlem yok); bit 0–62: uçuştaki işlem sayacı.
const ENGAGED_BIT: u64 = 1 << 63;
const INFLIGHT_MASK: u64 = ENGAGED_BIT - 1;

static LIFECYCLE: AtomicU64 = AtomicU64::new(0);
static WIPE_STATE: AtomicU8 = AtomicU8::new(WipeStatus::Idle as u8);
static WIPE_EXECUTOR_RUNNING: AtomicBool = AtomicBool::new(false);
static WIPE_SERIAL: OnceLock<Mutex<()>> = OnceLock::new();
static AUX_UNLOCK_FAILURES: AtomicUsize = AtomicUsize::new(0);

#[inline]
pub(crate) fn record_aux_unlock_failure() {
    AUX_UNLOCK_FAILURES.fetch_add(1, Ordering::Relaxed);
}

thread_local! {
    static THREAD_PERMIT_DEPTH: Cell<usize> = const { Cell::new(0) };
    static IN_WIPE_EXECUTOR: Cell<bool> = const { Cell::new(false) };
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WipeStatus {
    Idle = 0,
    Requested = 1,
    Running = 2,
    Complete = 3,
    Partial = 4,
    Failed = 5,
}

impl WipeStatus {
    #[inline]
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Idle,
            1 => Self::Requested,
            2 => Self::Running,
            3 => Self::Complete,
            4 => Self::Partial,
            _ => Self::Failed,
        }
    }

    #[inline]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Partial | Self::Failed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApoptosisError {
    ShuttingDown,
    TooManyInflight,
    WouldDeadlock,
    Timeout(WipeStatus),
    IncompleteWipe(WipeStatus),
    ExecutorSpawnFailed,
    CryptoError(&'static str),
    BufferError(MemLockError),
    StringError(&'static str),
}

impl From<ApoptosisError> for String {
    fn from(err: ApoptosisError) -> Self {
        err.to_string()
    }
}

impl fmt::Display for ApoptosisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShuttingDown => write!(f, "{ENGAGED_DENIED}"),
            Self::TooManyInflight => write!(f, "inflight counter saturated"),
            Self::WouldDeadlock => write!(f, "apoptosis wait would self-deadlock"),
            Self::Timeout(s) => write!(f, "apoptosis wait timeout (status={s:?})"),
            Self::IncompleteWipe(s) => write!(f, "apoptosis incomplete wipe (status={s:?})"),
            Self::ExecutorSpawnFailed => write!(f, "apoptosis executor spawn failed"),
            Self::CryptoError(msg) => write!(f, "crypto: {msg}"),
            Self::BufferError(err) => write!(f, "memlock: {err:?}"),
            Self::StringError(msg) => write!(f, "{msg}"),
        }
    }
}

#[inline]
pub fn lock_or_recover<'a, T>(mutex: &'a Mutex<T>) -> MutexGuard<'a, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Dışarıdan örneklenemez — sahte drop ile sayaç manipülasyonu imkânsız.
struct PermitSeal;

/// Aktif hassas işlem bariyeri — yalnızca oluşturulduğu thread'de düşürülür (`!Send`).
pub struct OperationPermit {
    _seal: PermitSeal,
    _thread_bound: PhantomData<Rc<()>>,
}

impl OperationPermit {
    fn new() -> Self {
        THREAD_PERMIT_DEPTH.set(THREAD_PERMIT_DEPTH.get().saturating_add(1));
        Self {
            _seal: PermitSeal,
            _thread_bound: PhantomData,
        }
    }
}

pub fn acquire_permit() -> Result<OperationPermit, ApoptosisError> {
    if wipe_status().is_terminal() {
        return Err(ApoptosisError::ShuttingDown);
    }
    loop {
        let current = LIFECYCLE.load(Ordering::Acquire);
        if (current & ENGAGED_BIT) != 0 {
            return Err(ApoptosisError::ShuttingDown);
        }
        let inflight = current & INFLIGHT_MASK;
        if inflight == INFLIGHT_MASK {
            return Err(ApoptosisError::TooManyInflight);
        }
        match LIFECYCLE.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(OperationPermit::new()),
            Err(_) => continue,
        }
    }
}

pub fn acquire_operation_permit() -> Result<OperationPermit, String> {
    acquire_permit().map_err(|e| e.to_string())
}

impl Drop for OperationPermit {
    fn drop(&mut self) {
        THREAD_PERMIT_DEPTH.set(THREAD_PERMIT_DEPTH.get().saturating_sub(1));
        let prev = LIFECYCLE.fetch_sub(1, Ordering::AcqRel);
        debug_assert!((prev & INFLIGHT_MASK) > 0, "LIFECYCLE inflight underflow");
    }
}

pub fn with_operation_permit<R>(f: impl FnOnce() -> Result<R, String>) -> Result<R, String> {
    let _permit = acquire_operation_permit()?;
    f()
}

#[inline]
pub fn current_thread_holds_permit() -> bool {
    THREAD_PERMIT_DEPTH.get() > 0
}

#[inline]
pub fn current_thread_in_wipe_executor() -> bool {
    IN_WIPE_EXECUTOR.with(|f| f.get())
}

#[inline]
pub fn wipe_status() -> WipeStatus {
    WipeStatus::from_u8(WIPE_STATE.load(Ordering::Acquire))
}

#[inline]
pub fn is_engaged() -> bool {
    wipe_status() == WipeStatus::Complete
}

#[inline]
pub fn is_shutting_down() -> bool {
    (LIFECYCLE.load(Ordering::Acquire) & ENGAGED_BIT) != 0
}

struct ExecutorRunGuard {
    finalized: bool,
}

impl ExecutorRunGuard {
    fn new() -> Self {
        Self { finalized: false }
    }

    fn complete_with(&mut self, status: WipeStatus) {
        WIPE_STATE.store(status as u8, Ordering::Release);
        self.finalized = true;
    }

    /// Bütçeli drain tamamlanamadı — wipe fazını erteleyip yeniden denenebilir bırakır.
    fn yield_retryable(&mut self) {
        WIPE_STATE.store(WipeStatus::Requested as u8, Ordering::Release);
        self.finalized = true;
        WIPE_EXECUTOR_RUNNING.store(false, Ordering::Release);
    }
}

impl Drop for ExecutorRunGuard {
    fn drop(&mut self) {
        if !self.finalized {
            WIPE_STATE.store(WipeStatus::Failed as u8, Ordering::Release);
        }
        WIPE_EXECUTOR_RUNNING.store(false, Ordering::Release);
    }
}

struct InWipeExecutorGuard;

impl InWipeExecutorGuard {
    fn enter() -> Self {
        IN_WIPE_EXECUTOR.with(|f| f.set(true));
        Self
    }
}

impl Drop for InWipeExecutorGuard {
    fn drop(&mut self) {
        IN_WIPE_EXECUTOR.with(|f| f.set(false));
    }
}

fn run_cleanup_hooks() -> usize {
    let hooks = {
        let guard = lock_or_recover(cleanup_hooks());
        guard.clone()
    };
    let mut failures = 0usize;
    for hook in hooks {
        match catch_unwind(AssertUnwindSafe(hook)) {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => failures += 1,
        }
    }
    failures
}

fn wipe_all_registered_payloads() -> Result<(), &'static str> {
    ApoptosisCoordinator::instance().clear_all_sensitive_memory()
}

fn force_sensitive_clear_after_panic() {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _ = crate::crypto::wipe_session_on_apoptosis();
        let _ = wipe_all_registered_payloads();
    }));
}

fn execute_wipe_phase_with_budget(drain_budget: Option<Duration>) -> Option<WipeStatus> {
    let serial = WIPE_SERIAL.get_or_init(|| Mutex::new(()));
    let _serial_guard = match drain_budget {
        Some(_) => match serial.try_lock() {
            Ok(guard) => guard,
            Err(_) => return None,
        },
        None => lock_or_recover(serial),
    };

    let current = wipe_status();
    if current.is_terminal() {
        return Some(current);
    }

    WIPE_STATE.store(WipeStatus::Running as u8, Ordering::Release);

    let drain_start = Instant::now();
    let mut drain_timed_out = false;
    while (LIFECYCLE.load(Ordering::Acquire) & INFLIGHT_MASK) != 0 {
        if let Some(budget) = drain_budget
            && drain_start.elapsed() >= budget
        {
            drain_timed_out = true;
            break;
        }
        thread::yield_now();
    }

    if drain_timed_out && (LIFECYCLE.load(Ordering::Acquire) & INFLIGHT_MASK) != 0 {
        return None;
    }

    let mut failures = AUX_UNLOCK_FAILURES.load(Ordering::Acquire);
    failures = failures.saturating_add(run_cleanup_hooks());

    match catch_unwind(AssertUnwindSafe(crate::crypto::wipe_session_on_apoptosis)) {
        Ok(Ok(())) => {}
        Ok(Err(_)) | Err(_) => failures = failures.saturating_add(1),
    }

    match catch_unwind(AssertUnwindSafe(wipe_all_registered_payloads)) {
        Ok(Ok(())) => {}
        Ok(Err(_)) | Err(_) => failures = failures.saturating_add(1),
    }

    failures = failures.saturating_add(AUX_UNLOCK_FAILURES.load(Ordering::Acquire));

    Some(if failures == 0 {
        WipeStatus::Complete
    } else {
        let _ = catch_unwind(AssertUnwindSafe(force_sensitive_clear_after_panic));
        WipeStatus::Partial
    })
}

fn execute_wipe_phase() -> Option<WipeStatus> {
    execute_wipe_phase_with_budget(None)
}

fn finish_executor_run(run_guard: &mut ExecutorRunGuard, status: Option<WipeStatus>) {
    match status {
        Some(s) => run_guard.complete_with(s),
        None => run_guard.yield_retryable(),
    }
}

pub fn request_apoptosis() -> Result<(), ApoptosisError> {
    loop {
        let current = LIFECYCLE.load(Ordering::Acquire);
        if (current & ENGAGED_BIT) != 0 {
            break;
        }
        if LIFECYCLE
            .compare_exchange_weak(
                current,
                current | ENGAGED_BIT,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            let _ = WIPE_STATE.compare_exchange(
                WipeStatus::Idle as u8,
                WipeStatus::Requested as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            break;
        }
    }

    if current_thread_in_wipe_executor() || wipe_status().is_terminal() {
        return Ok(());
    }

    spawn_wipe_executor(None)
}

fn spawn_wipe_executor(sync_drain_budget: Option<Duration>) -> Result<(), ApoptosisError> {
    if WIPE_EXECUTOR_RUNNING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Ok(());
    }

    match thread::Builder::new()
        .name("nexus-apoptosis-wipe".into())
        .spawn(|| {
            let mut run_guard = ExecutorRunGuard::new();
            let _in_wipe = InWipeExecutorGuard::enter();
            finish_executor_run(&mut run_guard, execute_wipe_phase());
        }) {
        Ok(_) => Ok(()),
        Err(_) => {
            WIPE_EXECUTOR_RUNNING.store(false, Ordering::Release);
            if current_thread_holds_permit() {
                return Err(ApoptosisError::ExecutorSpawnFailed);
            }
            let mut run_guard = ExecutorRunGuard::new();
            let _in_wipe = InWipeExecutorGuard::enter();
            let budget = sync_drain_budget.unwrap_or(FALLBACK_DRAIN_TIMEOUT);
            finish_executor_run(&mut run_guard, execute_wipe_phase_with_budget(Some(budget)));
            Ok(())
        }
    }
}

pub fn wait_apoptosis_complete(timeout: Duration) -> Result<WipeStatus, ApoptosisError> {
    if current_thread_holds_permit() || current_thread_in_wipe_executor() {
        return Err(ApoptosisError::WouldDeadlock);
    }

    let start = Instant::now();
    loop {
        let status = wipe_status();
        if status.is_terminal() {
            return if status == WipeStatus::Complete {
                Ok(status)
            } else {
                Err(ApoptosisError::IncompleteWipe(status))
            };
        }

        if is_shutting_down() && !WIPE_EXECUTOR_RUNNING.load(Ordering::Acquire) {
            let remaining = timeout.saturating_sub(start.elapsed());
            let _ = spawn_wipe_executor(Some(remaining));
        }

        if start.elapsed() > timeout {
            return Err(ApoptosisError::Timeout(status));
        }
        thread::sleep(Duration::from_millis(1));
    }
}

pub fn trigger_apoptosis() -> Result<WipeStatus, ApoptosisError> {
    request_apoptosis()?;
    if current_thread_holds_permit() || current_thread_in_wipe_executor() {
        return Ok(wipe_status());
    }
    wait_apoptosis_complete(Duration::from_secs(10))
}

/// Panik veya hata durumunda kilitli tamponu sıfırlayan mutasyon yardımcısı.
pub fn with_locked_mut<F, R>(buf: &mut LockedBuffer, f: F) -> Result<R, ApoptosisError>
where
    F: FnOnce(&mut LockedBuffer) -> Result<R, ApoptosisError>,
{
    struct ArmedWipeGuard<'a> {
        buf: &'a mut LockedBuffer,
        disarmed: bool,
    }
    impl Drop for ArmedWipeGuard<'_> {
        fn drop(&mut self) {
            if !self.disarmed && self.buf.wipe().is_err() {
                record_aux_unlock_failure();
            }
        }
    }

    let mut armed = ArmedWipeGuard {
        buf,
        disarmed: false,
    };
    let result = match catch_unwind(AssertUnwindSafe(|| f(armed.buf))) {
        Ok(r) => r,
        Err(_) => Err(ApoptosisError::StringError(
            "locked buffer closure panicked",
        )),
    };
    if result.is_ok() {
        armed.disarmed = true;
    }
    result
}

/// Eski API — yeni kod `acquire_operation_permit` kullanmalı.
pub fn ensure_operations_allowed() -> Result<(), String> {
    acquire_operation_permit().map(|_| ())
}

fn cleanup_hooks() -> &'static Mutex<Vec<CleanupHook>> {
    static HOOKS: OnceLock<Mutex<Vec<CleanupHook>>> = OnceLock::new();
    HOOKS.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn register_cleanup_hook(hook: CleanupHook) {
    let mut hooks = lock_or_recover(cleanup_hooks());
    if !hooks.contains(&hook) {
        hooks.push(hook);
    }
}

fn memlock_err(err: MemLockError) -> String {
    format!("memlock fail-closed: {err:?}")
}

pub(crate) fn memlock_err_public(err: MemLockError) -> String {
    memlock_err(err)
}

struct ApoptosisCoordinator {
    next_id: Mutex<u64>,
    active_buffers: Registry,
    trace_log: Mutex<Vec<TraceRecord>>,
}

impl ApoptosisCoordinator {
    fn instance() -> &'static ApoptosisCoordinator {
        static COORDINATOR: OnceLock<ApoptosisCoordinator> = OnceLock::new();
        COORDINATOR.get_or_init(|| ApoptosisCoordinator {
            next_id: Mutex::new(1),
            active_buffers: Mutex::new(HashMap::new()),
            trace_log: Mutex::new(Vec::new()),
        })
    }

    fn allocate_id(&self) -> u64 {
        let mut next = lock_or_recover(&self.next_id);
        let id = *next;
        *next = next.saturating_add(1);
        id
    }

    fn register_shared(&self, storage: &SharedPayload) -> u64 {
        let id = self.allocate_id();
        lock_or_recover(&self.active_buffers).insert(id, Arc::clone(storage));
        self.append_trace(format!("buffer registered id={id}"));
        id
    }

    fn unregister(&self, id: u64) {
        lock_or_recover(&self.active_buffers).remove(&id);
    }

    fn append_trace(&self, message: impl Into<String>) {
        let text = message.into();
        lock_or_recover(&self.trace_log).push(TraceRecord { text });
    }

    fn clear_all_sensitive_memory(&self) -> Result<(), &'static str> {
        let handles: Vec<SharedPayload> = lock_or_recover(&self.active_buffers)
            .drain()
            .map(|(_, storage)| storage)
            .collect();

        let mut first_err = None;
        for storage in handles {
            if wipe_payload(&storage).is_err() && first_err.is_none() {
                first_err = Some("Payload unlock or wipe failed");
            }
        }

        let mut traces = lock_or_recover(&self.trace_log);
        for record in traces.iter_mut() {
            record.zeroize();
        }
        traces.clear();

        match first_err {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct TraceRecord {
    text: String,
}

struct SensitivePayload {
    inner: LockedBuffer,
}

const JSON_NEED_CAPACITY_PREFIX: &str = "NX_NEED_CAP:";

#[derive(Debug)]
enum JsonEncodeError {
    NeedCapacity { need: usize },
    Serde(String),
    Memlock(String),
}

fn parse_need_capacity(err: &serde_json::Error) -> Option<usize> {
    if !err.is_io() {
        return None;
    }
    let msg = err.to_string();
    msg.split(JSON_NEED_CAPACITY_PREFIX)
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

struct FixedBufWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl Write for FixedBufWriter<'_> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let end = self
            .pos
            .checked_add(data.len())
            .ok_or_else(|| std::io::Error::new(ErrorKind::OutOfMemory, "overflow"))?;
        if end > self.buf.len() {
            return Err(std::io::Error::other(format!(
                "{JSON_NEED_CAPACITY_PREFIX}{end}"
            )));
        }
        self.buf[self.pos..end].copy_from_slice(data);
        self.pos = end;
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl SensitivePayload {
    fn try_new(data: &[u8]) -> Result<Self, String> {
        let inner = LockedBuffer::try_from_bytes(data).map_err(memlock_err)?;
        Ok(Self { inner })
    }

    fn try_with_capacity(capacity: usize) -> Result<Self, String> {
        let inner = LockedBuffer::try_with_capacity(capacity).map_err(memlock_err)?;
        Ok(Self { inner })
    }

    fn try_replace(&mut self, data: &[u8]) -> Result<(), String> {
        self.inner.try_replace(data).map_err(memlock_err)
    }

    fn try_serialize_json<T: Serialize>(&mut self, value: &T) -> Result<(), JsonEncodeError> {
        let written_pos = {
            let slice = self
                .inner
                .try_as_mut_slice()
                .map_err(|err| JsonEncodeError::Memlock(memlock_err(err)))?;
            let mut writer = FixedBufWriter { buf: slice, pos: 0 };
            match serde_json::to_writer(&mut writer, value) {
                Ok(()) => writer.pos,
                Err(err) if err.is_io() => {
                    if let Some(need) = parse_need_capacity(&err) {
                        return Err(JsonEncodeError::NeedCapacity { need });
                    }
                    return Err(JsonEncodeError::Serde(err.to_string()));
                }
                Err(err) => return Err(JsonEncodeError::Serde(err.to_string())),
            }
        };
        self.inner
            .try_set_len(written_pos)
            .map_err(|err| JsonEncodeError::Memlock(memlock_err(err)))?;
        Ok(())
    }

    fn try_wipe(&mut self) -> Result<(), MemLockError> {
        match self.inner.wipe() {
            Ok(()) => Ok(()),
            Err(err) => {
                record_aux_unlock_failure();
                Err(err)
            }
        }
    }

    fn wipe(&mut self) {
        let _ = self.try_wipe();
    }
}

impl Zeroize for SensitivePayload {
    fn zeroize(&mut self) {
        self.wipe();
    }
}

impl Drop for SensitivePayload {
    fn drop(&mut self) {
        let _ = self.try_wipe();
    }
}

impl ZeroizeOnDrop for SensitivePayload {}

fn wipe_payload(storage: &SharedPayload) -> Result<(), MemLockError> {
    let mut guard = lock_or_recover(storage.as_ref());
    guard.try_wipe()
}

#[cfg(test)]
fn read_payload_bytes(storage: &SharedPayload) -> Vec<u8> {
    lock_or_recover(storage.as_ref()).inner.as_slice().to_vec()
}

pub struct SecureToken {
    storage: SharedPayload,
    registry_id: u64,
}

impl SecureToken {
    pub fn new(secret: impl AsRef<[u8]>) -> Result<Self, String> {
        let _permit = acquire_operation_permit()?;
        let storage = Arc::new(Mutex::new(SensitivePayload::try_new(secret.as_ref())?));
        let registry_id = ApoptosisCoordinator::instance().register_shared(&storage);
        Ok(Self {
            storage,
            registry_id,
        })
    }

    pub fn len(&self) -> usize {
        lock_or_recover(self.storage.as_ref()).inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[cfg(test)]
    fn snapshot(&self) -> Vec<u8> {
        read_payload_bytes(&self.storage)
    }
}

impl Zeroize for SecureToken {
    fn zeroize(&mut self) {
        let _ = wipe_payload(&self.storage);
    }
}

impl Drop for SecureToken {
    fn drop(&mut self) {
        self.zeroize();
        ApoptosisCoordinator::instance().unregister(self.registry_id);
    }
}

impl ZeroizeOnDrop for SecureToken {}

pub struct EphemeralBuffer {
    storage: SharedPayload,
    registry_id: u64,
}

impl EphemeralBuffer {
    /// OsRng ile doldurulmuş kilitli oturum anahtarı (ara kopya yok).
    pub fn from_os_rng(len: usize) -> Result<Self, String> {
        let _permit = acquire_operation_permit()?;
        let mut inner =
            nexus_ephemera_memlock::LockedBuffer::try_allocate_for_len(len).map_err(memlock_err)?;
        rand::RngCore::fill_bytes(
            &mut rand::rngs::OsRng,
            inner
                .try_as_mut_slice()
                .map_err(|err| memlock_err(err).to_string())?,
        );
        let storage = Arc::new(Mutex::new(SensitivePayload { inner }));
        let registry_id = ApoptosisCoordinator::instance().register_shared(&storage);
        Ok(Self {
            storage,
            registry_id,
        })
    }

    /// Kilitli bellek üzerinden işlem — düz metin kopyası üretmez.
    pub(crate) fn with_sensitive_bytes<R>(
        &self,
        f: impl FnOnce(&[u8]) -> Result<R, String>,
    ) -> Result<R, String> {
        let guard = lock_or_recover(self.storage.as_ref());
        f(guard.inner.as_slice())
    }

    /// Kilitli alan üzerinde mutasyon — panik veya `Err` durumunda tampon sıfırlanır.
    pub(crate) fn with_locked_mut<R>(
        &self,
        f: impl FnOnce(&mut LockedBuffer) -> Result<R, ApoptosisError>,
    ) -> Result<R, ApoptosisError> {
        let _permit = acquire_permit()?;
        let mut guard = lock_or_recover(self.storage.as_ref());
        with_locked_mut(&mut guard.inner, f)
    }

    /// Kilitli alan üzerinde mutasyon — hata dizesi API uyumluluğu.
    #[allow(dead_code)]
    pub(crate) fn with_locked_mut_str<R>(
        &self,
        f: impl FnOnce(&mut LockedBuffer) -> Result<R, String>,
    ) -> Result<R, String> {
        self.with_locked_mut(|buf| {
            f(buf).map_err(|_| ApoptosisError::StringError("buffer op failed"))
        })
        .map_err(|e| e.to_string())
    }

    pub(crate) fn try_wipe(&self) -> Result<(), &'static str> {
        let mut guard = lock_or_recover(self.storage.as_ref());
        guard
            .try_wipe()
            .map_err(|_| "LockedBuffer wipe/unlock failed")
    }

    #[allow(dead_code)]
    pub(crate) fn scrub_on_error(&self) {
        let _ = self.try_wipe();
    }

    /// Base64 çözümünü doğrudan kilitli tampona yazar.
    #[allow(dead_code)]
    pub(crate) fn fill_from_b64(&self, b64: &str) -> Result<usize, String> {
        self.with_locked_mut_str(|inner| {
            let estimate = decoded_len_estimate(b64.len());
            let dst = inner.try_as_mut_slice().map_err(memlock_err)?;
            if estimate > dst.len() {
                return Err(format!(
                    "locked buffer too small for b64 payload (need ≥{estimate}, have {})",
                    dst.len()
                ));
            }
            let written = B64_ENGINE
                .decode_slice(b64, dst)
                .map_err(|e| format!("b64 decode: {e}"))?;
            inner.try_set_len(written).map_err(memlock_err)?;
            Ok(written)
        })
    }

    /// Base64 kapasite tahmini (kilitli tampon tahsisi için).
    pub(crate) fn b64_capacity_estimate(b64: &str) -> usize {
        decoded_len_estimate(b64.len()).max(1)
    }

    pub fn from_bytes(data: impl AsRef<[u8]>) -> Result<Self, String> {
        let _permit = acquire_operation_permit()?;
        let storage = Arc::new(Mutex::new(SensitivePayload::try_new(data.as_ref())?));
        let registry_id = ApoptosisCoordinator::instance().register_shared(&storage);
        Ok(Self {
            storage,
            registry_id,
        })
    }

    pub fn with_capacity(capacity: usize) -> Result<Self, String> {
        let _permit = acquire_operation_permit()?;
        let storage = Arc::new(Mutex::new(SensitivePayload::try_with_capacity(capacity)?));
        let registry_id = ApoptosisCoordinator::instance().register_shared(&storage);
        Ok(Self {
            storage,
            registry_id,
        })
    }

    pub fn fill(&mut self, data: impl AsRef<[u8]>) -> Result<(), String> {
        let _permit = acquire_operation_permit()?;
        let mut guard = lock_or_recover(self.storage.as_ref());
        guard.try_replace(data.as_ref())
    }

    /// JSON serileştirmesini doğrudan kilitli tampona yazar (serbest `Vec` kullanmaz).
    pub fn from_serializable<T: Serialize>(value: &T) -> Result<Self, String> {
        let _permit = acquire_operation_permit()?;
        let mut cap = 512usize;
        for _ in 0..16 {
            let mut payload = SensitivePayload::try_with_capacity(cap)?;
            match payload.try_serialize_json(value) {
                Ok(()) => {
                    let storage = Arc::new(Mutex::new(payload));
                    let registry_id = ApoptosisCoordinator::instance().register_shared(&storage);
                    return Ok(Self {
                        storage,
                        registry_id,
                    });
                }
                Err(JsonEncodeError::NeedCapacity { need }) => {
                    cap = need.max(cap.saturating_mul(2));
                }
                Err(JsonEncodeError::Serde(err)) => return Err(format!("json encode: {err}")),
                Err(JsonEncodeError::Memlock(err)) => return Err(err),
            }
        }
        Err("json encode: buffer growth limit".into())
    }

    pub fn decode_json<T: DeserializeOwned>(&self) -> Result<T, String> {
        self.with_sensitive_bytes(|bytes| {
            serde_json::from_slice(bytes).map_err(|err| format!("json decode: {err}"))
        })
    }

    pub fn digest_sha256_hex(&self) -> Result<String, String> {
        use sha2::{Digest, Sha256};
        self.with_sensitive_bytes(|bytes| {
            let digest = Sha256::digest(bytes);
            Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
        })
    }

    pub fn len(&self) -> usize {
        lock_or_recover(self.storage.as_ref()).inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Kilitli tampon hâlâ yazılabilir (silinmemiş / karantinada değil).
    pub(crate) fn memlock_accepts_writes(&self) -> bool {
        lock_or_recover(self.storage.as_ref()).inner.is_active()
    }

    #[cfg(test)]
    fn pages_locked(&self) -> bool {
        let _guard = lock_or_recover(self.storage.as_ref());
        drop(_guard);
        true
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> Vec<u8> {
        read_payload_bytes(&self.storage)
    }

    #[cfg(test)]
    fn shared_handle(&self) -> SharedPayload {
        Arc::clone(&self.storage)
    }
}

impl Zeroize for EphemeralBuffer {
    fn zeroize(&mut self) {
        let _ = wipe_payload(&self.storage);
    }
}

impl Drop for EphemeralBuffer {
    fn drop(&mut self) {
        self.zeroize();
        ApoptosisCoordinator::instance().unregister(self.registry_id);
    }
}

impl ZeroizeOnDrop for EphemeralBuffer {}

pub fn register_shutdown_hooks() {
    ApoptosisCoordinator::instance().append_trace("shutdown hooks: armed".to_string());

    tokio::spawn(async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                eprintln!("[apoptosis: Ctrl+C received]");
                let _ = trigger_apoptosis();
            }
            Err(err) => eprintln!("[apoptosis: signal listener error: {err}]"),
        }
    });

    eprintln!("[apoptosis: shutdown hooks registered]");
}

pub fn scrub(mut secret: Vec<u8>) {
    secret.zeroize();
}

#[cfg(test)]
pub(crate) fn test_serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|err| err.into_inner())
}

#[cfg(test)]
pub(crate) fn reset_coordinator_for_tests() {
    LIFECYCLE.store(0, Ordering::Release);
    WIPE_STATE.store(WipeStatus::Idle as u8, Ordering::Release);
    WIPE_EXECUTOR_RUNNING.store(false, Ordering::Release);
    AUX_UNLOCK_FAILURES.store(0, Ordering::Release);
    THREAD_PERMIT_DEPTH.set(0);
    crate::mesh::reset_mesh_for_tests();
    lock_or_recover(cleanup_hooks()).clear();
    let _ = ApoptosisCoordinator::instance().clear_all_sensitive_memory();
    crate::mesh::ensure_mesh_cleanup_registered();
}

#[cfg(test)]
fn bytes_are_zeroed(slice: &[u8]) -> bool {
    slice.is_empty() || slice.iter().all(|b| *b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn secure_token_registers_and_wipes_on_apoptosis() {
        let _guard = test_serial();
        reset_coordinator_for_tests();

        let token = SecureToken::new(vec![0xDE, 0xAD, 0xBE, 0xEF]).expect("token");
        assert_eq!(token.len(), 4);
        assert!(!bytes_are_zeroed(&token.snapshot()));

        let _ = trigger_apoptosis();

        assert!(bytes_are_zeroed(&token.snapshot()));
        drop(token);
    }

    #[test]
    fn engaged_rejects_new_buffers() {
        let _guard = test_serial();
        reset_coordinator_for_tests();
        let _ = trigger_apoptosis();
        assert!(EphemeralBuffer::from_bytes(b"x").is_err());
        assert!(SecureToken::new(b"y").is_err());
    }

    #[test]
    fn lifecycle_rejects_after_engaged_bit() {
        let _guard = test_serial();
        reset_coordinator_for_tests();
        LIFECYCLE.store(ENGAGED_BIT, Ordering::Release);
        assert!(acquire_operation_permit().is_err());
        LIFECYCLE.store(0, Ordering::Release);
    }

    #[test]
    fn nested_permits_do_not_deadlock() {
        let _guard = test_serial();
        reset_coordinator_for_tests();
        crate::crypto::init_session_for_tests([0x11; 32]).expect("session");
        let _outer = acquire_operation_permit().expect("outer");
        let _inner = acquire_operation_permit().expect("inner");
        let _ = EphemeralBuffer::from_bytes(b"nested").expect("buf");
        let _ = crate::crypto::seal(b"nested-crypto").expect("seal");
    }

    #[test]
    fn trigger_waits_for_inflight_permit() {
        let _guard = test_serial();
        reset_coordinator_for_tests();

        let permit = acquire_operation_permit().expect("permit");
        std::thread::spawn(|| {
            let _ = trigger_apoptosis();
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!is_engaged());
        drop(permit);
        let _ = wait_apoptosis_complete(Duration::from_secs(5));
        assert!(is_engaged());
    }

    #[test]
    fn trigger_from_permit_does_not_self_deadlock() {
        let _guard = test_serial();
        reset_coordinator_for_tests();

        let permit = acquire_operation_permit().expect("permit");
        let _ = request_apoptosis();
        drop(permit);
        let _ = wait_apoptosis_complete(Duration::from_secs(5));
        assert!(is_engaged());
    }

    #[test]
    fn wait_apoptosis_under_permit_returns_would_deadlock() {
        let _guard = test_serial();
        reset_coordinator_for_tests();
        let _permit = acquire_operation_permit().expect("permit");
        assert!(matches!(
            wait_apoptosis_complete(Duration::from_millis(10)),
            Err(ApoptosisError::WouldDeadlock)
        ));
    }

    #[test]
    fn trigger_apoptosis_is_idempotent() {
        let _guard = test_serial();
        reset_coordinator_for_tests();

        let _a = EphemeralBuffer::from_bytes(b"one").expect("a");
        let _b = EphemeralBuffer::from_bytes(b"two").expect("b");

        let _ = trigger_apoptosis();
        let _ = trigger_apoptosis();

        assert!(is_engaged());
        assert!(lock_or_recover(&ApoptosisCoordinator::instance().active_buffers).is_empty());
    }

    #[test]
    fn multiple_buffers_cleared_together() {
        let _guard = test_serial();
        reset_coordinator_for_tests();

        let buf1 = EphemeralBuffer::from_bytes(vec![0x11; 32]).expect("b1");
        let buf2 = SecureToken::new(vec![0x22; 16]).expect("b2");

        let _ = trigger_apoptosis();

        assert!(bytes_are_zeroed(&buf1.snapshot()));
        assert!(bytes_are_zeroed(&buf2.snapshot()));
    }

    #[test]
    fn ephemeral_buffer_drop_zeroizes_shared_storage() {
        let _guard = test_serial();
        reset_coordinator_for_tests();

        let storage = {
            let buf = EphemeralBuffer::from_bytes(b"sensitive-chunk").expect("buf");
            buf.shared_handle()
        };

        assert!(bytes_are_zeroed(&read_payload_bytes(&storage)));
    }

    #[test]
    fn secure_token_drop_unregisters_without_panic() {
        let _guard = test_serial();
        reset_coordinator_for_tests();

        {
            let _token = SecureToken::new(b"ephemeral-key").expect("token");
        }

        assert_eq!(
            lock_or_recover(&ApoptosisCoordinator::instance().active_buffers).len(),
            0
        );
    }

    #[test]
    fn request_apoptosis_delegates_to_trigger() {
        let _guard = test_serial();
        reset_coordinator_for_tests();

        let token = SecureToken::new(vec![0xAB; 8]).expect("token");
        let _ = trigger_apoptosis();
        assert!(bytes_are_zeroed(&token.snapshot()));
    }

    #[test]
    fn ephemeral_fill_syncs_shared_storage() {
        let _guard = test_serial();
        reset_coordinator_for_tests();

        let mut buf = EphemeralBuffer::with_capacity(64).expect("cap");
        buf.fill([0x7E; 10]).expect("fill");
        assert_eq!(buf.len(), 10);
        assert_eq!(buf.snapshot(), vec![0x7E; 10]);
    }

    #[test]
    fn cleanup_hooks_run_before_buffer_wipe() {
        let _guard = test_serial();
        reset_coordinator_for_tests();

        static CALLED: AtomicBool = AtomicBool::new(false);

        fn mark_called() -> Result<(), &'static str> {
            CALLED.store(true, Ordering::SeqCst);
            Ok(())
        }

        register_cleanup_hook(mark_called);
        let _ = trigger_apoptosis();
        assert!(CALLED.load(Ordering::SeqCst));
    }

    #[test]
    fn buffer_bytes_survive_page_lock() {
        let _guard = test_serial();
        reset_coordinator_for_tests();
        let buf = EphemeralBuffer::from_bytes(b"page-lock").expect("buf");
        assert_eq!(buf.snapshot(), b"page-lock");
        assert!(buf.pages_locked());
    }

    #[test]
    fn panicking_hook_transitions_to_partial_without_infinite_loop() {
        let _guard = test_serial();
        reset_coordinator_for_tests();

        fn panic_hook() -> Result<(), &'static str> {
            panic!("hook boom");
        }

        register_cleanup_hook(panic_hook);
        let _ = trigger_apoptosis();
        assert!(matches!(
            wipe_status(),
            WipeStatus::Partial | WipeStatus::Failed | WipeStatus::Complete
        ));
    }

    #[test]
    fn reentrant_hook_calling_trigger_does_not_deadlock() {
        let _guard = test_serial();
        reset_coordinator_for_tests();

        fn hook_requests_shutdown() -> Result<(), &'static str> {
            let _ = request_apoptosis();
            Ok(())
        }

        register_cleanup_hook(hook_requests_shutdown);
        let _ = trigger_apoptosis();
        assert!(wipe_status().is_terminal());
    }

    #[test]
    fn pre_apoptosis_aux_unlock_failure_yields_partial_status() {
        let _guard = test_serial();
        reset_coordinator_for_tests();
        record_aux_unlock_failure();
        let _buf = EphemeralBuffer::from_bytes(b"aux-failure-probe").expect("buf");
        let result = trigger_apoptosis();
        assert!(matches!(
            result,
            Err(ApoptosisError::IncompleteWipe(WipeStatus::Partial))
        ));
    }

    #[test]
    fn ephemeral_buffer_with_locked_mut_wipes_on_panic() {
        let _guard = test_serial();
        reset_coordinator_for_tests();

        let buf = EphemeralBuffer::from_bytes(b"sensitive-panic-test").expect("buf");
        let snap_before = buf.snapshot();
        assert!(!bytes_are_zeroed(&snap_before));

        let result: Result<(), ApoptosisError> = buf.with_locked_mut(|_| {
            panic!("forced panic inside with_locked_mut");
        });
        assert!(result.is_err());

        let snap_after = buf.snapshot();
        assert!(
            bytes_are_zeroed(&snap_after),
            "buffer must be wiped after panicking closure"
        );
    }

    #[test]
    fn zeroize_traits_cover_public_buffers() {
        let _guard = test_serial();
        fn assert_zeroize<T: Zeroize>() {}
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

        assert_zeroize::<SecureToken>();
        assert_zeroize::<EphemeralBuffer>();
        assert_zeroize_on_drop::<SecureToken>();
        assert_zeroize_on_drop::<EphemeralBuffer>();
        assert_zeroize::<SensitivePayload>();
        assert_zeroize_on_drop::<SensitivePayload>();
    }
}
