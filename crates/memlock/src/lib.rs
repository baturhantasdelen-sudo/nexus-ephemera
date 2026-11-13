//! Fail-closed bellek kilitleme: önce tahsis, sonra OS kilidi, sonra veri yazımı.
//!
//! # Tehdit sınırı (Sensitive-Memory Lifecycle Protection)
//! Kapsam içi: core dump, şifresiz swap/pagefile, `fork` sonrası adres alanı
//! ve kilit aralığında adli kalıntı.
//! Kapsam dışı: cold boot, DMA, fiziksel DRAM ve ayrıcalıklı `ptrace`.
//! `mlock` / `VirtualLock` ve Linux `MADV_DONTDUMP` + `MADV_DONTFORK` yalnızca
//! yönetilen aralığa uygulanır. Bu, `ptrace` veya donanım okumasını kapatmaz.
//! `MADV_DONTFORK` çocuğa sıfır sayfa kopyalamaz; aralığı çocuğun adres
//! uzayından çıkarır. Kısmi kilit açma karantinaya alır.

#![allow(unsafe_code)]

use std::sync::OnceLock;
use zeroize::Zeroize;

/// Bellek kilitleme hatası — işlem **başlatılmaz** (fail-closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemLockError {
    PrepareFailed,
    LockFailed,
    UnlockFailed,
    UnsupportedPlatform,
    InvalidLength,
    ArithmeticOverflow,
    Wiped,
    BufferWiped,
    NotWritable,
    ProcessHardeningFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SysLockError {
    Clean,
    /// Linux kirli rollback veya `#[cfg(test)]` simülasyonu.
    #[allow(dead_code)]
    DirtyRollback,
}

/// Süreç ve dump/fork sızıntılarına karşı OS düzeyi sertleştirme (idempotent).
pub fn harden_process_memory() -> Result<(), MemLockError> {
    static HARDEN_ONCE: OnceLock<Result<(), MemLockError>> = OnceLock::new();
    match HARDEN_ONCE.get_or_init(harden_process_memory_once) {
        Ok(()) => Ok(()),
        Err(err) => Err(*err),
    }
}

fn harden_process_memory_once() -> Result<(), MemLockError> {
    #[cfg(windows)]
    {
        harden_process_windows()
    }
    #[cfg(all(unix, not(windows)))]
    {
        harden_process_unix()
    }
    #[cfg(not(any(windows, unix)))]
    {
        Err(MemLockError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
fn harden_process_windows() -> Result<(), MemLockError> {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX, SetErrorMode,
    };
    let mode = SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX;
    // SAFETY: SetErrorMode yalnızca süreç geneli hata modunu ayarlar; geçerli bayrak birleşimi.
    unsafe {
        let _prev = SetErrorMode(mode);
    }
    Ok(())
}

#[cfg(unix)]
fn harden_process_unix() -> Result<(), MemLockError> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_SET_DUMPABLE=0 — çekirdek dump/ptrace yüzeyini kapatır (Linux).
        let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if rc != 0 {
            return Err(MemLockError::ProcessHardeningFailed);
        }
    }

    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: RLIMIT_CORE sıfırlama — core dump üretimini engeller.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return Err(MemLockError::ProcessHardeningFailed);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BufferState {
    Active,
    Wiped,
    Quarantined,
}

/// Sayfa hizalı, izole edilmiş kilitli tampon.
pub struct LockedBuffer {
    backing: Vec<u8>,
    data_offset: usize,
    data_len: usize,
    lock_span: usize,
    locked: bool,
    state: BufferState,
}

impl LockedBuffer {
    /// Önce tahsis + kilit, ardından veriyi kilitli alana yazar (ara `Vec` kopyası yok).
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, MemLockError> {
        let page = page_size()?;
        let data_len = data.len();
        let (backing, data_offset, lock_span) = allocate_layout(data_len.max(1), page)?;

        let mut buffer = Self {
            backing,
            data_offset,
            data_len,
            lock_span,
            locked: false,
            state: BufferState::Active,
        };
        buffer.lock_region()?;
        {
            let dst = buffer.try_as_mut_slice()?;
            if dst.len() != data.len() {
                return Err(MemLockError::InvalidLength);
            }
            dst.copy_from_slice(data);
        }
        Ok(buffer)
    }

    /// Kilitli, yazılabilir tampon (içerik henüz belirlenmemiş).
    pub fn try_allocate_for_len(len: usize) -> Result<Self, MemLockError> {
        if len == 0 {
            return Self::try_from_bytes(&[]);
        }
        let page = page_size()?;
        let (backing, data_offset, lock_span) = allocate_layout(len, page)?;

        let mut buffer = Self {
            backing,
            data_offset,
            data_len: len,
            lock_span,
            locked: false,
            state: BufferState::Active,
        };
        buffer.lock_region()?;
        Ok(buffer)
    }

    pub fn try_with_capacity(capacity: usize) -> Result<Self, MemLockError> {
        Self::try_allocate_for_len(capacity.max(1))
    }

    /// Sıfırdan doldurulmuş, kilitli yazılabilir tampon (kapasite = `len`).
    pub fn try_new_zeroed(len: usize) -> Result<Self, MemLockError> {
        Self::try_allocate_for_len(len.max(1))
    }

    /// Aktif yazılabilir kapasite (`data_len`).
    pub fn capacity(&self) -> usize {
        if self.state != BufferState::Active {
            0
        } else {
            self.data_len
        }
    }

    pub fn try_replace(&mut self, data: &[u8]) -> Result<(), MemLockError> {
        if self.state != BufferState::Active || !self.locked {
            return Err(MemLockError::BufferWiped);
        }
        let mut replacement = Self::try_from_bytes(data)?;
        if let Err(e) = self.wipe() {
            let _ = replacement.wipe();
            return Err(e);
        }
        *self = replacement;
        Ok(())
    }

    pub fn len(&self) -> usize {
        if self.state != BufferState::Active {
            0
        } else {
            self.data_len
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_active(&self) -> bool {
        self.state == BufferState::Active
    }

    pub fn is_wiped(&self) -> bool {
        self.state == BufferState::Wiped
    }

    #[cfg(test)]
    fn is_quarantined(&self) -> bool {
        self.state == BufferState::Quarantined
    }

    pub fn as_slice(&self) -> &[u8] {
        if self.state != BufferState::Active || !self.locked || self.data_len == 0 {
            return &[];
        }
        &self.backing[self.data_offset..self.data_offset + self.data_len]
    }

    /// Yazılabilir görünüm — yalnızca aktif ve kilitli tamponlarda.
    pub fn try_as_mut_slice(&mut self) -> Result<&mut [u8], MemLockError> {
        if self.state == BufferState::Wiped || self.state == BufferState::Quarantined {
            return Err(MemLockError::BufferWiped);
        }
        if self.state != BufferState::Active || !self.locked {
            return Err(MemLockError::BufferWiped);
        }
        let end = self.data_offset + self.data_len;
        Ok(&mut self.backing[self.data_offset..end])
    }

    /// Aktif yazılabilir uzunluğu günceller (kapasiteyi aşamaz).
    pub fn try_set_len(&mut self, new_len: usize) -> Result<(), MemLockError> {
        if self.state == BufferState::Wiped || self.state == BufferState::Quarantined {
            return Err(MemLockError::BufferWiped);
        }
        if self.state != BufferState::Active || !self.locked {
            return Err(MemLockError::BufferWiped);
        }
        let end = self
            .data_offset
            .checked_add(new_len)
            .ok_or(MemLockError::InvalidLength)?;
        let lock_end = self
            .data_offset
            .checked_add(self.lock_span)
            .ok_or(MemLockError::InvalidLength)?;
        if end > lock_end {
            return Err(MemLockError::InvalidLength);
        }
        self.data_len = new_len;
        self.zeroize_lock_span_slack(new_len);
        Ok(())
    }

    pub fn wipe(&mut self) -> Result<(), MemLockError> {
        if self.state == BufferState::Wiped {
            return Ok(());
        }
        if self.state == BufferState::Quarantined {
            return Err(MemLockError::UnlockFailed);
        }

        self.zeroize_locked_capacity();
        self.data_len = 0;

        if !self.locked {
            self.state = BufferState::Wiped;
            return Ok(());
        }

        match self.unlock_region() {
            Ok(()) => {
                self.state = BufferState::Wiped;
                Ok(())
            }
            Err(err) => {
                self.locked = false;
                self.state = BufferState::Quarantined;
                Err(err)
            }
        }
    }

    /// Kilitli aralığın tamamını (sayfa hizalı kapasite) sıfırlar.
    fn zeroize_locked_capacity(&mut self) {
        if self.lock_span == 0 {
            return;
        }
        let start = self.data_offset;
        let end = start
            .checked_add(self.lock_span)
            .unwrap_or(start)
            .min(self.backing.len());
        if start < end {
            self.backing[start..end].zeroize();
        }
    }

    /// Aktif veriden sonraki slack alanı sıfırlar.
    fn zeroize_lock_span_slack(&mut self, active_len: usize) {
        let slack_start = self.data_offset.saturating_add(active_len);
        let lock_end = self
            .data_offset
            .saturating_add(self.lock_span)
            .min(self.backing.len());
        if slack_start < lock_end {
            self.backing[slack_start..lock_end].zeroize();
        }
    }

    fn quarantine_backing(&mut self) {
        std::mem::forget(std::mem::take(&mut self.backing));
        self.locked = false;
        self.data_len = 0;
        self.lock_span = 0;
        self.state = BufferState::Quarantined;
    }

    fn lock_region(&mut self) -> Result<(), MemLockError> {
        if self.state == BufferState::Wiped || self.state == BufferState::Quarantined {
            return Err(MemLockError::BufferWiped);
        }
        if self.locked {
            return Ok(());
        }
        prepare_process()?;
        // SAFETY: `data_offset`/`lock_span` `allocate_layout` tarafından tam sayfa ve
        // bu `Vec`'in içine izole edilmiş; komşu heap nesnesiyle sayfa paylaşmaz.
        let ptr = unsafe { self.backing.as_mut_ptr().add(self.data_offset) };
        match sys::lock(ptr, self.lock_span) {
            Ok(()) => {
                self.locked = true;
                Ok(())
            }
            Err(SysLockError::Clean) => Err(MemLockError::LockFailed),
            Err(SysLockError::DirtyRollback) => {
                self.quarantine_backing();
                Err(MemLockError::LockFailed)
            }
        }
    }

    fn unlock_region(&mut self) -> Result<(), MemLockError> {
        if !self.locked {
            return Ok(());
        }
        // SAFETY: kilit aralığı hâlâ bu tampona ait; wipe önceden baytları sıfırlamış olur.
        let ptr = unsafe { self.backing.as_mut_ptr().add(self.data_offset) };
        sys::unlock(ptr, self.lock_span)?;
        self.locked = false;
        Ok(())
    }
}

impl Drop for LockedBuffer {
    fn drop(&mut self) {
        if self.wipe().is_err() || self.state == BufferState::Quarantined {
            let leaked = std::mem::take(&mut self.backing);
            std::mem::forget(leaked);
        }
    }
}

fn allocate_layout(data_len: usize, page: usize) -> Result<(Vec<u8>, usize, usize), MemLockError> {
    let lock_span = round_up_to_pages(data_len, page)?;
    let guard = page
        .checked_mul(2)
        .ok_or(MemLockError::ArithmeticOverflow)?;
    let backing_len = lock_span
        .checked_add(guard)
        .ok_or(MemLockError::ArithmeticOverflow)?;
    let backing = vec![0_u8; backing_len];
    let data_offset = align_offset(backing.as_ptr(), page)?;
    let lock_end = data_offset
        .checked_add(lock_span)
        .ok_or(MemLockError::ArithmeticOverflow)?;
    let exclusive_limit = backing.len() & !(page - 1);
    let lock_addr = (backing.as_ptr() as usize)
        .checked_add(data_offset)
        .ok_or(MemLockError::ArithmeticOverflow)?;
    if lock_span % page != 0
        || lock_addr % page != 0
        || lock_end > exclusive_limit
        || data_offset
            .checked_add(data_len)
            .ok_or(MemLockError::InvalidLength)?
            > backing.len()
    {
        return Err(MemLockError::InvalidLength);
    }
    Ok((backing, data_offset, lock_span))
}

fn round_up_to_pages(len: usize, page: usize) -> Result<usize, MemLockError> {
    if page == 0 {
        return Err(MemLockError::InvalidLength);
    }
    let rem = len % page;
    let rounded = if rem == 0 {
        len
    } else {
        len.checked_add(page - rem)
            .ok_or(MemLockError::ArithmeticOverflow)?
    };
    Ok(rounded)
}

fn align_offset(ptr: *const u8, page: usize) -> Result<usize, MemLockError> {
    if page == 0 || !page.is_power_of_two() {
        return Err(MemLockError::InvalidLength);
    }
    let addr = ptr as usize;
    let mask = page - 1;
    let aligned = (addr
        .checked_add(mask)
        .ok_or(MemLockError::ArithmeticOverflow)?)
        & !mask;
    let offset = aligned
        .checked_sub(addr)
        .ok_or(MemLockError::ArithmeticOverflow)?;
    Ok(offset)
}

/// Yükün kilitleneceği sayfa yuvarlanmış uzunluk. Boş yük bir sayfaya yuvarlanır.
pub fn locked_span_for(len: usize) -> Result<usize, MemLockError> {
    let page = page_size()?;
    round_up_to_pages(len.max(1), page)
}

fn page_size() -> Result<usize, MemLockError> {
    static PAGE: OnceLock<Result<usize, MemLockError>> = OnceLock::new();
    match PAGE.get_or_init(sys::query_page_size) {
        Ok(value) => Ok(*value),
        Err(err) => Err(*err),
    }
}

fn prepare_process() -> Result<(), MemLockError> {
    static ONCE: OnceLock<Result<(), MemLockError>> = OnceLock::new();
    match ONCE.get_or_init(|| {
        if sys::prepare() {
            Ok(())
        } else {
            Err(MemLockError::PrepareFailed)
        }
    }) {
        Ok(()) => Ok(()),
        Err(err) => Err(*err),
    }
}

#[cfg(test)]
mod test_hooks {
    use std::cell::Cell;

    pub(super) const SIM_NONE: u8 = 0;
    pub(super) const SIM_UNLOCK_PARTIAL: u8 = 1;
    pub(super) const SIM_LOCK_DIRTY_ROLLBACK: u8 = 2;

    thread_local! {
        static SIM: Cell<u8> = const { Cell::new(SIM_NONE) };
    }

    pub(super) fn set_sim(mode: u8) {
        SIM.with(|s| s.set(mode));
    }

    pub(super) fn clear_sim() {
        SIM.with(|s| s.set(SIM_NONE));
    }

    pub(super) fn sim() -> u8 {
        SIM.with(|s| s.get())
    }
}

#[cfg(windows)]
mod sys {
    use super::*;

    use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};
    use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, SetProcessWorkingSetSize};

    pub fn query_page_size() -> Result<usize, MemLockError> {
        let mut info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
        unsafe { GetSystemInfo(&mut info) };
        let page = info.dwPageSize as usize;
        if page == 0 {
            return Err(MemLockError::UnsupportedPlatform);
        }
        Ok(page)
    }

    pub fn prepare() -> bool {
        let min = 8 * 1024 * 1024;
        let max = 64 * 1024 * 1024;
        unsafe {
            let process = GetCurrentProcess();
            SetProcessWorkingSetSize(process, min, max) != 0
        }
    }

    pub fn lock(ptr: *mut u8, len: usize) -> Result<(), SysLockError> {
        #[cfg(test)]
        if test_hooks::sim() == test_hooks::SIM_LOCK_DIRTY_ROLLBACK {
            // SAFETY: test yolu — OS kilidi alındıktan sonra kirli rollback simülasyonu.
            if unsafe { VirtualLock(ptr.cast::<std::ffi::c_void>(), len) } != 0 {
                let _ = unsafe { VirtualUnlock(ptr.cast::<std::ffi::c_void>(), len) };
            }
            return Err(SysLockError::DirtyRollback);
        }

        // SAFETY: `ptr`/`len` bu tamponun sayfa hizalı, izole kilit aralığıdır.
        if unsafe { VirtualLock(ptr.cast::<std::ffi::c_void>(), len) } != 0 {
            Ok(())
        } else {
            Err(SysLockError::Clean)
        }
    }

    pub fn unlock(ptr: *mut u8, len: usize) -> Result<(), MemLockError> {
        #[cfg(test)]
        if test_hooks::sim() == test_hooks::SIM_UNLOCK_PARTIAL {
            // SAFETY: kısmi unlock hatası (advice yok); munlock/VirtualUnlock başarılı sayılır.
            if unsafe { VirtualUnlock(ptr.cast::<std::ffi::c_void>(), len) } != 0 {
                return Err(MemLockError::UnlockFailed);
            }
            return Err(MemLockError::UnlockFailed);
        }

        // SAFETY: aynı aralık daha önce `VirtualLock` ile kilitlendi.
        if unsafe { VirtualUnlock(ptr.cast::<std::ffi::c_void>(), len) } != 0 {
            Ok(())
        } else {
            Err(MemLockError::UnlockFailed)
        }
    }
}

#[cfg(unix)]
mod sys {
    use super::*;

    pub fn query_page_size() -> Result<usize, MemLockError> {
        let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if size <= 0 {
            return Err(MemLockError::UnsupportedPlatform);
        }
        Ok(size as usize)
    }

    /// Ayrıcalıksız `RLIMIT_MEMLOCK` tavanı `EPERM` döndürür.
    /// Test derlemesinde bu, fail-closed panik yerine simülasyon kilidine düşer.
    /// Üretim ikilisinde (`cfg(not(test))`) graceful fallback derlenmez.
    #[cfg(test)]
    fn eperm_graceful_fallback() -> bool {
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }

    pub fn prepare() -> bool {
        let limit = libc::rlimit {
            rlim_cur: 64 * 1024 * 1024,
            rlim_max: 64 * 1024 * 1024,
        };
        // SAFETY: yalnızca bu sürecin memlock tavanını yükseltmeyi dener.
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) };
        #[cfg(test)]
        return rc == 0 || eperm_graceful_fallback();
        rc == 0
    }

    pub fn lock(ptr: *mut u8, len: usize) -> Result<(), SysLockError> {
        #[cfg(test)]
        if test_hooks::sim() == test_hooks::SIM_LOCK_DIRTY_ROLLBACK {
            if unsafe { libc::mlock(ptr.cast::<libc::c_void>(), len) } == 0 {
                let _ = unsafe { libc::munlock(ptr.cast::<libc::c_void>(), len) };
            }
            return Err(SysLockError::DirtyRollback);
        }

        // SAFETY: `ptr`/`len` sayfa hizalı ve yalnızca bu tamponun tahsisindedir.
        if unsafe { libc::mlock(ptr.cast::<libc::c_void>(), len) } != 0 {
            #[cfg(test)]
            if eperm_graceful_fallback() {
                return Ok(());
            }
            return Err(SysLockError::Clean);
        }
        #[cfg(target_os = "linux")]
        {
            // SAFETY: aralık az önce mlock ile kilitlendi; madvise dönüşü yok sayılmaz.
            let r_dump =
                unsafe { libc::madvise(ptr.cast::<libc::c_void>(), len, libc::MADV_DONTDUMP) };
            if r_dump != 0 {
                let rolled_back = unsafe { libc::munlock(ptr.cast::<libc::c_void>(), len) };
                if rolled_back != 0 {
                    return Err(SysLockError::DirtyRollback);
                }
                return Err(SysLockError::Clean);
            }
            let r_fork =
                unsafe { libc::madvise(ptr.cast::<libc::c_void>(), len, libc::MADV_DONTFORK) };
            if r_fork != 0 {
                let undo_dump =
                    unsafe { libc::madvise(ptr.cast::<libc::c_void>(), len, libc::MADV_DODUMP) };
                let rolled_back = unsafe { libc::munlock(ptr.cast::<libc::c_void>(), len) };
                if undo_dump != 0 || rolled_back != 0 {
                    return Err(SysLockError::DirtyRollback);
                }
                return Err(SysLockError::Clean);
            }
        }
        Ok(())
    }

    pub fn unlock(ptr: *mut u8, len: usize) -> Result<(), MemLockError> {
        #[cfg(test)]
        if test_hooks::sim() == test_hooks::SIM_UNLOCK_PARTIAL {
            let r_unlock = unsafe { libc::munlock(ptr.cast::<libc::c_void>(), len) };
            if r_unlock != 0 {
                return Err(MemLockError::UnlockFailed);
            }
            return Err(MemLockError::UnlockFailed);
        }

        #[cfg(target_os = "linux")]
        {
            // SAFETY: wipe bu aralığı sıfırladı; advice geri alınmadan sayfa serbest bırakılmaz.
            let r_fork =
                unsafe { libc::madvise(ptr.cast::<libc::c_void>(), len, libc::MADV_DOFORK) };
            let r_dump =
                unsafe { libc::madvise(ptr.cast::<libc::c_void>(), len, libc::MADV_DODUMP) };
            let r_unlock = unsafe { libc::munlock(ptr.cast::<libc::c_void>(), len) };
            if r_fork != 0 || r_dump != 0 || r_unlock != 0 {
                Err(MemLockError::UnlockFailed)
            } else {
                Ok(())
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            // SAFETY: aynı aralık daha önce `mlock` ile kilitlendi.
            if unsafe { libc::munlock(ptr.cast::<libc::c_void>(), len) } != 0 {
                Err(MemLockError::UnlockFailed)
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(not(any(windows, unix)))]
mod sys {
    use super::*;

    pub fn query_page_size() -> Result<usize, MemLockError> {
        Err(MemLockError::UnsupportedPlatform)
    }

    pub fn prepare() -> bool {
        false
    }

    pub fn lock(_ptr: *mut u8, _len: usize) -> Result<(), SysLockError> {
        Err(SysLockError::Clean)
    }

    pub fn unlock(_ptr: *mut u8, _len: usize) -> Result<(), MemLockError> {
        Err(MemLockError::UnlockFailed)
    }
}

#[doc(hidden)]
/// Linux'ta `MADV_DONTFORK` aralığının çocukta eşlenmemiş olduğunu ve
/// `RLIMIT_MEMLOCK` tükenmesinin kontrollü hata verdiğini denetler.
/// Çocuk baytları okumaz. Diğer platformlarda yoklama çalışmaz ve başarı döner.
/// Cold boot, DMA ve ayrıcalıklı `ptrace` kapsam dışıdır. Kanarya yazdırılmaz.
pub fn run_fork_assurance_probe() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        linux_fork_assurance()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn linux_fork_assurance() -> Result<(), String> {
    dontfork_child_range_is_unmapped()?;
    rlimit_exhaustion_is_controlled()
}

#[cfg(target_os = "linux")]
fn dontfork_child_range_is_unmapped() -> Result<(), String> {
    const CANARY: &[u8] = b"NEXUS_FORK_CANARY_998877!!";
    let buf = LockedBuffer::try_from_bytes(CANARY).map_err(|err| format!("lock: {err:?}"))?;
    let page = page_size().map_err(|err| format!("page: {err:?}"))?;
    // Kilit aralığının kendisi. Çocukta bu sayfalar VM_DONTCOPY ile devralınmaz.
    let addr = unsafe { buf.backing.as_ptr().add(buf.data_offset) } as usize;
    let len = buf.lock_span;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err("fork failed".into());
    }
    if pid == 0 {
        // `mincore` eşlenmemiş aralıkta okumadan ENOMEM/EFAULT döner.
        // `read_volatile` bu adreste SIGSEGV üretir; çocuk baytlara dokunmaz.
        let pages = len.div_ceil(page).max(1);
        let mut resident = vec![0u8; pages];
        let rc = unsafe { libc::mincore(addr as *mut libc::c_void, len, resident.as_mut_ptr()) };
        let err = std::io::Error::last_os_error().raw_os_error();
        let code = if rc == 0 {
            1
        } else if matches!(err, Some(libc::ENOMEM) | Some(libc::EFAULT)) {
            0
        } else {
            2
        };
        unsafe { libc::_exit(code) };
    }
    let code = wait_child(pid)?;
    drop(buf);
    match code {
        0 => Ok(()),
        1 => Err("MADV_DONTFORK range is still mapped in the child".into()),
        _ => Err("child could not probe the locked range safely".into()),
    }
}

#[cfg(target_os = "linux")]
fn rlimit_exhaustion_is_controlled() -> Result<(), String> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err("fork for rlimit probe failed".into());
    }
    if pid == 0 {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) } != 0 {
            unsafe { libc::_exit(3) };
        }
        let code = match std::panic::catch_unwind(|| LockedBuffer::try_from_bytes(b"rl")) {
            Ok(Ok(_)) | Ok(Err(MemLockError::LockFailed | MemLockError::PrepareFailed)) => 0,
            Ok(Err(_)) => 4,
            Err(_) => 5,
        };
        unsafe { libc::_exit(code) };
    }
    match wait_child(pid)? {
        0 => Ok(()),
        3 => Err("could not lower RLIMIT_MEMLOCK".into()),
        4 => Err("mlock under a zero limit returned an unexpected error".into()),
        5 => Err("mlock under a zero limit panicked".into()),
        other => Err(format!("rlimit child status {other}")),
    }
}

#[cfg(target_os = "linux")]
fn wait_child(pid: libc::pid_t) -> Result<i32, String> {
    let mut status = 0;
    let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
    if rc < 0 {
        return Err("waitpid failed".into());
    }
    if libc::WIFEXITED(status) {
        Ok(libc::WEXITSTATUS(status))
    } else {
        Err(format!("child did not exit normally: {status}"))
    }
}

#[cfg(test)]
impl LockedBuffer {
    /// Forensic doğrulama: kilitli bölgenin başlangıç adresi.
    fn as_ptr(&self) -> *const u8 {
        unsafe { self.backing.as_ptr().add(self.data_offset) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SimGuard;
    impl SimGuard {
        fn set(mode: u8) -> Self {
            test_hooks::set_sim(mode);
            Self
        }
    }
    impl Drop for SimGuard {
        fn drop(&mut self) {
            test_hooks::clear_sim();
        }
    }

    #[test]
    fn locked_buffer_roundtrip() {
        let buf = LockedBuffer::try_from_bytes(b"secret").expect("lock");
        assert_eq!(buf.as_slice(), b"secret");
    }

    #[test]
    fn locked_buffer_replace() {
        let mut buf = LockedBuffer::try_from_bytes(b"one").expect("lock");
        buf.try_replace(b"two").expect("replace");
        assert_eq!(buf.as_slice(), b"two");
    }

    #[test]
    fn allocate_then_write() {
        let mut buf = LockedBuffer::try_allocate_for_len(4).expect("alloc");
        buf.try_as_mut_slice()
            .expect("mut")
            .copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(buf.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn dynamic_page_size_nonzero() {
        assert!(page_size().expect("page") > 0);
    }

    #[test]
    fn try_set_len_clears_lock_span_slack() {
        let mut buf = LockedBuffer::try_allocate_for_len(8).expect("alloc");
        {
            let slot = buf.try_as_mut_slice().expect("mut");
            assert_eq!(slot.len(), 8, "capacity/data_len must match for this test");
            slot.copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44]);
        }
        buf.try_set_len(2).expect("shrink");
        assert_eq!(buf.as_slice(), &[0xAA, 0xBB]);
        buf.try_set_len(8).expect("expand to full capacity");
        let view = buf.try_as_mut_slice().expect("mut");
        assert_eq!(view.len(), 8);
        assert_eq!(&view[..2], &[0xAA, 0xBB]);
        assert!(
            view[2..].iter().all(|&b| b == 0),
            "slack between active len and capacity was not zeroized"
        );
    }

    #[test]
    fn process_memory_hardening_succeeds() {
        harden_process_memory().expect("harden_process_memory");
        assert!(harden_process_memory().is_ok(), "idempotent second call");
    }

    #[test]
    fn wipe_prevents_further_writes() {
        let mut buf = LockedBuffer::try_allocate_for_len(8).expect("alloc");
        assert!(buf.try_as_mut_slice().is_ok());
        buf.wipe().expect("wipe");
        assert!(buf.is_wiped());
        assert_eq!(buf.len(), 0);
        assert!(matches!(
            buf.try_as_mut_slice(),
            Err(MemLockError::BufferWiped)
        ));
        assert!(matches!(
            buf.try_replace(b"x"),
            Err(MemLockError::BufferWiped)
        ));
    }

    #[test]
    fn partial_unlock_failure_quarantines_buffer_and_blocks_writes() {
        let _sim = SimGuard::set(test_hooks::SIM_UNLOCK_PARTIAL);
        let mut buf = LockedBuffer::try_allocate_for_len(16).expect("alloc");
        buf.try_as_mut_slice().expect("mut").fill(0x5A);

        assert!(matches!(buf.wipe(), Err(MemLockError::UnlockFailed)));
        assert!(buf.is_quarantined());
        assert_eq!(buf.len(), 0);
        assert!(matches!(
            buf.try_as_mut_slice(),
            Err(MemLockError::BufferWiped)
        ));
        assert!(matches!(buf.try_set_len(1), Err(MemLockError::BufferWiped)));
        assert!(matches!(buf.wipe(), Err(MemLockError::UnlockFailed)));
    }

    #[test]
    fn dirty_lock_rollback_quarantines_allocation() {
        let _sim = SimGuard::set(test_hooks::SIM_LOCK_DIRTY_ROLLBACK);
        let result = LockedBuffer::try_allocate_for_len(16);
        assert!(matches!(result, Err(MemLockError::LockFailed)));
    }

    #[test]
    fn try_replace_partial_unlock_failure_quarantines_old_buffer() {
        let mut buf = LockedBuffer::try_from_bytes(b"initial-secret").expect("alloc");
        let _sim = SimGuard::set(test_hooks::SIM_UNLOCK_PARTIAL);

        let err = buf
            .try_replace(b"new-secret")
            .expect_err("must fail on partial unlock");
        assert_eq!(err, MemLockError::UnlockFailed);
        assert!(buf.as_slice().is_empty());
        assert!(buf.is_quarantined());
        assert_eq!(buf.try_as_mut_slice(), Err(MemLockError::BufferWiped));
        assert_eq!(buf.try_set_len(4), Err(MemLockError::BufferWiped));
        assert_eq!(buf.try_replace(b"retry"), Err(MemLockError::BufferWiped));
        assert_eq!(buf.wipe(), Err(MemLockError::UnlockFailed));
    }

    #[test]
    fn physical_canary_scrub_leaves_zero_residue_across_lock_span() {
        const CANARY: &[u8] = b"NEXUS_FORENSIC_CANARY_99887766!!";
        assert_eq!(CANARY.len(), 32);

        let mut buf = LockedBuffer::try_from_bytes(CANARY).expect("lock");
        let _base_addr = buf.as_ptr();
        let capacity = buf.capacity();
        let lock_span = buf.lock_span;
        assert_eq!(buf.as_slice(), CANARY);
        assert!(capacity >= CANARY.len());
        assert!(lock_span >= capacity);

        let base = buf.as_ptr();
        buf.try_set_len(8).expect("shrink active len");
        buf.wipe().expect("wipe");

        for offset in 0..capacity {
            let byte = unsafe { std::ptr::read_volatile(base.add(offset)) };
            assert_eq!(
                byte, 0,
                "non-zero residue at offset {offset} within capacity {capacity}"
            );
            assert!(
                !CANARY.contains(&byte) || byte == 0,
                "canary residue at offset {offset}"
            );
        }
        for offset in capacity..lock_span {
            let byte = unsafe { std::ptr::read_volatile(base.add(offset)) };
            assert_eq!(
                byte, 0,
                "non-zero slack residue at offset {offset} within lock_span {lock_span}"
            );
        }
    }
}
